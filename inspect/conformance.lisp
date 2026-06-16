;;;; shared/bitcoind/inspect/conformance.lisp
;;;;
;;;; Run Bitcoin Core's script_tests.json against our interpreter to quantify
;;;; consensus divergence.  Each case is reconstructed exactly as Core's
;;;; script_tests.cpp does — a synthetic "credit" tx funding the scriptPubKey
;;;; and a "spend" tx carrying the scriptSig/witness — then run through our
;;;; VERIFY-INPUT.  We bucket results:
;;;;
;;;;   agree-ok / agree-fail  — we match Core
;;;;   FALSE-POSITIVE         — we ACCEPT what Core REJECTS (unenforced rule: gap)
;;;;   FALSE-NEGATIVE         — we REJECT what Core ACCEPTS (interpreter bug)
;;;;
;;;; Compile the vectors first:  python3 /tmp/parse_scripts.py  ->  script_tests_hex.json
;;;;
;;;;   sbcl --load shared/bitcoind/inspect/conformance.lisp \
;;;;        --eval '(btc-conf:run "/tmp/script_tests_hex.json")'

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (pushnew (uiop:pathname-parent-directory-pathname (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
           asdf:*central-registry* :test #'equal)
  (ql:quickload '(:com.inuoe.jzon) :silent t)
  (asdf:load-system "cl-consensus"))

(defpackage #:btc-conf
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script) (#:jzon #:com.inuoe.jzon))
  (:export #:run #:ci))

(in-package #:btc-conf)

(defparameter *show-fp* nil "When T, RUN prints example false-positive cases per category.")

(defun flag-set (flags name) (search name flags))

(defparameter *flag-map*
  '(("P2SH" . :p2sh) ("WITNESS" . :witness) ("STRICTENC" . :strictenc)
    ("DERSIG" . :dersig) ("LOW_S" . :low-s) ("NULLDUMMY" . :nulldummy)
    ("SIGPUSHONLY" . :sigpushonly) ("MINIMALDATA" . :minimaldata)
    ("CLEANSTACK" . :cleanstack) ("MINIMALIF" . :minimalif) ("NULLFAIL" . :nullfail)
    ("WITNESS_PUBKEYTYPE" . :witness-pubkeytype) ("TAPROOT" . :taproot)
    ("DISCOURAGE_UPGRADABLE_NOPS" . :discourage-nops)
    ("CHECKLOCKTIMEVERIFY" . :cltv) ("CHECKSEQUENCEVERIFY" . :csv)))

(defun parse-flags (flags)
  "Comma-separated Core flag string -> list of our keywords.  Order matters:
   match longer names first so WITNESS_PUBKEYTYPE isn't read as WITNESS."
  (let ((toks (remove "" (loop with start = 0 for i = (position #\, flags :start start)
                               collect (subseq flags start (or i (length flags)))
                               while i do (setf start (1+ i)))
                      :test #'string=))
        (out '()))
    (dolist (tok toks (nreverse out))
      (let ((kw (cdr (assoc (string-trim " " tok) *flag-map* :test #'string=))))
        (when kw (push kw out))))))

(defun build-credit (pk amount)
  "Core's BuildCreditingTransaction: null prevout, scriptSig OP_0 OP_0."
  (let ((txn (tx:make-tx :version 1 :locktime 0 :segwit-p nil
               :inputs (list (tx:make-txin
                              :prev-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                              :prev-index #xffffffff
                              :script (coerce #(0 0) '(simple-array (unsigned-byte 8) (*)))
                              :sequence #xffffffff))
               :outputs (list (tx:make-txout :value amount :script pk)))))
    (tx:finalize-tx txn)))

(defun build-spend (credit sig witness amount)
  "Core's BuildSpendingTransaction."
  (let ((txn (tx:make-tx :version 1 :locktime 0 :segwit-p (not (null witness))
               :inputs (list (tx:make-txin :prev-hash (tx:tx-txid credit) :prev-index 0
                              :script sig :sequence #xffffffff))
               :outputs (list (tx:make-txout :value amount
                               :script (make-array 0 :element-type '(unsigned-byte 8)))))))
    (when witness (setf (tx:tx-witnesses txn) (list witness)))
    (tx:finalize-tx txn)))

(defun ci (&optional (path "/tmp/script_tests_hex.json") (min-agree 0.99) (max-fn 1))
  "Run conformance and exit nonzero if agreement < MIN-AGREE or false-negatives
   exceed MAX-FN (a regression).  For scripting."
  (multiple-value-bind (agree fn) (run path)
    (let ((ok (and (>= agree min-agree) (<= fn max-fn))))
      (format t "~&CONFORMANCE: ~a (agree ~,1f%, fn ~d; need >=~,1f%, fn<=~d)~%"
              (if ok "PASS" "FAIL") (* 100 agree) fn (* 100 min-agree) max-fn)
      (sb-ext:exit :code (if ok 0 1)))))

(defun run (&optional (path "/tmp/script_tests_hex.json"))
  (let ((cases (with-open-file (f path) (jzon:parse f)))
        (agree-ok 0) (agree-fail 0) (fp 0) (fn 0)
        (fp-flags (make-hash-table :test 'equal))
        (fp-ex (make-hash-table :test 'equal))
        (fn-examples '()))
    (loop for c across cases do
      (let* ((sig (w:hex->bytes (aref c 0)))
             (pk (w:hex->bytes (aref c 1)))
             (flags (aref c 2))
             (expected (aref c 3))
             (wit (map 'list #'w:hex->bytes (aref c 4)))
             (amount (truncate (aref c 5)))
             (core-ok (string= expected "OK"))
             (credit (build-credit pk amount))
             (spend (build-spend credit sig wit amount))
             (prevouts (vector (cons amount pk)))
             (ours (handler-case
                       (and (s:verify-input spend 0 pk amount
                                            :flags (parse-flags flags)
                                            :prevouts prevouts)
                            t)
                     (error () nil))))
        (cond
          ((and core-ok ours) (incf agree-ok))
          ((and (not core-ok) (not ours)) (incf agree-fail))
          ((and (not core-ok) ours)         ; we accept, Core rejects -> gap
           (incf fp)
           (incf (gethash expected fp-flags 0))   ; expected = Core's error code
           (when (< (length (gethash expected fp-ex)) 3)
             (push (list (aref c 0) (aref c 1) flags) (gethash expected fp-ex))))
          (t                                 ; we reject, Core accepts -> bug
           (incf fn)
           (when (< (length fn-examples) 12)
             (push (list (aref c 0) (aref c 1) flags expected) fn-examples))))))
    (let ((total (+ agree-ok agree-fail fp fn)))
      (format t "~&==== script_tests.json conformance (~d cases) ====~%" total)
      (format t "  agree OK    : ~d~%" agree-ok)
      (format t "  agree FAIL  : ~d~%" agree-fail)
      (format t "  AGREE total : ~d (~,1f%)~%" (+ agree-ok agree-fail)
              (* 100.0 (/ (+ agree-ok agree-fail) total)))
      (format t "  FALSE-POS   : ~d  (we accept, Core rejects — unenforced rules)~%" fp)
      (format t "  FALSE-NEG   : ~d  (we reject, Core accepts — interpreter bugs)~%" fn)
      (format t "~%  false-positive by expected-error (top rule gaps):~%")
      (let ((pairs (sort (loop for k being the hash-keys of fp-flags using (hash-value v) collect (cons k v))
                         #'> :key #'cdr)))
        (loop for (k . v) in pairs repeat 16 do
          (format t "    ~5d  ~a~%" v k)
          (when *show-fp*
            (dolist (e (reverse (gethash k fp-ex)))
              (format t "            sig=~a pk=~a [~a]~%"
                      (subseq (first e) 0 (min 36 (length (first e))))
                      (subseq (second e) 0 (min 36 (length (second e)))) (third e))))))
      (when fn-examples
        (format t "~%  false-negative examples (OUR BUGS to fix):~%")
        (dolist (e (reverse fn-examples))
          (format t "    expected ~a flags=~a~%      sig=~a pk=~a~%"
                  (fourth e) (third e) (subseq (first e) 0 (min 40 (length (first e))))
                  (subseq (second e) 0 (min 40 (length (second e)))))))
      (values (/ (+ agree-ok agree-fail) total) fn))))

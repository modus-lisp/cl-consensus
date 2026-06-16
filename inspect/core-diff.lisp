;;;; inspect/core-diff.lisp
;;;;
;;;; The HARDCORE differential: call Bitcoin Core's *actual compiled* consensus
;;;; code (libbitcoinkernel, built from a v29.1 checkout) via a tiny C++ shim
;;;; (core_shim.cpp -> core_verify_script), and diff it against our interpreter.
;;;;
;;;; Calling Core's VerifyScript directly lets us pass the FULL SCRIPT_VERIFY_*
;;;; flag set — consensus AND policy, including TAPROOT — so we can:
;;;;   (vectors)     re-run all of Core's script_tests through its LIVE code and
;;;;                 triangulate Core-now vs ours vs the recorded expected;
;;;;   (fuzz)        random scripts over the full flag set;
;;;;   (fuzz-mutate) mutations of the real corpus.
;;;;
;;;; Build first: inspect/build-libkernel.sh    Then:
;;;;   sbcl --load inspect/core-diff.lisp --eval '(core-diff:ci)'

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (pushnew (uiop:pathname-parent-directory-pathname
            (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
           asdf:*central-registry* :test #'equal)
  (ql:quickload '(:cffi :com.inuoe.jzon) :silent t)
  (asdf:load-system "cl-consensus"))

(defpackage #:core-diff
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script) (#:jzon #:com.inuoe.jzon))
  (:export #:core-verify #:diff-one #:vectors #:fuzz #:fuzz-mutate #:load-corpus #:ci #:*lib-path*))

(in-package #:core-diff)

(defparameter *lib-path* "/mnt/lisp/bitcoin-kernel/build/lib/core_shim.so")
(cffi:load-foreign-library *lib-path*)   ; rpath pulls in libbitcoinkernel.so

(cffi:defcfun ("core_verify_script" %core-verify) :int
  (script-pubkey :pointer) (script-pubkey-len :unsigned-long)
  (amount :int64)
  (tx-to :pointer) (tx-to-len :unsigned-long)
  (n-in :uint) (flags :uint))

;;; our flag keyword -> Core SCRIPT_VERIFY_* bit (v29 src/script/interpreter.h)
(defparameter *core-flag-bits*
  '((:p2sh . #.(ash 1 0)) (:strictenc . #.(ash 1 1)) (:dersig . #.(ash 1 2))
    (:low-s . #.(ash 1 3)) (:nulldummy . #.(ash 1 4)) (:sigpushonly . #.(ash 1 5))
    (:minimaldata . #.(ash 1 6)) (:discourage-nops . #.(ash 1 7)) (:cleanstack . #.(ash 1 8))
    (:cltv . #.(ash 1 9)) (:csv . #.(ash 1 10)) (:witness . #.(ash 1 11))
    (:discourage-upgradable-witness . #.(ash 1 12)) (:minimalif . #.(ash 1 13))
    (:nullfail . #.(ash 1 14)) (:witness-pubkeytype . #.(ash 1 15)) (:taproot . #.(ash 1 17))))
(defparameter *supported-flags* (mapcar #'car *core-flag-bits*))

(defun core-flags (our-flags)
  (reduce #'logior our-flags :key (lambda (f) (or (cdr (assoc f *core-flag-bits*)) 0))
          :initial-value 0))

(defun bytes->foreign (bytes)
  (let* ((n (length bytes)) (p (cffi:foreign-alloc :unsigned-char :count (max 1 n))))
    (dotimes (i n) (setf (cffi:mem-aref p :unsigned-char i) (aref bytes i)))
    (values p n)))

(defun core-verify (script-pubkey amount tx-to n-in our-flags)
  "Call Core's compiled VerifyScript via the shim.  Returns :valid / :invalid /
   :err (deserialization failure)."
  (multiple-value-bind (sp spn) (bytes->foreign script-pubkey)
    (multiple-value-bind (tp tpn) (bytes->foreign tx-to)
      (unwind-protect
           (case (%core-verify sp spn amount tp tpn n-in (core-flags our-flags))
             (1 :valid) (0 :invalid) (t :err))
        (cffi:foreign-free sp) (cffi:foreign-free tp)))))

;;; ----------------------------------------------------------------------------
;;; Synthetic credit/spend tx (same construction as Core's script_tests.cpp)
;;; ----------------------------------------------------------------------------

(defun build-credit (pk amount)
  (tx:finalize-tx
   (tx:make-tx :version 1 :locktime 0 :segwit-p nil
     :inputs (list (tx:make-txin
                    :prev-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                    :prev-index #xffffffff
                    :script (coerce #(0 0) '(simple-array (unsigned-byte 8) (*)))
                    :sequence #xffffffff))
     :outputs (list (tx:make-txout :value amount :script pk)))))

(defun build-spend (credit sig witness amount)
  (let ((spend (tx:make-tx :version 1 :locktime 0 :segwit-p (and witness t)
                 :inputs (list (tx:make-txin :prev-hash (tx:tx-txid credit) :prev-index 0
                                :script sig :sequence #xffffffff))
                 :outputs (list (tx:make-txout :value amount
                                 :script (make-array 0 :element-type '(unsigned-byte 8)))))))
    (when witness (setf (tx:tx-witnesses spend) (list witness)))
    (tx:finalize-tx spend)))

(defun ours-verify (spend pk amount our-flags)
  (handler-case (if (s:verify-input spend 0 pk amount :flags our-flags
                                    :prevouts (vector (cons amount pk)))
                    :valid :invalid)
    (error () :invalid)))

(defun valid-flags (fs)
  "Add the prerequisites Core's VerifyScript ASSERTS on (an invalid combo aborts
   the whole process): CLEANSTACK/TAPROOT ⇒ WITNESS ⇒ P2SH."
  (let ((fs (copy-list fs)))
    (when (or (member :witness fs) (member :taproot fs) (member :cleanstack fs))
      (pushnew :witness fs) (pushnew :p2sh fs))
    fs))

(defun diff-one (sig pk witness our-flags-in &optional (amount 0))
  "Run one case through Core and us.  Returns (values core ours agree?)."
  (let* ((our-flags (valid-flags our-flags-in))
         (credit (build-credit pk amount))
         (spend (build-spend credit sig witness amount))
         (txto (tx:serialize-tx spend :witness (and witness t)))
         (core (core-verify pk amount txto 0 our-flags))
         (ours (ours-verify spend pk amount our-flags)))
    ;; treat Core deserialization errors as "invalid" for comparison
    (let ((c (if (eq core :err) :invalid core)))
      (values c ours (eq c ours)))))

;;; ----------------------------------------------------------------------------
;;; (1) Cross-check the WHOLE script_tests corpus through Core's live code
;;; ----------------------------------------------------------------------------

(defparameter *flag-map*
  '(("P2SH" . :p2sh) ("WITNESS" . :witness) ("STRICTENC" . :strictenc)
    ("DERSIG" . :dersig) ("LOW_S" . :low-s) ("NULLDUMMY" . :nulldummy)
    ("SIGPUSHONLY" . :sigpushonly) ("MINIMALDATA" . :minimaldata)
    ("CLEANSTACK" . :cleanstack) ("MINIMALIF" . :minimalif) ("NULLFAIL" . :nullfail)
    ("WITNESS_PUBKEYTYPE" . :witness-pubkeytype) ("TAPROOT" . :taproot)
    ("DISCOURAGE_UPGRADABLE_NOPS" . :discourage-nops)
    ("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" . :discourage-upgradable-witness)
    ("CHECKLOCKTIMEVERIFY" . :cltv) ("CHECKSEQUENCEVERIFY" . :csv)))

(defun parse-flags (flags)
  (loop for tok in (uiop:split-string flags :separator ",")
        for kw = (cdr (assoc (string-trim " " tok) *flag-map* :test #'string=))
        when kw collect kw))

(defun vectors (&optional (path "inspect/vectors/script_tests_hex.json"))
  "Run all of Core's script_tests through Core's LIVE compiled code and through
   ours; triangulate against the recorded expected result."
  (let ((cases (with-open-file (f path) (jzon:parse f)))
        (n 0) (core-vs-ours 0) (core-vs-recorded 0))
    (loop for c across cases do
      (let* ((sig (w:hex->bytes (aref c 0))) (pk (w:hex->bytes (aref c 1)))
             (flags (parse-flags (aref c 2)))
             (recorded (if (string= (aref c 3) "OK") :valid :invalid))
             (wit (let ((ws (map 'list #'w:hex->bytes (aref c 4)))) (and ws ws)))
             (amount (truncate (aref c 5))))
        (incf n)
        (multiple-value-bind (core ours) (diff-one sig pk wit flags amount)
          (unless (eq core ours)
            (incf core-vs-ours)
            (when (<= core-vs-ours 15)
              (format t "~&  CORE≠OURS core=~a ours=~a [~a]~%    sig=~a pk=~a~%"
                      core ours (aref c 2) (aref c 0) (aref c 1))))
          (unless (eq core recorded) (incf core-vs-recorded)))))
    (format t "~&==== script_tests through Core's LIVE libbitcoinkernel (~d cases) ====~%" n)
    (format t "  Core vs ours      : ~d disagreements~%" core-vs-ours)
    (format t "  Core vs recorded  : ~d (v29 code vs v26-era recorded expected)~%" core-vs-recorded)
    core-vs-ours))

;;; ----------------------------------------------------------------------------
;;; (2) Fuzz — random + mutation, over the full flag set (non-witness scripts)
;;; ----------------------------------------------------------------------------

(defparameter *opcode-pool*
  (concatenate 'vector
    #(#x00 #x4f #x51 #x52 #x53 #x60 #x61 #x63 #x64 #x67 #x68 #x69 #x6a)
    #(#x6b #x6c #x6d #x6e #x6f #x73 #x74 #x75 #x76 #x77 #x78 #x79 #x7a #x7b #x7c #x7d)
    #(#x82 #x87 #x88 #x8b #x8c #x8f #x90 #x91 #x92 #x93 #x94 #x95 #x9a #x9b #x9c #x9f #xa0 #xa3 #xa4 #xa5)
    #(#xa6 #xa7 #xa8 #xa9 #xaa #xac #xad #xae #xaf #xb1 #xb2)))

(defun random-script (max-ops)
  (let ((wr (w:make-writer)))
    (dotimes (i (1+ (random max-ops)))
      (if (< (random 100) 35)
          (let ((n (random 6))) (w:w-u8 wr n) (dotimes (k n) (w:w-u8 wr (random 256))))
          (w:w-u8 wr (aref *opcode-pool* (random (length *opcode-pool*))))))
    (w:writer-bytes wr)))

(defun random-flags ()
  ;; Core's VerifyScript asserts WITNESS=>P2SH and CLEANSTACK=>{P2SH,WITNESS},
  ;; TAPROOT=>WITNESS.  An invalid combo aborts the whole process, so enforce it.
  (let ((fs (loop for f in *supported-flags* when (zerop (random 2)) collect f)))
    (when (or (member :witness fs) (member :taproot fs) (member :cleanstack fs))
      (pushnew :p2sh fs) (pushnew :witness fs))
    fs))

(defstruct (fz (:conc-name fz-)) (agree 0) (valid 0) (diverge 0) (errs 0) (examples '()))

(defun fz-run (fz sig pk flags)
  (handler-case
      (multiple-value-bind (core ours ok) (diff-one sig pk nil flags)
        (cond (ok (incf (fz-agree fz)) (when (eq core :valid) (incf (fz-valid fz))))
              (t (incf (fz-diverge fz))
                 (when (< (length (fz-examples fz)) 25)
                   (push (list (w:bytes->hex sig) (w:bytes->hex pk) flags core ours) (fz-examples fz))))))
    (error () (incf (fz-errs fz)))))

(defun fz-report (fz label rounds)
  (format t "~%==== core-diff ~a: ~d rounds ====~%" label rounds)
  (format t "  agree ~d (both-valid ~d)~%  DIVERGE ~d~%  harness-err ~d~%"
          (fz-agree fz) (fz-valid fz) (fz-diverge fz) (fz-errs fz))
  (dolist (e (reverse (fz-examples fz)))
    (destructuring-bind (sig pk flags core ours) e
      (format t "    flags ~a core=~a ours=~a~%      sig=~a~%      pk =~a~%" flags core ours sig pk)))
  (fz-diverge fz))

(defun fuzz (&optional (rounds 100000) (max-ops 8))
  (let ((fz (make-fz)))
    (dotimes (i rounds)
      (fz-run fz (random-script (max 1 (floor max-ops 2))) (random-script max-ops) (random-flags))
      (when (and (plusp i) (zerop (mod i 20000)))
        (format t "~&[fuzz] ~d/~d agree ~d diverge ~d~%" i rounds (fz-agree fz) (fz-diverge fz)) (force-output)))
    (fz-report fz "random fuzz" rounds)))

(defparameter *corpus* nil)
(defun load-corpus (&optional (path "inspect/vectors/script_tests_hex.json"))
  (setf *corpus* (let ((cs (with-open-file (f path) (jzon:parse f))))
                   (coerce (loop for c across cs collect (cons (w:hex->bytes (aref c 0)) (w:hex->bytes (aref c 1)))) 'vector)))
  (length *corpus*))

(defun mutate (b)
  (let ((b (copy-seq b)) (n (length b)))
    (when (plusp n)
      (case (random 4)
        (0 (setf (aref b (random n)) (random 256)))
        (1 (setf b (concatenate '(simple-array (unsigned-byte 8) (*)) (subseq b 0 (random (1+ n)))
                                (vector (random 256)) (subseq b (random (1+ n))))))
        (2 (when (> n 1) (setf b (concatenate '(simple-array (unsigned-byte 8) (*))
                                              (subseq b 0 (random n)) (subseq b (1+ (random n)))))))
        (3 (setf (aref b (random n)) (aref *opcode-pool* (random (length *opcode-pool*)))))))
    b))

(defun fuzz-mutate (&optional (rounds 100000))
  (unless *corpus* (load-corpus))
  (let ((fz (make-fz)))
    (dotimes (i rounds)
      (let* ((base (aref *corpus* (random (length *corpus*)))) (sig (car base)) (pk (cdr base)))
        (dotimes (k (1+ (random 3))) (setf sig (mutate sig) pk (mutate pk)))
        (fz-run fz sig pk (random-flags)))
      (when (and (plusp i) (zerop (mod i 20000)))
        (format t "~&[mutate] ~d/~d agree ~d both-valid ~d diverge ~d~%"
                i rounds (fz-agree fz) (fz-valid fz) (fz-diverge fz)) (force-output)))
    (fz-report fz "mutation fuzz" rounds)))

(defun ci (&optional (rounds 50000))
  "Full corpus cross-check + random + mutation fuzz vs Core's compiled code."
  (let ((d 0))
    (incf d (vectors))
    (incf d (fuzz rounds))
    (incf d (fuzz-mutate rounds))
    (format t "~&CORE-DIFF: ~a (~d total divergences)~%" (if (zerop d) "PASS" "FAIL") d)
    (sb-ext:exit :code (if (zerop d) 0 1))))

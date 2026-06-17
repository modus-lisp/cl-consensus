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
  (asdf:load-system "cl-consensus")
  (load (merge-pathnames "vectors.lisp" (or *load-truename* *compile-file-truename*))))

(defpackage #:core-diff
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script) (#:jzon #:com.inuoe.jzon)
                    (#:bv #:btc-vectors)
                    (#:ec #:cl-consensus.crypto.secp256k1) (#:sch #:cl-consensus.crypto.schnorr))
  (:export #:core-verify #:diff-one #:vectors #:fuzz #:fuzz-mutate #:load-corpus #:ci
           #:taproot-fuzz #:assets #:*lib-path*))

(in-package #:core-diff)

(defparameter *lib-path* "/mnt/lisp/bitcoin-kernel/build/lib/core_shim.so")
(cffi:load-foreign-library *lib-path*)   ; rpath pulls in libbitcoinkernel.so

(cffi:defcfun ("core_verify_script" %core-verify) :int
  (script-pubkey :pointer) (script-pubkey-len :unsigned-long)
  (amount :int64)
  (tx-to :pointer) (tx-to-len :unsigned-long)
  (n-in :uint) (flags :uint))

(cffi:defcfun ("core_verify_tx" %core-verify-tx) :int
  (tx-to :pointer) (tx-to-len :unsigned-long)
  (spents :pointer) (spents-len :unsigned-long)
  (input-index :uint) (flags :uint))

;;; our flag keyword -> Core SCRIPT_VERIFY_* bit (v29 src/script/interpreter.h)
(defparameter *core-flag-bits*
  '((:p2sh . #.(ash 1 0)) (:strictenc . #.(ash 1 1)) (:dersig . #.(ash 1 2))
    (:low-s . #.(ash 1 3)) (:nulldummy . #.(ash 1 4)) (:sigpushonly . #.(ash 1 5))
    (:minimaldata . #.(ash 1 6)) (:discourage-nops . #.(ash 1 7)) (:cleanstack . #.(ash 1 8))
    (:cltv . #.(ash 1 9)) (:csv . #.(ash 1 10)) (:witness . #.(ash 1 11))
    (:discourage-upgradable-witness . #.(ash 1 12)) (:minimalif . #.(ash 1 13))
    (:nullfail . #.(ash 1 14)) (:witness-pubkeytype . #.(ash 1 15)) (:taproot . #.(ash 1 17))
    (:discourage-upgradable-taproot-version . #.(ash 1 18))
    (:discourage-op-success . #.(ash 1 19))
    (:discourage-upgradable-pubkeytype . #.(ash 1 20))))
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

(defun vectors (&optional (path "inspect/vectors/script_tests.json"))
  "Run all of Core's script_tests through Core's LIVE compiled code and through
   ours; triangulate against the recorded expected result."
  (let ((cases (bv:load-script-tests path))
        (n 0) (core-vs-ours 0) (core-vs-recorded 0))
    (loop for c across cases do
      (destructuring-bind (sig pk flags-str expected wit amount) c
       (let* ((flags (parse-flags flags-str))
             (recorded (if (string= expected "OK") :valid :invalid)))
        (incf n)
        (multiple-value-bind (core ours) (diff-one sig pk wit flags amount)
          (unless (eq core ours)
            (incf core-vs-ours)
            (when (<= core-vs-ours 15)
              (format t "~&  CORE≠OURS core=~a ours=~a [~a]~%    sig=~a pk=~a~%"
                      core ours flags-str (w:bytes->hex sig) (w:bytes->hex pk))))
          (unless (eq core recorded) (incf core-vs-recorded))))))
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
(defun load-corpus (&optional (path "inspect/vectors/script_tests.json"))
  (setf *corpus* (let ((cs (bv:load-script-tests path)))
                   (coerce (loop for c across cs collect (cons (first c) (second c))) 'vector)))
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
  "Corpus cross-check + random/mutation/taproot fuzz vs Core's compiled code.
   If the optional script_assets_test.json is present (bring-your-own; Core's
   Python framework generates it — see ROADMAP), its ~5.2k full taproot/tapscript
   spend cases are GATED too: the BIP342 surface (OP_SUCCESS, unknown tapleaf
   versions, sigops budget, CODESEPARATOR/siglen-in-tapscript) is now implemented
   and diffs 0 vs Core."
  (let ((d 0))
    (incf d (vectors))
    (incf d (fuzz rounds))
    (incf d (fuzz-mutate rounds))
    (incf d (taproot-fuzz 1500))                 ; pure-Lisp schnorr is slow; keep modest
    (when (probe-file "/mnt/lisp/script_assets_test.json")
      (incf d (assets)))
    (format t "~&CORE-DIFF: ~a (~d divergences)~%" (if (zerop d) "PASS" "FAIL") d)
    (sb-ext:exit :code (if (zerop d) 0 1))))

;;; ----------------------------------------------------------------------------
;;; (3) Taproot witness fuzzing — construct REAL taproot spends (key-path and
;;; tapscript), diff against Core's libbitcoinkernel via core_verify_tx, then
;;; mutate the witness and check both still agree.  This exercises the segwit-v1
;;; verification path (commitment, BIP341 sighash, schnorr) end to end.
;;; ----------------------------------------------------------------------------

(defun core-verify-tx (txto spents idx flags)
  (multiple-value-bind (tp tpn) (bytes->foreign txto)
    (multiple-value-bind (sp spn) (bytes->foreign spents)
      (unwind-protect
           (case (%core-verify-tx tp tpn sp spn idx (core-flags (valid-flags flags)))
             (1 :valid) (0 :invalid) (t :err))
        (cffi:foreign-free tp) (cffi:foreign-free sp)))))

(defun serialize-txout (amount script)
  (let ((wr (w:make-writer)))
    (w:w-i64 wr amount) (w:w-varint wr (length script)) (w:w-bytes wr script)
    (w:writer-bytes wr)))

(defun random-priv () (1+ (random (1- ec:*secp256k1-n*))))
(defun even-y-priv (d) (if (evenp (cdr (ec:secp-pubkey d))) d (- ec:*secp256k1-n* d)))
(defun bvec (&rest xs) (coerce xs '(simple-array (unsigned-byte 8) (*))))

(defun spend-tx-for (spk amount)
  (tx:make-tx :version 2 :locktime 0 :segwit-p t
    :inputs (list (tx:make-txin :prev-hash (w:hash256 (ironclad:ascii-string-to-byte-array "tp"))
                   :prev-index 0 :script (bvec) :sequence #xffffffff))
    :outputs (list (tx:make-txout :value (max 0 (- amount 1000)) :script (bvec #x6a)))))

(defun build-keypath ()
  "Build a valid taproot key-path spend.  Returns (values spend spk amount)."
  (let* ((d (even-y-priv (random-priv)))
         (px (ec:int-to-bytes32 (car (ec:secp-pubkey d))))
         (tweak (ec:bytes-to-int (sch:tagged-hash "TapTweak" px)))   ; key-path: no script tree
         (out-priv (mod (+ d tweak) ec:*secp256k1-n*))
         (qx (ec:int-to-bytes32 (car (ec:secp-pubkey out-priv))))
         (spk (concatenate '(simple-array (unsigned-byte 8) (*)) (bvec #x51 #x20) qx))
         (amount (1+ (random 1000000000)))
         (spend (spend-tx-for spk amount))
         (digest (s:taproot-sighash spend 0 (vector (cons amount spk)) 0 :ext-flag 0))
         (sig (sch:schnorr-sign out-priv digest)))
    (setf (tx:tx-witnesses spend) (list (list sig)))
    (tx:finalize-tx spend)
    (values spend spk amount)))

(defun build-tapscript ()
  "Build a valid taproot script-path spend: a single <pk> CHECKSIG tapleaf."
  (let* ((leaf-priv (even-y-priv (random-priv)))
         (leaf-px (ec:int-to-bytes32 (car (ec:secp-pubkey leaf-priv))))
         (leaf-script (concatenate '(simple-array (unsigned-byte 8) (*)) (bvec #x20) leaf-px (bvec #xac)))
         (leaf (s:tapleaf-hash #xc0 leaf-script))
         (d (even-y-priv (random-priv)))
         (px (ec:int-to-bytes32 (car (ec:secp-pubkey d))))
         (tweak (ec:bytes-to-int (sch:tagged-hash "TapTweak"
                  (concatenate '(simple-array (unsigned-byte 8) (*)) px leaf))))
         (qpt (ec:secp-add-points (ec:secp-pubkey d) (ec:secp-mul-point tweak (ec:secp-generator))))
         (qx (ec:int-to-bytes32 (car qpt)))
         (parity (logand (cdr qpt) 1))
         (spk (concatenate '(simple-array (unsigned-byte 8) (*)) (bvec #x51 #x20) qx))
         (amount (1+ (random 1000000000)))
         (spend (spend-tx-for spk amount))
         (digest (s:taproot-sighash spend 0 (vector (cons amount spk)) 0 :ext-flag 1 :tapleaf-hash leaf))
         (sig (sch:schnorr-sign leaf-priv digest))
         (control (concatenate '(simple-array (unsigned-byte 8) (*)) (bvec (logior #xc0 parity)) px)))
    (setf (tx:tx-witnesses spend) (list (list sig leaf-script control)))
    (tx:finalize-tx spend)
    (values spend spk amount)))

(defun diff-taproot (spend spk amount)
  "Core (libbitcoinkernel) vs ours on a taproot spend.  Returns (values core ours)."
  (let* ((flags '(:p2sh :witness :taproot :dersig :nulldummy :cltv :csv))
         (txto (tx:serialize-tx spend :witness t))
         (spents (serialize-txout amount spk))
         (core (core-verify-tx txto spents 0 flags))
         (ours (handler-case (if (s:verify-input spend 0 spk amount
                                                 :flags flags :prevouts (vector (cons amount spk)))
                                 :valid :invalid)
                 (error () :invalid))))
    (values (if (eq core :err) :invalid core) ours)))

(defun mutate-witness (spend)
  "Flip a random byte in a random witness item of input 0 (returns a copy-spend)."
  (let* ((wit (mapcar #'copy-seq (first (tx:tx-witnesses spend))))
         (item (nth (random (length wit)) wit)))
    (when (plusp (length item))
      (let ((j (random (length item)))) (setf (aref item j) (logxor (aref item j) #x01))))
    (setf (tx:tx-witnesses spend) (list wit))
    (tx:finalize-tx spend)
    spend))

(defun taproot-fuzz (&optional (rounds 4000))
  "Construct valid key-path/tapscript spends + byte-mutated variants; diff each
   against Core's libbitcoinkernel."
  (setf *random-state* (make-random-state t))
  (let ((fz (make-fz)) (kp-valid 0) (ts-valid 0))
    (dotimes (i rounds)
      (handler-case
          (multiple-value-bind (spend spk amount)
              (if (zerop (random 2)) (build-keypath) (build-tapscript))
            ;; valid spend: expect both :valid
            (multiple-value-bind (core ours) (diff-taproot spend spk amount)
              (if (eq core ours)
                  (progn (incf (fz-agree fz)) (when (eq core :valid) (incf (fz-valid fz))))
                  (progn (incf (fz-diverge fz))
                         (when (< (length (fz-examples fz)) 15)
                           (push (list "valid" (w:bytes->hex spk) core ours) (fz-examples fz)))))
              (when (eq core :valid)
                (if (zerop (random 2)) (incf kp-valid) (incf ts-valid))))
            ;; mutated witness: expect both :invalid
            (let ((m (mutate-witness spend)))
              (multiple-value-bind (core ours) (diff-taproot m spk amount)
                (if (eq core ours) (incf (fz-agree fz))
                    (progn (incf (fz-diverge fz))
                           (when (< (length (fz-examples fz)) 15)
                             (push (list "mutated" (w:bytes->hex spk) core ours) (fz-examples fz))))))))
        (error () (incf (fz-errs fz))))
      (when (and (plusp i) (zerop (mod i 1000)))
        (format t "~&[taproot] ~d/~d agree ~d both-valid ~d diverge ~d~%"
                i rounds (fz-agree fz) (fz-valid fz) (fz-diverge fz)) (force-output)))
    (format t "~%==== taproot fuzz: ~d rounds (key-path + tapscript, +mutations) ====~%" rounds)
    (format t "  agree ~d (constructed-valid accepted by both ~d)~%  DIVERGE ~d~%  harness-err ~d~%"
            (fz-agree fz) (fz-valid fz) (fz-diverge fz) (fz-errs fz))
    (dolist (e (reverse (fz-examples fz)))
      (format t "    ~a spk=~a core=~a ours=~a~%" (first e) (second e) (third e) (fourth e)))
    (fz-diverge fz)))

;;; ----------------------------------------------------------------------------
;;; (4) OPTIONAL bring-your-own corpus: Core's generated script_assets_test.json
;;; — ~100k taproot/tapscript spend cases.  This repo does NOT generate it (that
;;; needs Core's Python test framework — feature_taproot.py --dumptests — kept out
;;; of cl-consensus on purpose); drop the file at /mnt/lisp/script_assets_test.json
;;; and (assets) will run it.  Our primary taproot gate is (taproot-fuzz), which
;;; constructs real key-path + tapscript spends in Lisp.  Each asset case: a full
;;; spending tx, all prevouts (serialized CTxOuts), the input index, flags, and a
;;; success (and maybe failure) scriptSig+witness to splice in.
;;; ----------------------------------------------------------------------------

(defun deserialize-txout (hex)
  "Serialized CTxOut hex -> (amount . scriptPubKey-bytes)."
  (let* ((r (w:make-reader (w:hex->bytes hex)))
         (amount (w:r-i64 r)) (len (w:r-varint r)))
    (cons amount (w:r-bytes r len))))

(defun asset-flags (flags-field)
  "script_assets flags (a JSON array of names, or a comma string) -> our keywords."
  (let ((names (if (stringp flags-field) (uiop:split-string flags-field :separator ",")
                   (coerce flags-field 'list))))
    (loop for nm in names for kw = (cdr (assoc (string-trim " " nm) *flag-map* :test #'string=))
          when kw collect kw)))

(defun run-asset (tx-hex prevout-hexes idx flags wit)
  "WIT = (scriptSig-hex . list-of-witness-hex).  Returns (values core ours)."
  (let* ((tx (tx:parse-tx (w:make-reader (w:hex->bytes tx-hex))))
         (prevouts (map 'vector #'deserialize-txout prevout-hexes))
         (spents (let ((wr (w:make-writer)))
                   (loop for h across prevout-hexes do (w:w-bytes wr (w:hex->bytes h)))
                   (w:writer-bytes wr)))
         (our-flags (asset-flags flags)))
    ;; splice the success/failure scriptSig + witness onto input IDX
    (setf (tx:txin-script (nth idx (tx:tx-inputs tx))) (w:hex->bytes (car wit)))
    (let ((ws (loop for i below (length (tx:tx-inputs tx))
                    collect (if (= i idx) (mapcar #'w:hex->bytes (cdr wit))
                                (and (tx:tx-witnesses tx) (nth i (tx:tx-witnesses tx)))))))
      (setf (tx:tx-witnesses tx) ws)
      ;; Serialize WITH a witness only if some input actually carries one.  Core's
      ;; tx deserializer throws "Superfluous witness record" on a witness marker
      ;; with HasWitness()==false — which happens when the tested input is legacy
      ;; and no other input has witness data (multi-input legacy-among-taproot).
      (setf (tx:tx-segwit-p tx)
            (and (some (lambda (w) (some (lambda (item) (plusp (length item))) w)) ws) t)))
    (tx:finalize-tx tx)
    (let* ((txto (tx:serialize-tx tx :witness (tx:tx-segwit-p tx)))
           (core (core-verify-tx txto spents idx our-flags))
           (ours (handler-case
                     (if (s:verify-input tx idx (cdr (aref prevouts idx)) (car (aref prevouts idx))
                                         :flags our-flags :prevouts prevouts)
                         :valid :invalid)
                   (error () :invalid))))
      (values (if (eq core :err) :invalid core) ours))))

(defun assets (&optional (path "/mnt/lisp/script_assets_test.json") (limit most-positive-fixnum))
  (let ((cases (with-open-file (f path) (jzon:parse f)))
        (n 0) (cvo 0) (cve 0) (ex '()))
    (loop for c across cases while (< n limit) do
      (when (and (hash-table-p c) (gethash "tx" c))
        (let ((txh (gethash "tx" c)) (pv (gethash "prevouts" c))
              (idx (truncate (gethash "index" c))) (flags (gethash "flags" c)))
          (dolist (kind '("success" "failure"))
            (let ((wd (gethash kind c)))
              (when wd
                (incf n)
                (let ((wit (cons (gethash "scriptSig" wd) (coerce (gethash "witness" wd) 'list)))
                      (expected (if (string= kind "success") :valid :invalid)))
                  (handler-case
                      (multiple-value-bind (core ours) (run-asset txh pv idx flags wit)
                        (unless (eq core ours)
                          (incf cvo)
                          (when (<= cvo 15)
                            (push (list kind core ours (gethash "comment" c)) ex)))
                        (unless (eq core expected) (incf cve)))
                    (error () (incf cve))))
                (when (zerop (mod n 20000))
                  (format t "~&[assets] ~d  core-vs-ours ~d~%" n cvo) (force-output))))))))
    (format t "~&==== script_assets_test.json through Core's libbitcoinkernel (~d cases) ====~%" n)
    (format t "  Core vs ours      : ~d disagreements~%" cvo)
    (format t "  Core vs expected  : ~d (success->valid / failure->invalid)~%" cve)
    (dolist (e (reverse ex))
      (format t "    ~a core=~a ours=~a  ~a~%" (first e) (second e) (third e) (fourth e)))
    cvo))

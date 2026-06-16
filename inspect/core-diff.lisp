;;;; inspect/core-diff.lisp
;;;;
;;;; The HARDCORE differential: call Bitcoin Core's *actual compiled* script
;;;; verifier (libbitcoinconsensus, built from a checkout of bitcoin/bitcoin) via
;;;; FFI, and diff it against our interpreter on fuzzed inputs.
;;;;
;;;; Where conformance.lisp checks us against Core's *recorded* test vectors,
;;;; this checks us against Core's *running code* on scripts nobody wrote down —
;;;; random and mutated scripts, run through both and compared.
;;;;
;;;; Build the lib first (see inspect/build-libconsensus.sh), then:
;;;;   sbcl --load inspect/core-diff.lisp \
;;;;        --eval '(in-package :core-diff)' --eval '(fuzz 200000)'
;;;;
;;;; libbitcoinconsensus exposes the consensus script flags P2SH/DERSIG/NULLDUMMY/
;;;; CLTV/CSV/WITNESS; we fuzz over those (taproot/policy flags need libkernel).

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (pushnew (uiop:pathname-parent-directory-pathname
            (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
           asdf:*central-registry* :test #'equal)
  (ql:quickload '(:cffi) :silent t)
  (asdf:load-system "cl-consensus"))

(defpackage #:core-diff
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script))
  (:export #:core-verify #:diff-one #:fuzz #:fuzz-mutate #:load-corpus #:ci #:*lib-path*))

(in-package #:core-diff)

(defparameter *lib-path*
  (or (first (directory #p"/mnt/lisp/bitcoin-core/src/.libs/libbitcoinconsensus.so*"))
      (first (directory #p"/mnt/lisp/bitcoin-core/src/libbitcoinconsensus.so*"))
      "/mnt/lisp/bitcoin-core/src/.libs/libbitcoinconsensus.so"))

(cffi:load-foreign-library (namestring *lib-path*))

(cffi:defcfun ("bitcoinconsensus_verify_script_with_amount" %verify-amount) :int
  (script-pubkey :pointer) (script-pubkey-len :uint)
  (amount :int64)
  (tx-to :pointer) (tx-to-len :uint)
  (n-in :uint) (flags :uint) (err :pointer))

;;; our flag keyword -> libbitcoinconsensus flag bit
(defparameter *core-flag-bits*
  '((:p2sh . 1) (:dersig . 4) (:nulldummy . 16)
    (:cltv . 512) (:csv . 1024) (:witness . 2048)))
(defparameter *supported-flags* (mapcar #'car *core-flag-bits*))

(defun core-flags (our-flags)
  (reduce #'logior our-flags :key (lambda (f) (or (cdr (assoc f *core-flag-bits*)) 0))
          :initial-value 0))

(defun bytes->foreign (bytes)
  (let* ((n (length bytes))
         (p (cffi:foreign-alloc :unsigned-char :count (max 1 n))))
    (dotimes (i n) (setf (cffi:mem-aref p :unsigned-char i) (aref bytes i)))
    (values p n)))

(defun core-verify (script-pubkey amount tx-to n-in our-flags)
  "Call Core's compiled verifier.  Returns T (valid) / NIL (invalid)."
  (multiple-value-bind (sp spn) (bytes->foreign script-pubkey)
    (multiple-value-bind (tp tpn) (bytes->foreign tx-to)
      (cffi:with-foreign-object (err :int)
        (unwind-protect
             (= 1 (%verify-amount sp spn amount tp tpn n-in (core-flags our-flags) err))
          (cffi:foreign-free sp) (cffi:foreign-free tp))))))

;;; ----------------------------------------------------------------------------
;;; Synthetic credit/spend tx (same construction Core's script_tests uses)
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

(defun build-spend (credit sig amount)
  (tx:finalize-tx
   (tx:make-tx :version 1 :locktime 0 :segwit-p nil
     :inputs (list (tx:make-txin :prev-hash (tx:tx-txid credit) :prev-index 0
                    :script sig :sequence #xffffffff))
     :outputs (list (tx:make-txout :value amount
                     :script (make-array 0 :element-type '(unsigned-byte 8)))))))

(defun diff-one (sig pk our-flags &optional (amount 0))
  "Run one (scriptSig, scriptPubKey, flags) through both Core and us.
   Returns (values core-result our-result agree?)."
  (let* ((credit (build-credit pk amount))
         (spend (build-spend credit sig amount))
         (txto (tx:serialize-tx spend :witness nil))
         (core (core-verify pk amount txto 0 our-flags))
         (ours (handler-case (and (s:verify-input spend 0 pk amount :flags our-flags) t)
                 (error () nil))))
    (values core ours (eq core ours))))

;;; ----------------------------------------------------------------------------
;;; Fuzzer — random scripts over the supported consensus flags
;;; ----------------------------------------------------------------------------

;; a pool of opcodes worth exercising (stack / arith / compare / crypto / flow)
(defparameter *opcode-pool*
  (concatenate 'vector
    #(#x00 #x4f #x51 #x52 #x53 #x60)                       ; OP_0,1NEGATE,1,2,3,16
    #(#x61 #x63 #x64 #x67 #x68 #x69 #x6a)                  ; NOP IF NOTIF ELSE ENDIF VERIFY RETURN
    #(#x6b #x6c #x6d #x6e #x6f #x73 #x74 #x75 #x76 #x77 #x78 #x79 #x7a #x7b #x7c #x7d) ; stack ops
    #(#x82 #x87 #x88)                                      ; SIZE EQUAL EQUALVERIFY
    #(#x8b #x8c #x8f #x90 #x91 #x92 #x93 #x94 #x95 #x9a #x9b #x9c #x9f #xa0 #xa3 #xa4 #xa5) ; arith
    #(#xa6 #xa7 #xa8 #xa9 #xaa)                            ; RIPEMD160 SHA1 SHA256 HASH160 HASH256
    #(#xac #xad #xae #xaf)                                 ; CHECKSIG(VERIFY) CHECKMULTISIG(VERIFY)
    #(#xb1 #xb2)))                                         ; CLTV CSV

(defun random-script (max-ops)
  (let ((wr (w:make-writer)))
    (dotimes (i (1+ (random max-ops)))
      (if (< (random 100) 35)
          ;; a small push
          (let ((n (random 6)))
            (w:w-u8 wr n) (dotimes (k n) (w:w-u8 wr (random 256))))
          ;; a random opcode from the pool
          (w:w-u8 wr (aref *opcode-pool* (random (length *opcode-pool*))))))
    (w:writer-bytes wr)))

(defun random-flags ()
  ;; Core's VerifyScript asserts WITNESS implies P2SH — respect that (an invalid
  ;; flag combo aborts the whole process, not just the call).
  (let ((fs (loop for f in *supported-flags* when (zerop (random 2)) collect f)))
    (when (and (member :witness fs) (not (member :p2sh fs))) (push :p2sh fs))
    fs))

(defstruct (fz (:conc-name fz-)) (agree 0) (valid 0) (diverge 0) (errs 0) (examples '()))

(defun fz-run (fz sig pk flags)
  (handler-case
      (multiple-value-bind (core ours ok) (diff-one sig pk flags)
        (cond (ok (incf (fz-agree fz)) (when core (incf (fz-valid fz))))
              (t (incf (fz-diverge fz))
                 (when (< (length (fz-examples fz)) 25)
                   (push (list (w:bytes->hex sig) (w:bytes->hex pk) flags core ours) (fz-examples fz))))))
    (error () (incf (fz-errs fz)))))

(defun fz-report (fz label rounds)
  (format t "~%==== core-diff ~a: ~d rounds ====~%" label rounds)
  (format t "  agree ~d (of which both-valid ~d)~%  DIVERGE ~d~%  harness-err ~d~%"
          (fz-agree fz) (fz-valid fz) (fz-diverge fz) (fz-errs fz))
  (when (fz-examples fz)
    (format t "~%  divergences (Core vs ours) — reproducers:~%")
    (dolist (e (reverse (fz-examples fz)))
      (destructuring-bind (sig pk flags core ours) e
        (format t "    flags ~a  core=~a ours=~a~%      sig=~a~%      pk =~a~%" flags core ours sig pk))))
  (values (fz-agree fz) (fz-diverge fz)))

(defun fuzz (&optional (rounds 100000) (max-ops 8))
  "Random (scriptSig, scriptPubKey, flags) triples through Core and us."
  (let ((fz (make-fz)))
    (dotimes (i rounds)
      (fz-run fz (random-script (max 1 (floor max-ops 2))) (random-script max-ops) (random-flags))
      (when (and (plusp i) (zerop (mod i 20000)))
        (format t "~&[fuzz] ~d/~d  agree ~d  diverge ~d~%" i rounds (fz-agree fz) (fz-diverge fz))
        (force-output)))
    (fz-report fz "random fuzz" rounds)))

;;; ----------------------------------------------------------------------------
;;; Mutation fuzz — start from Core's real script_tests and perturb them, so the
;;; scripts actually execute deeply (far more likely to surface edge divergences)
;;; ----------------------------------------------------------------------------

(defparameter *corpus* nil)

(defun load-corpus (&optional (path "inspect/vectors/script_tests_hex.json"))
  (setf *corpus*
        (let ((cases (with-open-file (f path) (com.inuoe.jzon:parse f))))
          (coerce (loop for c across cases
                        collect (cons (w:hex->bytes (aref c 0)) (w:hex->bytes (aref c 1))))
                  'vector)))
  (length *corpus*))

(defun mutate (bytes)
  (let ((b (copy-seq bytes)) (n (length bytes)))
    (when (plusp n)
      (case (random 4)
        (0 (setf (aref b (random n)) (random 256)))                  ; flip a byte
        (1 (setf b (concatenate '(simple-array (unsigned-byte 8) (*))  ; insert a byte
                                (subseq b 0 (random (1+ n)))
                                (vector (random 256)) (subseq b (random (1+ n))))))
        (2 (when (> n 1) (setf b (concatenate '(simple-array (unsigned-byte 8) (*))  ; delete
                                              (subseq b 0 (random n)) (subseq b (1+ (random n)))))))
        (3 (setf (aref b (random n))
                 (aref *opcode-pool* (random (length *opcode-pool*)))))))           ; swap in an opcode
    b))

(defun fuzz-mutate (&optional (rounds 200000))
  "Mutate random script_tests cases and diff Core vs ours."
  (unless *corpus* (load-corpus))
  (let ((fz (make-fz)))
    (dotimes (i rounds)
      (let* ((base (aref *corpus* (random (length *corpus*))))
             (sig (car base)) (pk (cdr base)))
        (dotimes (k (1+ (random 3))) (setf sig (mutate sig) pk (mutate pk)))
        (fz-run fz sig pk (random-flags)))
      (when (and (plusp i) (zerop (mod i 20000)))
        (format t "~&[mutate] ~d/~d  agree ~d  both-valid ~d  diverge ~d~%"
                i rounds (fz-agree fz) (fz-valid fz) (fz-diverge fz))
        (force-output)))
    (fz-report fz "mutation fuzz" rounds)))

(defun ci (&optional (rounds 50000))
  "Random + mutation fuzz vs Core's compiled verifier; exit nonzero on any
   divergence.  For inspect/regression.sh."
  (let ((d 0))
    (multiple-value-bind (a dv) (fuzz rounds) (declare (ignore a)) (incf d dv))
    (multiple-value-bind (a dv) (fuzz-mutate rounds) (declare (ignore a)) (incf d dv))
    (format t "~&CORE-DIFF: ~a (~d divergences over ~d random + ~d mutation rounds)~%"
            (if (zerop d) "PASS" "FAIL") d rounds rounds)
    (sb-ext:exit :code (if (zerop d) 0 1))))

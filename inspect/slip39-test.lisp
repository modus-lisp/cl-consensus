;;;; inspect/slip39-test.lisp
;;;;
;;;; Gate for Shamir secret sharing + SLIP-0039 Shamir backup:
;;;;   * GF(2^8) core: split/combine round-trips, digest guard, textbook t-of-n.
;;;;   * SLIP-0039: all 45 official test vectors (decode + invalid-rejection + extendable),
;;;;     encode->decode round-trips across sizes/thresholds/ext, wrong-passphrase divergence.
;;;;   * wallet bridge: BIP39 seed phrase -> shares -> phrase -> same wallet address.
;;;;
;;;;   sbcl --non-interactive --load inspect/slip39-test.lisp --eval '(slip39-test:run)'
(require :asdf)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(let* ((here (or *load-truename* *default-pathname-defaults*))
       (root (make-pathname :directory (butlast (pathname-directory here))
                            :name nil :type nil :defaults here)))
  (pushnew (truename root) asdf:*central-registry* :test #'equal))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :slip39-test
  (:use :cl)
  (:local-nicknames (:sh :cl-consensus.shamir) (:sl :cl-consensus.slip39)
                    (:b39 :cl-consensus.bip39) (:wal :cl-consensus.wallet)
                    (:w :cl-consensus.wire))
  (:export #:run))
(in-package :slip39-test)

;; the 45 official vectors, vendored beside this file
(load (merge-pathnames "slip39-vectors.lisp"
                       (or *load-truename* *default-pathname-defaults*)))

(defparameter *ok* t)
(defun okk (name) (format t "  ok   ~a~%" name))
(defun bad (fmt &rest args) (setf *ok* nil) (format t "  *** FAIL ~a~%" (apply #'format nil fmt args)))
(defun check (name got want) (if (equalp got want) (okk name) (bad "~a: ~a /= ~a" name got want)))
(defun checkt (name c) (if c (okk name) (bad name)))
(defun hx (v) (string-downcase (format nil "~{~2,'0x~}" (coerce v 'list))))

(defun test-core ()
  (let* ((secret (sh::as-u8vec (loop for i below 16 collect (mod (* i 37) 256))))
         (sh (sh:split-secret 3 5 secret)))
    (check "core 3of5 [0,2,4]" (sh:recover-secret 3 (list (nth 0 sh) (nth 2 sh) (nth 4 sh))) secret)
    (check "core 3of5 [1,3,4]" (sh:recover-secret 3 (list (nth 1 sh) (nth 3 sh) (nth 4 sh))) secret)
    (checkt "core digest guard rejects 2"
            (handler-case (progn (sh:recover-secret 3 (list (nth 0 sh) (nth 1 sh))) nil)
              (sh:shamir-error () t))))
  (let* ((s (sh::as-u8vec #(222 173 190 239 0 1 2 3)))
         (sh (sh:shamir-split s 3 5)))
    (check "textbook 3of5" (sh:shamir-combine (list (nth 0 sh) (nth 2 sh) (nth 4 sh))) s)))

(defun test-vectors ()
  (let ((pass 0) (fail 0))
    (dolist (vec *vectors*)
      (destructuring-bind (desc mns expected) vec
        (let ((valid (plusp (length expected))))
          (handler-case
              (let ((got (hx (sl:combine-mnemonics mns :passphrase "TREZOR"))))
                (cond ((not valid) (incf fail) (bad "~a: expected rejection, got ~a" desc got))
                      ((string= got expected) (incf pass))
                      (t (incf fail) (bad "~a: ~a /= ~a" desc got expected))))
            (error (e)
              (if valid (progn (incf fail) (bad "~a: unexpected error ~a" desc e))
                  (incf pass)))))))
    (checkt (format nil "45 official vectors (~d/~d)" pass (+ pass fail)) (zerop fail))))

(defun test-roundtrips ()
  (dolist (nbytes '(16 32))
    (dolist (ext '(0 1))
      (let ((secret (sh:random-bytes nbytes)))
        (check (format nil "rt 1of1 n=~d ext=~d" nbytes ext)
               (sl:combine-mnemonics (first (sl:generate-mnemonics 1 '((1 . 1)) secret :passphrase "p" :ext ext))
                                     :passphrase "p")
               secret)
        (let ((g (first (sl:generate-mnemonics 1 '((2 . 3)) secret :passphrase "p" :ext ext))))
          (check (format nil "rt 2of3 n=~d ext=~d" nbytes ext)
                 (sl:combine-mnemonics (list (nth 0 g) (nth 2 g)) :passphrase "p") secret))
        (let* ((gs (sl:generate-mnemonics 2 '((2 . 3) (1 . 1) (3 . 5)) secret :passphrase "p" :ext ext)))
          (check (format nil "rt 2groups n=~d ext=~d" nbytes ext)
                 (sl:combine-mnemonics (append (subseq (first gs) 0 2) (subseq (second gs) 0 1)) :passphrase "p")
                 secret)
          (checkt (format nil "rt wrong-passphrase differs n=~d ext=~d" nbytes ext)
                  (not (equalp secret (sl:combine-mnemonics
                                       (append (subseq (first gs) 0 2) (subseq (second gs) 0 1))
                                       :passphrase "WRONG")))))))))

(defun test-wallet-bridge ()
  (let* ((entropy (sh:random-bytes 16))
         (mns (sl:wallet-backup entropy 1 '((2 . 3)))))
    (multiple-value-bind (w bip39m ent) (sl:wallet-from-mnemonics (subseq (first mns) 0 2))
      (check "bridge entropy round-trips" (hx ent) (hx entropy))
      (check "bridge -> same wallet address"
             (wal:wallet-receive-address w)
             (wal:wallet-receive-address (b39:make-wallet-from-mnemonic bip39m :type :p2wpkh))))))

(defun run ()
  (setf *ok* t)
  (format t "~&== SLIP-0039 / Shamir gate ==~%")
  (test-core)
  (test-vectors)
  (test-roundtrips)
  (test-wallet-bridge)
  (format t "~a~%" (if *ok* "ALL OK" "FAILURES ABOVE"))
  *ok*)

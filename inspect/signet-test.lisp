;;;; inspect/signet-test.lisp
;;;;
;;;; Gate — BIP325 signet block signatures.
;;;;
;;;; Signet's proof-of-work is trivial by design: anyone can grind a valid signet
;;;; header in milliseconds.  What actually makes a signet block valid is the
;;;; signature in its coinbase, so this gate is the whole security argument for
;;;; the network, and the NEGATIVE cases matter more than the positive one.  A
;;;; validator that accepts blocks under the wrong challenge — or accepts an
;;;; unsigned block — is not validating signet at all.
;;;;
;;;; Runs offline against blocks captured from the private signet devnet at
;;;; /mnt/lisp/signet (see vectors/signet-blocks.txt); no node required.
;;;;
;;;;   sbcl --load inspect/signet-test.lisp --eval '(signet-test:run)'
(require :asdf)
;; Sibling repos, found relative to this file so the workspace can live anywhere.
(asdf:initialize-source-registry
 (let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
   `(:source-registry (:tree ,(merge-pathnames "../../" here)) :inherit-configuration)))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage #:signet-test
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:blk #:cl-consensus.block)
                    (#:tx #:cl-consensus.tx) (#:sig #:cl-consensus.signet))
  (:export #:run))

(in-package #:signet-test)

(defparameter *vectors*
  (merge-pathnames "vectors/signet-blocks.txt"
                   (make-pathname :name nil :type nil :defaults *load-truename*)))

(defvar *checks* 0)
(defvar *fails* 0)

(defun ok (label result)
  (incf *checks*)
  (if result
      (format t "~&  ok    ~a~%" label)
      (progn (incf *fails*) (format t "~&  FAIL  ~a~%" label)))
  result)

(defun load-vectors ()
  "(challenge-hex . list-of-block-hex) from the captured devnet blocks."
  (with-open-file (f *vectors* :if-does-not-exist nil)
    (unless f (return-from load-vectors nil))
    (let ((challenge nil) (blocks '()))
      (loop for line = (read-line f nil) while line do
        (let ((l (string-trim '(#\Space #\Tab #\Return) line)))
          (cond ((zerop (length l)))
                ((char= (char l 0) #\#)
                 (let ((p (search "challenge=" l)))
                   (when p (setf challenge (subseq l (+ p 10))))))
                (t (push l blocks)))))
      (cons challenge (nreverse blocks)))))

(defun test-magic-derivation ()
  (format t "~&~%signet magic is derived from the challenge~%")
  ;; The public signet's magic is a fixed, published value; deriving it from the
  ;; published challenge is an end-to-end check of the derivation (including the
  ;; CompactSize length prefix, which is easy to omit and yields a plausible
  ;; wrong answer).
  (let ((m (w:derive-signet-magic w:*default-signet-challenge*)))
    (ok "public signet magic (wire bytes 0a 03 cf 40)" (= m #x40CF030A)))
  ;; Two different challenges must not collide — that is what keeps a private
  ;; signet from ever handshaking with the public one.
  (ok "a custom challenge derives a different magic"
      (/= (w:derive-signet-magic w:*default-signet-challenge*)
          (w:derive-signet-magic (w:hex->bytes "0014000102030405060708090a0b0c0d0e0f10111213")))))

(defun test-params ()
  (format t "~&~%signet network parameters~%")
  (let ((saved w:*network*))
    (unwind-protect
         (progn
           (w:select-network :signet)
           (ok "genesis hash"
               (string= (w:net-genesis-hash w:*network*)
                        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"))
           (ok "pow limit is signet's minimum (1e0377ae)"
               (= (w:net-pow-limit-bits w:*network*) #x1e0377ae))
           (ok "difficulty retargets (unlike regtest)" (not (w:net-no-retarget w:*network*)))
           (ok "signet-p is true" (w:signet-p))
           ;; The genesis header must actually hash to the genesis hash.
           (ok "genesis header hashes to genesis hash"
               (string= (w:hash->hex (w:hash256 (w:hex->bytes (w:net-genesis-hex w:*network*))))
                        (w:net-genesis-hash w:*network*)))
           (w:select-network :mainnet)
           (ok "signet-p is false off signet" (not (w:signet-p))))
      (setf w:*network* saved))))

(defun test-block-signatures ()
  (let* ((v (load-vectors))
         (challenge-hex (car v))
         (blocks (cdr v)))
    (format t "~&~%BIP325 block signatures (~d captured devnet block~:p)~%" (length blocks))
    (unless (and challenge-hex blocks)
      (format t "  SKIP  no vectors at ~a~%" *vectors*)
      (return-from test-block-signatures))
    (let ((challenge (w:hex->bytes challenge-hex))
          (parsed (mapcar (lambda (h) (blk:parse-block (w:hex->bytes h))) blocks)))
      ;; Positive: every real block validates under its own challenge.
      (let ((good (count-if (lambda (b) (sig:signet-block-signature-p b challenge)) parsed)))
        (ok (format nil "all ~d blocks valid under their own challenge" (length parsed))
            (= good (length parsed))))
      ;; Negative 1: the same blocks under the PUBLIC signet's challenge.  This is
      ;; the check that proves we verify the signature rather than merely parse it.
      (let ((bad (count-if (lambda (b) (sig:signet-block-signature-p b w:*default-signet-challenge*))
                           parsed)))
        (ok "none valid under a different challenge" (zerop bad)))
      ;; Negative 2: strip the signature out of a block entirely.
      (let* ((b (first parsed))
             (cb (aref (blk:block-txs b) 0))
             (stripped
               (loop for out in (tx:tx-outputs cb)
                     collect (let ((s (tx:txout-script out)))
                               (if (and (>= (length s) 38)
                                        (equalp (subseq s 0 6) #(#x6a #x24 #xaa #x21 #xa9 #xed)))
                                   ;; keep only the witness commitment, drop the
                                   ;; appended signet solution push
                                   (tx:make-txout :value (tx:txout-value out)
                                                  :script (subseq s 0 38))
                                   out)))))
        (setf (tx:tx-outputs cb) stripped)
        (ok "a block with its signature removed is rejected"
            (not (sig:signet-block-signature-p b challenge)))))))

(defun run ()
  (setf *checks* 0 *fails* 0)
  (format t "~&=== signet (BIP325) ===~%")
  (test-magic-derivation)
  (test-params)
  (test-block-signatures)
  (format t "~&~%~d check~:p, ~d failure~:p~%" *checks* *fails*)
  (zerop *fails*))

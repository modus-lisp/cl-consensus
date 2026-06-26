;;;; inspect/wallet-store-test.lisp
;;;;
;;;; Gate for wallet persistence: build a wallet, fund a coin into it, save to disk, load it
;;;; back, and assert the restored wallet's balance, coin count, and receive-address(0) all
;;;; match the original.
;;;;
;;;;   sbcl --non-interactive --load inspect/wallet-store-test.lisp --eval '(wallet-store-test:run)'
(require :asdf)
;; Derive THIS worktree's repo root portably: the test file lives at <root>/inspect/, so the
;; root is the parent of its directory.  We build the wallet-store under test (whichever
;; worktree we're loaded from) rather than the canonical checked-in tree.
(let ((root (make-pathname :directory (butlast (pathname-directory *load-truename*))
                           :name nil :type nil)))
  (pushnew root asdf:*central-registry* :test #'equal))
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :wallet-store-test
  (:use :cl)
  (:local-nicknames (:w :cl-consensus.wire) (:wal :cl-consensus.wallet)
                    (:ws :cl-consensus.wallet-store) (:tx :cl-consensus.tx))
  (:export #:run))
(in-package :wallet-store-test)

(defparameter *op-true* (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51))
(defun hx (s) (w:hex->bytes s))

(defun mk-tx (prevs outs)
  "PREVS = list of (txid . idx); OUTS = list of (value . script)."
  (let ((txn (tx:make-tx :version 2
               :inputs (mapcar (lambda (p) (tx:make-txin :prev-hash (car p) :prev-index (cdr p)
                                                         :script #() :sequence #xffffffff)) prevs)
               :outputs (mapcar (lambda (o) (tx:make-txout :value (car o) :script (cdr o))) outs)
               :witnesses nil :locktime 0 :segwit-p nil)))
    (tx:finalize-tx txn) txn))

(defparameter *ok* t)
(defun check (name got want)
  (unless (equal got want)
    (setf *ok* nil) (format t "  *** FAIL ~a~%      got  ~a~%      want ~a~%" name got want)))

(defun run ()
  (setf *ok* t)
  (let* ((seed (hx "000102030405060708090a0b0c0d0e0f"))
         (wal (wal:make-wallet-from-seed seed :type :p2wpkh))
         (path "/tmp/wallet-store-test.wallet"))
    ;; fund receive[0] (mirror inspect/wallet-test.lisp)
    (let* ((spk0 (wal::waddr-script (aref (wal:wallet-receive wal) 0)))
           (funding (mk-tx (list (cons (hx "aa") 0))
                           (list (cons 250000 spk0) (cons 999 *op-true*)))))
      (wal:wallet-process-tx wal funding 100))
    (check "original balance" (wal:wallet-balance wal) 250000)
    (check "original coin count" (hash-table-count (wal:wallet-coins wal)) 1)
    ;; (1) PLAINTEXT save + load — back-compat
    (ws:save-wallet wal path :seed seed)
    (let ((loaded (ws:load-wallet path)))
      (check "loaded balance matches" (wal:wallet-balance loaded) (wal:wallet-balance wal))
      (check "loaded coin count matches"
             (hash-table-count (wal:wallet-coins loaded))
             (hash-table-count (wal:wallet-coins wal)))
      (check "loaded receive-address(0) matches"
             (wal:wallet-receive-address loaded 0) (wal:wallet-receive-address wal 0))
      (check "loaded type matches" (wal:wallet-type loaded) (wal:wallet-type wal)))
    ;; (2) ENCRYPTED save + load with the CORRECT passphrase round-trips
    (let ((epath "/tmp/wallet-store-test-enc.wallet")
          (pass  "correct horse battery staple"))
      (ws:save-wallet wal epath :seed seed :passphrase pass :kdf-iterations 100000)
      ;; sanity: the on-disk plaintext seed must be gone, encrypted-p flag present
      (let ((blob (with-open-file (in epath) (read in))))
        (check "encrypted file: no plaintext seed" (getf blob :seed) nil)
        (check "encrypted file: encrypted-p set" (and (getf blob :encrypted-p) t) t))
      (let ((loaded (ws:load-wallet epath :passphrase pass)))
        (check "enc loaded balance matches" (wal:wallet-balance loaded) (wal:wallet-balance wal))
        (check "enc loaded coin count matches"
               (hash-table-count (wal:wallet-coins loaded))
               (hash-table-count (wal:wallet-coins wal)))
        (check "enc loaded receive-address(0) matches"
               (wal:wallet-receive-address loaded 0) (wal:wallet-receive-address wal 0)))
      ;; (3) WRONG passphrase must signal an error (never a wrong wallet)
      (let ((raised (handler-case (progn (ws:load-wallet epath :passphrase "wrong passphrase") nil)
                      (error () t))))
        (check "wrong passphrase signals error" raised t))
      ;; missing passphrase on an encrypted wallet must also error
      (let ((raised (handler-case (progn (ws:load-wallet epath) nil)
                      (error () t))))
        (check "missing passphrase signals error" raised t))))
  (format t "~&wallet-store-test: ~a~%" (if *ok* "OK — save/load round-trips balance+coins+address" "FAILED"))
  (unless *ok* (sb-ext:exit :code 1))
  *ok*)

;;;; inspect/wallet-store-test.lisp
;;;;
;;;; Gate for wallet persistence: build a wallet, fund a coin into it, save to disk, load it
;;;; back, and assert the restored wallet's balance, coin count, and receive-address(0) all
;;;; match the original.
;;;;
;;;;   sbcl --non-interactive --load inspect/wallet-store-test.lisp --eval '(wallet-store-test:run)'
(require :asdf)
;; This worktree's repo root (NOT the canonical /home/claude/cl-consensus), so we build the
;; wallet-store under test rather than the checked-in tree.
(pushnew #p"/home/claude/cl-consensus-wallet-store/" asdf:*central-registry* :test #'equal)
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
    ;; save + load
    (ws:save-wallet wal path :seed seed)
    (let ((loaded (ws:load-wallet path)))
      (check "loaded balance matches" (wal:wallet-balance loaded) (wal:wallet-balance wal))
      (check "loaded coin count matches"
             (hash-table-count (wal:wallet-coins loaded))
             (hash-table-count (wal:wallet-coins wal)))
      (check "loaded receive-address(0) matches"
             (wal:wallet-receive-address loaded 0) (wal:wallet-receive-address wal 0))
      (check "loaded type matches" (wal:wallet-type loaded) (wal:wallet-type wal))))
  (format t "~&wallet-store-test: ~a~%" (if *ok* "OK — save/load round-trips balance+coins+address" "FAILED"))
  (unless *ok* (sb-ext:exit :code 1))
  *ok*)

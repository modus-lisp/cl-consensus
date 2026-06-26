;;;; inspect/rpc-wallet-test.lisp
;;;;
;;;; Gate for the wallet-backed JSON-RPC methods (src/rpc-wallet.lisp): set a
;;;; wallet from a known seed, fund it with an in-RAM UTXO coin paying its
;;;; receive[0] script, then dispatch getbalance / getnewaddress / listunspent /
;;;; sendtoaddress through cl-consensus.node:rpc-call (no HTTP server needed) and
;;;; assert the results — including that sendtoaddress lands a tx in the node's
;;;; mempool.  Fully offline.
;;;;
;;;;   sbcl --non-interactive --load inspect/rpc-wallet-test.lisp --eval '(rpc-wallet-test:run)'
(require :asdf)
;; THIS worktree's repo root (NOT the canonical /home/claude/cl-consensus), so we
;; load the code under test, plus the sibling deps.
(pushnew (truename #p"./") asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :rpc-wallet-test
  (:use :cl)
  (:local-nicknames (:node :cl-consensus.node) (:rw :cl-consensus.rpc-wallet)
                    (:wal :cl-consensus.wallet) (:u :cl-consensus.utxo)
                    (:tx :cl-consensus.tx) (:w :cl-consensus.wire))
  (:export #:run))
(in-package :rpc-wallet-test)

(defparameter *ok* t)
(defun check (name cond)
  (if cond (format t "  ok: ~a~%" name)
      (progn (setf *ok* nil) (format t "  *** FAIL: ~a~%" name))))

(defun seed (n)
  "A deterministic 64-byte (512-bit) seed."
  (let ((s (make-array 64 :element-type '(unsigned-byte 8))))
    (dotimes (i 64 s) (setf (aref s i) (logand (+ n (* 7 i)) 255)))))

(defun fake-hash (n)
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (logand n 255) (aref h 1) (logand (ash n -8) 255)) h))

(defun call (method &rest params)
  "Dispatch through the node and surface any RPC error as a Lisp error."
  (multiple-value-bind (result err) (node:rpc-call method (coerce params 'vector))
    (when err (error "rpc ~a error: ~a" method (gethash "message" err)))
    result))

(defun run ()
  (setf *ok* t)
  ;; fresh node mempool so the count delta is unambiguous
  (setf node:*mempool* (cl-consensus.mempool:make-mempool))
  ;; reset getnewaddress's running index for determinism
  (setf (symbol-value (find-symbol "*RECEIVE-INDEX*" :cl-consensus.rpc-wallet)) 0)

  ;; --- wallet from a known seed (default P2WPKH / BIP84) ---
  (let* ((wallet (wal:make-wallet-from-seed (seed 1)))
         (recv0-script (wal:waddr-script (aref (wal:wallet-receive wallet) 0))))
    (setf rw:*wallet* wallet)

    ;; --- an in-RAM UTXO set with one coin the wallet owns (pays receive[0]) ---
    (let ((set (u:make-utxo-set))
          (txid (fake-hash 42))
          (value 10000000))               ; 0.1 BTC
      (u:utxo-add set txid 0
                  (u:make-coin :value value :height 1 :coinbase-p nil :script recv0-script))
      (setf node:*utxo* set)
      ;; make the wallet see that coin (forward-track it as a confirmed tx output)
      (let ((found (wal:wallet-rescan-utxo wallet set)))
        (check "wallet rescan found the coin" (= found 1)))

      ;; ===================== RPC surface =====================

      ;; getbalance > 0
      (let ((bal (call "getbalance")))
        (check "getbalance > 0" (and (numberp bal) (> bal 0)))
        (check "getbalance == 0.1 BTC" (= bal (/ value 1d8))))

      ;; getnewaddress returns a fresh bc1... string, advancing the index
      (let ((a0 (call "getnewaddress"))
            (a1 (call "getnewaddress")))
        (check "getnewaddress[0] is bc1..." (and (stringp a0) (>= (length a0) 4)
                                                 (string= (subseq a0 0 3) "bc1")))
        (check "getnewaddress[1] is bc1..." (and (stringp a1) (string= (subseq a1 0 3) "bc1")))
        (check "getnewaddress advances (a0 /= a1)" (string/= a0 a1)))

      ;; listunspent contains the coin
      (let ((unspent (call "listunspent")))
        (check "listunspent is an array of 1" (and (vectorp unspent) (= (length unspent) 1)))
        (when (and (vectorp unspent) (plusp (length unspent)))
          (let ((row (aref unspent 0)))
            (check "listunspent row txid matches" (string= (gethash "txid" row) (w:hash->hex txid)))
            (check "listunspent row vout 0" (= (gethash "vout" row) 0))
            (check "listunspent row amount 0.1" (= (gethash "amount" row) (/ value 1d8))))))

      ;; getwalletinfo
      (let ((info (call "getwalletinfo")))
        (check "getwalletinfo coincount 1" (= (gethash "coincount" info) 1))
        (check "getwalletinfo balance 0.1" (= (gethash "balance" info) (/ value 1d8))))

      ;; sendtoaddress: spend a sub-amount to a valid address; expect a txid and a
      ;; new mempool entry.  Send back to one of the wallet's own receive addresses
      ;; (a valid bech32 destination).
      (let ((dest (wal:wallet-receive-address wallet 5))
            (before (cl-consensus.mempool:mempool-size node:*mempool*)))
        (let ((txid-hex (call "sendtoaddress" dest 0.01d0)))
          (check "sendtoaddress returns a 64-hex txid"
                 (and (stringp txid-hex) (= (length txid-hex) 64)))
          (check "node mempool gained a tx"
                 (= (cl-consensus.mempool:mempool-size node:*mempool*) (1+ before)))
          (check "the new tx is the returned txid"
                 (cl-consensus.mempool:mempool-get node:*mempool* txid-hex))))))

  (format t "~&rpc-wallet-test: ~a~%"
          (if *ok* "OK — getbalance/getnewaddress/listunspent/sendtoaddress/getwalletinfo"
              "FAILED"))
  (unless *ok* (sb-ext:exit :code 1))
  *ok*)

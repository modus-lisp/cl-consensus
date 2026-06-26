;;;; src/rpc-wallet.lisp
;;;;
;;;; Wallet-backed JSON-RPC methods.  This file loads AFTER both "node" and
;;;; "wallet" so it can cleanly reference both packages (node is loaded before
;;;; wallet, so these methods cannot live in node.lisp without a load-order
;;;; problem).  It registers a handful of bitcoind-style wallet RPCs into the
;;;; node's dispatch table (cl-consensus.node::*methods*):
;;;;
;;;;   getnewaddress   — a fresh receive address (advances the receive index)
;;;;   getbalance      — wallet balance in BTC
;;;;   listunspent     — array of wallet coins {txid, vout, amount, ...}
;;;;   sendtoaddress   — build + sign a spend, accept it into the node mempool,
;;;;                     return the txid hex (wallet -> mempool; the consolidated
;;;;                     node then relays it)
;;;;   getwalletinfo   — balance + coin/address counts
;;;;
;;;; The methods register at load time (a top-level form below) and are also
;;;; re-registered whenever the node calls register-methods (we hook it), so a
;;;; hot reload! keeps them live.

(defpackage #:cl-consensus.rpc-wallet
  (:use #:cl)
  (:local-nicknames (#:node #:cl-consensus.node) (#:w #:cl-consensus.wire)
                    (#:tx #:cl-consensus.tx) (#:c #:cl-consensus.chain)
                    (#:mp #:cl-consensus.mempool) (#:wal #:cl-consensus.wallet))
  (:export #:*wallet* #:register-wallet-methods))

(in-package #:cl-consensus.rpc-wallet)

(defvar *wallet* nil "The node's HD wallet, if one is attached.")

;; mirror the node's tiny JSON-object helper so renders match the other methods
(defun obj (&rest kv) (apply #'node::obj kv))

(defun ensure-wallet ()
  (or *wallet* (error "no wallet loaded")))

(defvar *receive-index* 0 "Next receive index getnewaddress will return.")

;;; ----------------------------------------------------------------------------
;;; Methods
;;; ----------------------------------------------------------------------------

(defun m-getnewaddress (&rest _)
  "A fresh receive address; advances the receive index each call."
  (declare (ignore _))
  (let* ((wallet (ensure-wallet))
         (addr (wal:wallet-receive-address wallet *receive-index*)))
    (incf *receive-index*)
    addr))

(defun m-getbalance (&rest _)
  "Wallet balance in BTC."
  (declare (ignore _))
  (/ (wal:wallet-balance (ensure-wallet)) 1d8))

(defun m-listunspent (&rest _)
  "Array of the wallet's unspent coins."
  (declare (ignore _))
  (let ((wallet (ensure-wallet)) (out '()))
    (maphash (lambda (k coin)
               (declare (ignore k))
               (push (obj "txid" (w:hash->hex (wal:wcoin-txid coin))
                          "vout" (wal:wcoin-vout coin)
                          "amount" (/ (wal:wcoin-value coin) 1d8)
                          "satoshis" (wal:wcoin-value coin)
                          "scriptPubKey" (w:bytes->hex (wal:wcoin-script coin))
                          "address" (wal:waddr-address (wal:wcoin-waddr coin)))
                     out))
             (wal:wallet-coins wallet))
    (coerce (nreverse out) 'vector)))

(defun m-sendtoaddress (address amount &rest _)
  "Build a signed spend of AMOUNT (BTC) to ADDRESS from the wallet, accept it into
   the node mempool, and return the txid hex.  This is wallet -> mempool; the
   consolidated node then relays the tx to peers."
  (declare (ignore _))
  (let* ((wallet (ensure-wallet))
         (sats (round (* amount 1d8)))
         (txn (wal:create-tx wallet (list (cons address sats)))))
    (unless node:*utxo* (error "no UTXO set loaded (cannot accept spend)"))
    (let* ((tip (c:tip))
           (height (if tip (1+ (c:tip-height)) most-positive-fixnum))
           (mtp (if tip (c:median-time-past tip) 0)))
      (handler-case
          (progn
            (mp:accept-tx txn node:*utxo* node:*mempool* :height height :mtp mtp)
            (tx:txid-hex txn))
        (mp:rejected (e) (error "~a" (mp:rejected-reason e)))))))

(defun m-getwalletinfo (&rest _)
  "Balance plus coin / address counts."
  (declare (ignore _))
  (let ((wallet (ensure-wallet)))
    (obj "balance" (/ (wal:wallet-balance wallet) 1d8)
         "txcount" 'null
         "coincount" (hash-table-count (wal:wallet-coins wallet))
         "receive_addresses" (length (wal:wallet-addresses wallet 0))
         "change_addresses" (length (wal:wallet-addresses wallet 1))
         "next_receive_index" *receive-index*)))

;;; ----------------------------------------------------------------------------
;;; Registration — splice these into the node's dispatch table
;;; ----------------------------------------------------------------------------

(defun register-wallet-methods ()
  "Add the wallet methods to the node's *methods* table (idempotent)."
  (dolist (m '(("getnewaddress" m-getnewaddress)
               ("getbalance"    m-getbalance)
               ("listunspent"   m-listunspent)
               ("sendtoaddress" m-sendtoaddress)
               ("getwalletinfo" m-getwalletinfo)))
    (setf (gethash (first m) (symbol-value 'node::*methods*))
          (symbol-function (find-symbol (string (second m)) '#:cl-consensus.rpc-wallet)))))

;; The node's register-methods clrhash's its table, so wrap it to re-add ours
;; afterwards.  This keeps the wallet methods live across reload! and across an
;; explicit register-methods call (e.g. on node start).
(let ((orig (symbol-function 'node::register-methods)))
  (unless (get 'node::register-methods 'rpc-wallet-hooked)
    (setf (symbol-function 'node::register-methods)
          (lambda (&rest args)
            (apply orig args)
            (register-wallet-methods)))
    (setf (get 'node::register-methods 'rpc-wallet-hooked) t)))

;; Register now (the node may already have populated *methods* at its own load).
(register-wallet-methods)

;;;; src/wallet.lisp
;;;;
;;;; A BIP32/44/84 HD wallet on top of the node: derive addresses, watch the chain for
;;;; coins paying us (track as blocks connect), and (Phase 3) build + sign + broadcast
;;;; spends through the mempool/relay path.  Spendable address types: P2WPKH (BIP84,
;;;; default) and P2PKH (BIP44) — ECDSA + legacy/BIP143 sighash.  P2TR addresses can be
;;;; generated for receiving.

(defpackage #:cl-consensus.wallet
  (:use #:cl)
  (:nicknames #:btc-wallet)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script) (#:u #:cl-consensus.utxo)
                    (#:b32 #:cl-consensus.bip32) (#:enc #:cl-consensus.encoding)
                    (#:secp #:secp256k1-fast))
  (:export
   #:wallet #:wallet-p #:make-wallet-from-seed #:wallet-type #:wallet-balance
   #:wallet-coins #:wallet-receive #:wallet-change
   #:wallet-receive-address #:wallet-change-address #:wallet-addresses
   #:wallet-process-tx #:wallet-process-block #:wallet-rescan-utxo
   #:waddr #:waddr-address #:waddr-script #:waddr-index #:waddr-chain
   #:wcoin #:wcoin-value #:wcoin-txid #:wcoin-vout #:wcoin-script
   #:script-for #:purpose-for))

(in-package #:cl-consensus.wallet)

;;; ----------------------------------------------------------------------------
;;; scriptPubKey constructors
;;; ----------------------------------------------------------------------------

(defun p2pkh-script (h160)
  (concatenate '(vector (unsigned-byte 8)) #(#x76 #xa9 #x14) h160 #(#x88 #xac)))
(defun p2wpkh-script (h160)
  (concatenate '(vector (unsigned-byte 8)) #(#x00 #x14) h160))
(defun p2tr-script (xonly)
  (concatenate '(vector (unsigned-byte 8)) #(#x51 #x20) xonly))

(defun purpose-for (type) (ecase type (:p2pkh 44) (:p2wpkh 84) (:p2tr 86)))

(defun script-for (type pubkey)
  "scriptPubKey for a compressed PUBKEY under address TYPE."
  (ecase type
    (:p2pkh  (p2pkh-script (w:hash160 pubkey)))
    (:p2wpkh (p2wpkh-script (w:hash160 pubkey)))
    (:p2tr   (p2tr-script (subseq pubkey 1)))))   ; x-only = compressed sans prefix

(defun address-for (type pubkey)
  (ecase type
    (:p2pkh  (enc:encode-p2pkh (w:hash160 pubkey)))
    (:p2wpkh (enc:encode-p2wpkh (w:hash160 pubkey)))
    (:p2tr   (enc:encode-p2tr (subseq pubkey 1)))))

;;; ----------------------------------------------------------------------------
;;; Wallet model
;;; ----------------------------------------------------------------------------

(defstruct (waddr (:constructor %make-waddr))
  index chain xkey pubkey script address)

(defstruct (wcoin (:constructor %make-wcoin))
  txid vout value script waddr height)

(defstruct (wallet (:constructor %make-wallet) (:predicate wallet-p))
  master account-xkey
  (type :p2wpkh) (gap-limit 20)
  (receive (make-array 0 :adjustable t :fill-pointer 0))   ; chain 0
  (change  (make-array 0 :adjustable t :fill-pointer 0))   ; chain 1
  (coins (make-hash-table :test 'equal))            ; "txidhex:vout" -> wcoin
  (script-index (make-hash-table :test 'equal)))    ; scriptPubKey hex -> waddr

(defun coin-key (txid vout) (format nil "~a:~d" (w:hash->hex txid) vout))

(defun derive-waddr (wallet chain index)
  "Derive the WADDR at (CHAIN, INDEX) below the account key and register its script."
  (let* ((child (b32:ckd-priv (b32:ckd-priv (wallet-account-xkey wallet) chain) index))
         (pubkey (b32:xkey-pubkey child))
         (script (script-for (wallet-type wallet) pubkey))
         (wa (%make-waddr :index index :chain chain :xkey child :pubkey pubkey
                          :script script :address (address-for (wallet-type wallet) pubkey))))
    (setf (gethash (w:bytes->hex script) (wallet-script-index wallet)) wa)
    wa))

(defun ensure-addresses (wallet chain upto)
  "Make sure the CHAIN (0 receive / 1 change) has at least UPTO+1 derived addresses."
  (let ((vec (if (zerop chain) (wallet-receive wallet) (wallet-change wallet))))
    (loop while (<= (fill-pointer vec) upto)
          do (vector-push-extend (derive-waddr wallet chain (fill-pointer vec)) vec))
    vec))

(defun make-wallet-from-seed (seed &key (type :p2wpkh) (account 0) (gap-limit 20))
  "Build an HD wallet from a binary SEED (e.g. a BIP39 512-bit seed).  Derives the
   account key m/PURPOSE'/0'/ACCOUNT' and the first GAP-LIMIT receive + change
   addresses."
  (let* ((master (b32:master-from-seed seed))
         (path (format nil "m/~d'/0'/~d'" (purpose-for type) account))
         (wallet (%make-wallet :master master :account-xkey (b32:derive-path master path)
                               :type type :gap-limit gap-limit)))
    (ensure-addresses wallet 0 (1- gap-limit))
    (ensure-addresses wallet 1 (1- gap-limit))
    wallet))

(defun wallet-receive-address (wallet &optional (index 0))
  (waddr-address (aref (ensure-addresses wallet 0 index) index)))
(defun wallet-change-address (wallet &optional (index 0))
  (waddr-address (aref (ensure-addresses wallet 1 index) index)))
(defun wallet-addresses (wallet &optional (chain 0))
  (map 'list #'waddr-address (if (zerop chain) (wallet-receive wallet) (wallet-change wallet))))

;;; ----------------------------------------------------------------------------
;;; Watching the chain
;;; ----------------------------------------------------------------------------

(defun %maybe-extend (wallet waddr)
  "When a freshly-used address is within the gap window of the end of its chain, derive
   more so we keep a full GAP-LIMIT lookahead past the last used index."
  (let* ((chain (waddr-chain waddr))
         (vec (if (zerop chain) (wallet-receive wallet) (wallet-change wallet))))
    (when (>= (waddr-index waddr) (- (fill-pointer vec) (wallet-gap-limit wallet)))
      (ensure-addresses wallet chain (+ (waddr-index waddr) (wallet-gap-limit wallet))))))

(defun wallet-process-tx (wallet txn height)
  "Update the wallet from one confirmed TXN: drop coins it spends, add outputs paying
   us.  Returns the number of coins gained."
  (let ((txid (tx:tx-txid txn)) (gained 0))
    (dolist (in (tx:tx-inputs txn))
      (remhash (coin-key (tx:txin-prev-hash in) (tx:txin-prev-index in)) (wallet-coins wallet)))
    (loop for out in (tx:tx-outputs txn) for vout from 0 do
      (let ((wa (gethash (w:bytes->hex (tx:txout-script out)) (wallet-script-index wallet))))
        (when wa
          (setf (gethash (coin-key txid vout) (wallet-coins wallet))
                (%make-wcoin :txid txid :vout vout :value (tx:txout-value out)
                             :script (tx:txout-script out) :waddr wa :height height))
          (%maybe-extend wallet wa)
          (incf gained))))
    gained))

(defun wallet-process-block (wallet block height)
  "Apply every tx in BLOCK (a block* or a sequence of txs) to the wallet."
  (let ((txs (if (typep block 'sequence) block
                 (funcall (find-symbol "BLOCK-TXS" '#:cl-consensus.block) block))))
    (map nil (lambda (txn) (wallet-process-tx wallet txn height)) txs)))

(defun wallet-balance (wallet)
  "Total value (sat) of unspent wallet coins."
  (let ((sum 0)) (maphash (lambda (k c) (declare (ignore k)) (incf sum (wcoin-value c)))
                          (wallet-coins wallet)) sum))

(defun wallet-rescan-utxo (wallet utxo)
  "Scan an in-RAM UTXO-SET for coins paying our addresses (for recovering an existing
   wallet).  O(set) — for the live disk-backed set, prefer forward tracking via
   wallet-process-block.  Returns the count found."
  (let ((found 0)
        (map (funcall (find-symbol "UTXO-SET-MAP" '#:cl-consensus.utxo) utxo)))
    (maphash
     (lambda (key coin)
       (when (and (consp key) (not (eq coin :spent)))
         (let ((wa (gethash (w:bytes->hex (u:coin-script coin)) (wallet-script-index wallet))))
           (when wa
             (setf (gethash (format nil "~a:~d" (w:hash->hex (car key)) (cdr key))
                            (wallet-coins wallet))
                   (%make-wcoin :txid (car key) :vout (cdr key) :value (u:coin-value coin)
                                :script (u:coin-script coin) :waddr wa
                                :height (u:coin-height coin)))
             (incf found)))))
     map)
    found))

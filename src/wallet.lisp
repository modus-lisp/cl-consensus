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
                    (#:secp #:secp256k1-fast) (#:sch #:secp256k1-fast.schnorr))
  (:export
   #:wallet #:wallet-p #:make-wallet-from-seed #:wallet-type #:wallet-balance
   #:wallet-coins #:wallet-receive #:wallet-change
   #:wallet-receive-address #:wallet-change-address #:wallet-addresses
   #:wallet-process-tx #:wallet-process-block #:wallet-rescan-utxo
   #:waddr #:waddr-address #:waddr-script #:waddr-index #:waddr-chain
   #:waddr-xkey #:waddr-pubkey
   #:wcoin #:wcoin-value #:wcoin-txid #:wcoin-vout #:wcoin-script #:wcoin-waddr
   #:script-for #:purpose-for #:address->script #:create-tx #:sign-input
   #:taproot-output-key #:taproot-tweak))

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

(defun taproot-tweak (internal-xonly)
  "BIP341 key-path-only output integer tweak t = tagged_hash(\"TapTweak\", P) mod n."
  (mod (secp:bytes-to-int (sch:tagged-hash "TapTweak" internal-xonly)) secp:*secp256k1-n*))

(defun taproot-output-key (internal-xonly)
  "The 32-byte BIP341 output key Q = lift_x(P) + t*G (key-path only, empty merkle root)."
  (let* ((p-even (sch:lift-x (secp:bytes-to-int internal-xonly)))
         (q (secp:secp-add-points p-even (secp:secp-pubkey (taproot-tweak internal-xonly)))))
    (secp:int-to-bytes32 (secp:secp-x q))))

(defun script-for (type pubkey)
  "scriptPubKey for a compressed internal PUBKEY under address TYPE (P2TR applies the
   taproot output-key tweak)."
  (ecase type
    (:p2pkh  (p2pkh-script (w:hash160 pubkey)))
    (:p2wpkh (p2wpkh-script (w:hash160 pubkey)))
    (:p2tr   (p2tr-script (taproot-output-key (subseq pubkey 1))))))

(defun address-for (type pubkey)
  (ecase type
    (:p2pkh  (enc:encode-p2pkh (w:hash160 pubkey)))
    (:p2wpkh (enc:encode-p2wpkh (w:hash160 pubkey)))
    (:p2tr   (enc:encode-p2tr (taproot-output-key (subseq pubkey 1))))))

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

;;; ----------------------------------------------------------------------------
;;; Phase 3 — spend: build, sign (ECDSA + legacy/BIP143 sighash), ready to broadcast
;;; ----------------------------------------------------------------------------

(defun %int->be (n)
  "Minimal big-endian bytes of a non-negative integer (at least one byte)."
  (let ((out '()))
    (loop while (plusp n) do (push (logand n #xff) out) (setf n (ash n -8)))
    (or out (list 0))))

(defun %der-int (n)
  "DER INTEGER for N: 0x02 len <minimal big-endian, 0x00-prefixed if high bit set>."
  (let ((b (%int->be n)))
    (when (logbitp 7 (first b)) (push 0 b))
    (list* #x02 (length b) b)))

(defun der-encode-sig (r s)
  "DER-encode an ECDSA signature (r,s) -> byte vector (no sighash byte)."
  (let ((body (append (%der-int r) (%der-int s))))
    (coerce (list* #x30 (length body) body) '(vector (unsigned-byte 8)))))

(defun %push-data (bytes)
  "A scriptSig push of BYTES (only the small direct-push form, sufficient for sigs +
   compressed pubkeys, both < 76 bytes)."
  (let ((n (length bytes)))
    (assert (< n 76))
    (concatenate '(vector (unsigned-byte 8)) (vector n) bytes)))

(defun sign-input (wallet txn i coin prevouts)
  "Sign input I of TXN (which spends COIN, one of our wallet coins) — sets the witness
   (P2WPKH BIP143 / P2TR BIP341 key-path) or scriptSig (P2PKH).  PREVOUTS is the vector
   of (amount . scriptPubKey) for ALL inputs (needed by the taproot sighash)."
  (declare (ignore wallet))
  (let* ((wa (wcoin-waddr coin))
         (priv (b32:xkey-key (waddr-xkey wa)))
         (pubkey (waddr-pubkey wa))
         (type (wallet-type-of-script (wcoin-script coin))))
    (ecase type
      (:p2wpkh
       (let* ((sc (p2pkh-script (w:hash160 pubkey)))
              (sighash (s:bip143-sighash txn i sc (wcoin-value coin) s:+sighash-all+)))
         (multiple-value-bind (r ss) (secp:ecdsa-sign-raw priv sighash)
           (let ((sig (concatenate '(vector (unsigned-byte 8))
                                   (der-encode-sig r ss) (vector s:+sighash-all+))))
             (setf (nth i (tx:tx-witnesses txn)) (list sig pubkey))))))
      (:p2pkh
       (let* ((sc (p2pkh-script (w:hash160 pubkey)))
              (sighash (s:legacy-sighash txn i sc s:+sighash-all+)))
         (multiple-value-bind (r ss) (secp:ecdsa-sign-raw priv sighash)
           (let ((sig (concatenate '(vector (unsigned-byte 8))
                                   (der-encode-sig r ss) (vector s:+sighash-all+))))
             (setf (tx:txin-script (nth i (tx:tx-inputs txn)))
                   (concatenate '(vector (unsigned-byte 8))
                                (%push-data sig) (%push-data pubkey)))))))
      (:p2tr
       ;; BIP341 key-path: sign the taproot sighash with the tweaked private key.
       (let* ((pt (secp:secp-pubkey priv))
              (d-even (if (evenp (secp:secp-y pt)) priv (- secp:*secp256k1-n* priv)))
              (internal-xonly (secp:int-to-bytes32 (secp:secp-x pt)))
              (d-tweaked (mod (+ d-even (taproot-tweak internal-xonly)) secp:*secp256k1-n*))
              (sighash (s:taproot-sighash txn i prevouts 0 :ext-flag 0))   ; SIGHASH_DEFAULT
              (sig (sch:schnorr-sign d-tweaked sighash)))
         (setf (nth i (tx:tx-witnesses txn)) (list sig)))))))

(defun wallet-type-of-script (script)
  "Classify a scriptPubKey we own as :p2wpkh / :p2pkh / :p2tr."
  (cond ((and (= (length script) 22) (= (aref script 0) 0) (= (aref script 1) #x14)) :p2wpkh)
        ((and (= (length script) 34) (= (aref script 0) #x51) (= (aref script 1) #x20)) :p2tr)
        ((and (= (length script) 25) (= (aref script 0) #x76)) :p2pkh)
        (t (error "unsupported coin script type for signing"))))

(defun address->script (addr)
  "scriptPubKey for a destination ADDRESS (bech32/bech32m segwit or base58 P2PKH/P2SH)."
  (if (and (>= (length addr) 3)
           (string-equal (subseq addr 0 (min 3 (length addr))) "bc1"))
      (multiple-value-bind (witver program) (enc:segwit-decode addr)
        (concatenate '(vector (unsigned-byte 8))
                     (vector (if (zerop witver) 0 (+ #x50 witver)) (length program)) program))
      (let* ((payload (enc:base58check-decode addr)) (ver (aref payload 0))
             (h (subseq payload 1)))
        (cond ((= ver #x00) (p2pkh-script h))
              ((= ver #x05) (concatenate '(vector (unsigned-byte 8)) #(#xa9 #x14) h #(#x87)))
              (t (error "unsupported address version ~d" ver))))))

(defun %unspent-coins (wallet)
  (sort (loop for c being the hash-values of (wallet-coins wallet) collect c)
        #'> :key #'wcoin-value))

(defun %est-vsize (type nin nout)
  (ecase type
    (:p2wpkh (+ 11 (* 68 nin) (* 31 nout)))
    (:p2tr   (+ 11 (* 58 nin) (* 43 nout)))
    (:p2pkh  (+ 10 (* 148 nin) (* 34 nout)))))

(defun %dust (type) (ecase type (:p2wpkh 294) (:p2tr 330) (:p2pkh 546)))

(defun create-tx (wallet recipients &key (feerate 2))
  "Build + sign a tx paying RECIPIENTS (a list of (address-string . value-sat)) from the
   wallet's coins, with change back to the wallet.  FEERATE is sat/vB.  Returns a signed
   TX ready to broadcast (e.g. via the node mempool / sendrawtransaction).  Greedy
   largest-first coin selection."
  (let* ((type (wallet-type wallet))
         (target (reduce #'+ recipients :key #'cdr :initial-value 0))
         (coins (%unspent-coins wallet)) (sel '()) (sum 0) (fee 0) (nrec (length recipients)))
    ;; select largest-first until inputs cover target + fee (fee grows with input count)
    (dolist (c coins)
      (push c sel) (incf sum (wcoin-value c))
      (setf fee (ceiling (* (%est-vsize type (length sel) (1+ nrec)) feerate)))
      (when (>= sum (+ target fee)) (return)))
    (when (< sum (+ target fee)) (error "insufficient funds: have ~d, need ~d + fee" sum target))
    (let* ((change (- sum target fee))
           (outs (mapcar (lambda (r) (tx:make-txout :value (cdr r) :script (address->script (car r))))
                         recipients)))
      (when (> change (%dust type))
        (let ((cs (waddr-script (aref (ensure-addresses wallet 1 0) 0))))
          (setf outs (append outs (list (tx:make-txout :value change :script cs))))))
      (let ((txn (tx:make-tx :version 2
                   :inputs (mapcar (lambda (c) (tx:make-txin :prev-hash (wcoin-txid c)
                                                             :prev-index (wcoin-vout c)
                                                             :script #() :sequence #xfffffffd))
                                   sel)
                   :outputs outs :witnesses (make-list (length sel))
                   :locktime 0 :segwit-p (and (member type '(:p2wpkh :p2tr)) t)))
            ;; prevouts (amount . spk) for every input, in input order — the taproot
            ;; sighash commits to all of them.
            (prevouts (coerce (mapcar (lambda (c) (cons (wcoin-value c) (wcoin-script c))) sel)
                              'vector)))
        (loop for c in sel for i from 0 do (sign-input wallet txn i c prevouts))
        (tx:finalize-tx txn)
        txn))))

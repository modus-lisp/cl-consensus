;;;; src/wallet-store.lisp
;;;;
;;;; Persist / restore an HD wallet to disk.  A saved wallet records everything needed to
;;;; deterministically reconstruct the wallet — its address type, gap-limit, account index,
;;;; the BIP39 SEED (so all addresses re-derive) — plus the set of tracked coins (each coin's
;;;; outpoint, value, scriptPubKey, height, and the (chain,index) of the wallet address it
;;;; pays).  On load we rebuild via wallet:make-wallet-from-seed and re-insert the coins.
;;;;
;;;; Format: a single readable s-expression (a property list), written under
;;;; with-standard-io-syntax so it round-trips independent of reader/printer state.  Byte
;;;; vectors (txid, script, seed) are stored as hex strings via wire:bytes->hex/hex->bytes.
;;;;
;;;; SECURITY: the seed is raw key material written here in PLAINTEXT.  At-rest encryption
;;;; (e.g. passphrase-derived key over the seed field) is a follow-up.

(defpackage #:cl-consensus.wallet-store
  (:use #:cl)
  (:nicknames #:btc-wallet-store)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:wal #:cl-consensus.wallet))
  (:export #:save-wallet #:load-wallet))

(in-package #:cl-consensus.wallet-store)

(defconstant +format-version+ 1)

(defun %coin->plist (coin)
  "Serialize one wcoin to a property list with hex-encoded byte fields and the (chain,index)
   of the wallet address it pays (so the loader can re-link it to a re-derived waddr)."
  (let ((wa (wal:wcoin-waddr coin)))
    (list :txid   (w:bytes->hex (wal:wcoin-txid coin))
          :vout   (wal:wcoin-vout coin)
          :value  (wal:wcoin-value coin)
          :script (w:bytes->hex (wal:wcoin-script coin))
          :height (wal::wcoin-height coin)
          :chain  (wal:waddr-chain wa)
          :index  (wal:waddr-index wa))))

(defun save-wallet (wallet path &key seed)
  "Persist WALLET to PATH so it can be fully reconstructed.  SEED is the binary BIP39 seed
   the wallet was built from (make-wallet-from-seed does not retain it, so the caller must
   supply it here) — it is required and stored so addresses re-derive deterministically.
   Returns PATH."
  (check-type seed (vector (unsigned-byte 8)))
  (let ((data (list :format-version +format-version+
                    :type       (wal:wallet-type wallet)
                    :gap-limit  (wal::wallet-gap-limit wallet)
                    :account    (account-index wallet)
                    :seed       (w:bytes->hex seed)
                    :coins      (loop for c being the hash-values of (wal:wallet-coins wallet)
                                      collect (%coin->plist c)))))
    (with-open-file (out path :direction :output :if-exists :supersede
                              :if-does-not-exist :create)
      (with-standard-io-syntax
        ;; keep standard reader/printer state but emit plain "..." strings rather than the
        ;; verbose #A(...) form *print-readably* would otherwise force for specialized
        ;; hex strings — the result still reads back losslessly via plain READ.
        (let ((*print-readably* nil) (*print-pretty* nil))
          (prin1 data out)
          (terpri out))))
    path))

(defun account-index (wallet)
  "Recover the BIP44/84/86 account index from the wallet's derived account key.  The account
   node is the last hardened child on the path m/PURPOSE'/0'/ACCOUNT', so its child-number is
   ACCOUNT' = ACCOUNT + 2^31."
  (let ((cn (cl-consensus.bip32::xkey-child-number (wal::wallet-account-xkey wallet))))
    (logand cn #x7fffffff)))

(defun load-wallet (path)
  "Read a wallet persisted by SAVE-WALLET from PATH and reconstruct it: re-derive from the
   stored seed (same type / gap-limit / account) and re-insert every tracked coin, linking
   each back to its (chain,index) wallet address.  Returns the WALLET."
  (let ((data (with-open-file (in path :direction :input)
                (with-standard-io-syntax
                  (let ((*read-eval* nil))   ; defense: never eval while reading wallet data
                    (read in))))))
    (let* ((type      (getf data :type))
           (gap-limit (getf data :gap-limit))
           (account   (getf data :account))
           (seed      (w:hex->bytes (getf data :seed)))
           (wallet    (wal:make-wallet-from-seed seed :type type :account account
                                                       :gap-limit gap-limit)))
      (dolist (cp (getf data :coins))
        (let* ((chain (getf cp :chain))
               (index (getf cp :index))
               ;; ensure the chain is derived deep enough to hold the address this coin pays,
               ;; then re-link to the live waddr object.
               (vec   (wal::ensure-addresses wallet chain index))
               (wa    (aref vec index))
               (txid  (w:hex->bytes (getf cp :txid)))
               (vout  (getf cp :vout))
               (coin  (wal::%make-wcoin :txid txid :vout vout
                                        :value (getf cp :value)
                                        :script (w:hex->bytes (getf cp :script))
                                        :waddr wa :height (getf cp :height))))
          (setf (gethash (wal::coin-key txid vout) (wal:wallet-coins wallet)) coin)))
      wallet)))

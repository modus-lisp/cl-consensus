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
;;;; SECURITY: the seed is raw key material.  When SAVE-WALLET is given a :PASSPHRASE the seed
;;;; is encrypted at rest (encrypt-then-MAC): a 32-byte key is derived via PBKDF2-HMAC-SHA256
;;;; (fresh 16-byte salt, >=100000 iterations) and used to AES-256-CBC encrypt the PKCS#7-padded
;;;; seed under a fresh 16-byte IV; an HMAC-SHA256 over salt|iv|ciphertext authenticates the
;;;; whole envelope.  The plaintext seed field is then replaced by ENCRYPTED-P + KDF params +
;;;; salt/iv/ciphertext/mac hex.  Without a passphrase the original PLAINTEXT behavior is kept,
;;;; tagged ENCRYPTED-P NIL.

(defpackage #:cl-consensus.wallet-store
  (:use #:cl)
  (:nicknames #:btc-wallet-store)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:wal #:cl-consensus.wallet))
  (:export #:save-wallet #:load-wallet))

(in-package #:cl-consensus.wallet-store)

(defconstant +format-version+ 1)
(defconstant +default-kdf-iterations+ 200000
  "PBKDF2-HMAC-SHA256 iteration count used when none is supplied to SAVE-WALLET.")

;;; ------------------------------------------------------------------------------------------
;;; Seed at-rest encryption (encrypt-then-MAC: AES-256-CBC + HMAC-SHA256, key from PBKDF2)
;;; ------------------------------------------------------------------------------------------

(defun %b (n) (make-array n :element-type '(unsigned-byte 8)))

;;; All of it is natrium, and every secret -- the passphrase bytes, the derived key, the
;;; padded seed, the decrypted plaintext -- is in fixed memory.  AES is natrium's
;;; constant-time (bit-sliced, table-free) implementation.  The file format is unchanged.

(defmacro %with-derived-key ((key passphrase salt iterations) &body body)
  "Bind KEY to the 32-byte PBKDF2-HMAC-SHA256 key (fixed scratch) for PASSPHRASE and SALT."
  (let ((pw (gensym "PW")) (heap (gensym "HEAP")))
    `(gossamer:with-fixed-scratch ((,key :octets 32))
       (let* ((,heap (sb-ext:string-to-octets ,passphrase :external-format :utf-8))
              (,pw (prog1 (gossamer:pooled-copy ,heap) (fill ,heap 0))))
         (unwind-protect (natrium:pbkdf2-into :sha256 ,pw ,salt ,iterations ,key)
           (gossamer:free ,pw)))
       ,@body)))

(defun %mac (key salt iv ct)
  "HMAC-SHA256(KEY) over salt|iv|ciphertext (as parts: nothing is concatenated)."
  (let ((out (%b 32)))
    (natrium:hmac-sha256-into key (list salt iv ct) out)
    out))

(defun %constant-time-equal (a b)
  "Constant-time byte-vector compare (avoids leaking the MAC mismatch position via timing)."
  (and (= (length a) (length b))
       (let ((acc 0))
         (dotimes (i (length a)) (setf acc (logior acc (logxor (aref a i) (aref b i)))))
         (zerop acc))))

(defun %encrypt-seed (seed passphrase iterations)
  "Encrypt SEED under PASSPHRASE.  Returns a plist :salt/:iv/:ciphertext (hex) + :mac (hex)
   and the effective :iterations.  Encrypt-then-MAC over salt|iv|ciphertext."
  (let* ((salt (natrium:random-bytes 16))
         (iv   (natrium:random-bytes 16))
         (n    (length seed))
         (plen (* 16 (1+ (floor n 16)))))              ; PKCS#7: 1..16 bytes of padding
    (%with-derived-key (key passphrase salt iterations)
      (let ((padded (gossamer:acquire :octets plen)))
        (unwind-protect
             (progn
               (replace padded seed)
               (fill padded (- plen n) :start n)
               (let ((ct (natrium:with-aes-key (k key) (natrium:aes-cbc-encrypt k iv padded))))
                 (list :iterations iterations
                       :salt       (w:bytes->hex salt)
                       :iv         (w:bytes->hex iv)
                       :ciphertext (w:bytes->hex ct)
                       :mac        (w:bytes->hex (%mac key salt iv ct)))))
          (gossamer:free padded))))))

(defun %decrypt-seed (data passphrase)
  "Re-derive the key from PASSPHRASE, verify the MAC, then AES-CBC-decrypt back to the raw
   seed, returned as a POOLED FIXED buffer the caller FIXED:FREEs.  Signals a clear error on a
   wrong passphrase or any tampering (the MAC is checked before anything is decrypted)."
  (let* ((iterations (getf data :kdf-iterations))
         (salt       (w:hex->bytes (getf data :salt)))
         (iv         (w:hex->bytes (getf data :iv)))
         (ct         (w:hex->bytes (getf data :ciphertext)))
         (stored-mac (w:hex->bytes (getf data :mac)))
         (n          (length ct)))
    (%with-derived-key (key passphrase salt iterations)
      (unless (%constant-time-equal stored-mac (%mac key salt iv ct))
        (error "wrong passphrase or corrupt wallet"))
      (when (or (zerop n) (plusp (mod n 16)))
        (error "wrong passphrase or corrupt wallet (bad block length)"))
      (let ((pt (gossamer:acquire :octets n)))
        (unwind-protect
             (progn
               (natrium:with-aes-key (k key) (natrium:aes-cbc-decrypt-into k iv ct pt))
               (let ((pad (aref pt (1- n))))
                 (when (or (zerop pad) (> pad 16) (> pad n)
                           (loop for i from (- n pad) below n thereis (/= (aref pt i) pad)))
                   (error "wrong passphrase or corrupt wallet (bad padding)"))
                 (gossamer:pooled-copy pt :end (- n pad))))
          (gossamer:free pt))))))

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

(defun save-wallet (wallet path &key seed passphrase (kdf-iterations +default-kdf-iterations+))
  "Persist WALLET to PATH so it can be fully reconstructed.  SEED is the binary BIP39 seed
   the wallet was built from (make-wallet-from-seed does not retain it, so the caller must
   supply it here) — it is required and stored so addresses re-derive deterministically.

   When PASSPHRASE is supplied (a non-empty string) the seed is encrypted at rest with
   PBKDF2-HMAC-SHA256 (KDF-ITERATIONS, default 200000) + AES-256-CBC + HMAC-SHA256
   (encrypt-then-MAC); the plaintext seed field is replaced by ENCRYPTED-P T and the envelope
   (kdf-iterations, salt, iv, ciphertext, mac).  Without a passphrase the seed is stored in
   plaintext, tagged ENCRYPTED-P NIL.  Returns PATH."
  (check-type seed (vector (unsigned-byte 8)))
  (let* ((encrypt-p (and passphrase (plusp (length passphrase))))
         (base (list :format-version +format-version+
                     :type       (wal:wallet-type wallet)
                     :gap-limit  (wal::wallet-gap-limit wallet)
                     :account    (account-index wallet)
                     :encrypted-p (and encrypt-p t)))
         (seed-part
           (if encrypt-p
               (let ((env (%encrypt-seed seed passphrase kdf-iterations)))
                 (list :kdf-iterations (getf env :iterations)
                       :salt           (getf env :salt)
                       :iv             (getf env :iv)
                       :ciphertext     (getf env :ciphertext)
                       :mac            (getf env :mac)))
               (list :seed (w:bytes->hex seed))))
         (data (append base seed-part
                       (list :coins (loop for c being the hash-values of (wal:wallet-coins wallet)
                                          collect (%coin->plist c))))))
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

(defun load-wallet (path &key passphrase)
  "Read a wallet persisted by SAVE-WALLET from PATH and reconstruct it: re-derive from the
   stored seed (same type / gap-limit / account) and re-insert every tracked coin, linking
   each back to its (chain,index) wallet address.  Returns the WALLET.

   If the file is encrypted (ENCRYPTED-P T) a PASSPHRASE is required: the key is re-derived,
   the MAC verified, and the seed decrypted.  A wrong passphrase or any tampering signals a
   clear error rather than producing a wrong wallet."
  (let ((data (with-open-file (in path :direction :input)
                (with-standard-io-syntax
                  (let ((*read-eval* nil))   ; defense: never eval while reading wallet data
                    (read in))))))
    (let* ((type      (getf data :type))
           (gap-limit (getf data :gap-limit))
           (account   (getf data :account))
           ;; the seed reaches fixed memory either way: decrypted straight into it, or
           ;; decoded from plaintext hex with the heap copy wiped at once
           (seed      (if (getf data :encrypted-p)
                          (progn
                            (unless (and passphrase (plusp (length passphrase)))
                              (error "wallet is encrypted: a passphrase is required to load it"))
                            (%decrypt-seed data passphrase))
                          (let ((heap-seed (w:hex->bytes (getf data :seed))))
                            (prog1 (gossamer:pooled-copy heap-seed) (fill heap-seed 0)))))
           (wallet    (unwind-protect
                           (wal:make-wallet-from-seed seed :type type :account account
                                                           :gap-limit gap-limit)
                        (gossamer:free seed))))
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

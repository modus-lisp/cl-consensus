;;;; src/bip39.lisp
;;;;
;;;; BIP39 mnemonic seed phrases: entropy -> mnemonic (with SHA256 checksum) -> a
;;;; 512-bit seed via PBKDF2-HMAC-SHA512.  The seed feeds BIP32 master-from-seed.
;;;; SHA256 from wire (ironclad), PBKDF2-HMAC-SHA512 from ironclad's KDF.  The
;;;; canonical 2048-word English list lives in bip39-wordlist.lisp (same package);
;;;; its exact order is load-bearing for the checksum and the test vectors.

(defpackage #:cl-consensus.bip39
  (:use #:cl)
  (:nicknames #:btc-bip39)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:wal #:cl-consensus.wallet)
                    (#:ic #:ironclad))
  (:export
   #:*wordlist* #:mnemonic-from-entropy #:mnemonic->seed
   #:validate-mnemonic #:make-wallet-from-mnemonic))

(in-package #:cl-consensus.bip39)

;;; ----------------------------------------------------------------------------
;;; bit <-> word helpers
;;; ----------------------------------------------------------------------------

(defun bytes->bits (bytes)
  "BYTES -> a list of bits (0/1), most-significant-bit first."
  (loop for b across (coerce bytes '(vector (unsigned-byte 8)))
        nconc (loop for i from 7 downto 0 collect (if (logbitp i b) 1 0))))

(defun bits->index (bits)
  "An 11-element list of bits (msb first) -> the integer word index 0..2047."
  (reduce (lambda (acc bit) (+ (* acc 2) bit)) bits :initial-value 0))

(defun entropy->checksum-bits (entropy)
  "The leading (length-in-bits/32) bits of SHA256(ENTROPY)."
  (let* ((entbytes (coerce entropy '(vector (unsigned-byte 8))))
         (cs-len (/ (* (length entbytes) 8) 32))
         (digest (w:sha256 entbytes)))
    (subseq (bytes->bits digest) 0 cs-len)))

(defun word-index (word)
  "The 0..2047 index of WORD in the wordlist, or NIL if not present."
  (position word *wordlist* :test #'string=))

;;; ----------------------------------------------------------------------------
;;; entropy -> mnemonic
;;; ----------------------------------------------------------------------------

(defun mnemonic-from-entropy (entropy-bytes)
  "BIP39 mnemonic string for ENTROPY-BYTES (16 bytes -> 12 words, 32 -> 24 words;
   any multiple-of-4-byte length from 16..32 is accepted).  Appends an
   (entropy-bits/32)-bit SHA256 checksum, then maps each 11-bit group to a word."
  (let ((nbytes (length entropy-bytes)))
    (unless (and (member nbytes '(16 20 24 28 32))
                 (zerop (mod (* nbytes 8) 32)))
      (error "BIP39 entropy must be 128/160/192/224/256 bits, got ~d bits"
             (* nbytes 8)))
    (let* ((bits (append (bytes->bits entropy-bytes)
                         (entropy->checksum-bits entropy-bytes)))
           (words (loop for i from 0 below (length bits) by 11
                        collect (aref *wordlist*
                                      (bits->index (subseq bits i (+ i 11)))))))
      (format nil "~{~a~^ ~}" words))))

;;; ----------------------------------------------------------------------------
;;; mnemonic -> entropy (for validation)
;;; ----------------------------------------------------------------------------

(defun split-words (mnemonic)
  "MNEMONIC string -> a list of its space-separated words (any whitespace run)."
  (loop with len = (length mnemonic) with start = 0
        for ws = (position-if (lambda (c) (member c '(#\Space #\Tab #\Newline #\Return)))
                              mnemonic :start start)
        for word = (subseq mnemonic start (or ws len))
        unless (string= word "") collect word
        while ws do (setf start (1+ ws))
        until (> start len)))

(defun mnemonic->bits (mnemonic)
  "MNEMONIC -> the full (entropy+checksum) bit list, or NIL if a word is unknown."
  (let ((idxs (mapcar #'word-index (split-words mnemonic))))
    (when (every #'identity idxs)
      (loop for idx in idxs
            nconc (loop for i from 10 downto 0 collect (if (logbitp i idx) 1 0))))))

(defun bits->bytes (bits)
  "A bit list whose length is a multiple of 8 -> a byte vector (msb first)."
  (coerce (loop for i from 0 below (length bits) by 8
                collect (bits->index (subseq bits i (+ i 8))))
          '(vector (unsigned-byte 8))))

(defun validate-mnemonic (mnemonic)
  "T iff MNEMONIC is a well-formed BIP39 phrase whose checksum recomputes correctly."
  (let* ((words (split-words mnemonic))
         (nwords (length words)))
    (and (member nwords '(12 15 18 21 24))
         (let ((bits (mnemonic->bits mnemonic)))
           (and bits
                (let* ((ent-bits (* nwords 11))          ; total bits
                       (cs-len (/ ent-bits 33))          ; checksum bits = total/33
                       (ent-len (- ent-bits cs-len))     ; entropy bits
                       (entropy (bits->bytes (subseq bits 0 ent-len)))
                       (want (entropy->checksum-bits entropy))
                       (got (subseq bits ent-len)))
                  (equal want got)))))))

;;; ----------------------------------------------------------------------------
;;; mnemonic -> 512-bit seed (PBKDF2-HMAC-SHA512, 2048 iterations)
;;; ----------------------------------------------------------------------------

(defun mnemonic->seed (mnemonic &optional (passphrase ""))
  "The 64-byte BIP39 seed: PBKDF2(HMAC-SHA512, password=MNEMONIC,
   salt=\"mnemonic\"||PASSPHRASE, 2048 iterations, dkLen=64).  The mnemonic and
   passphrase are taken as UTF-8 (NFKD assumed already applied; ASCII is exact)."
  (let ((kdf (ic:make-kdf :pbkdf2 :digest :sha512))
        (pw (ic:ascii-string-to-byte-array mnemonic))
        (salt (ic:ascii-string-to-byte-array
               (concatenate 'string "mnemonic" passphrase))))
    (ic:derive-key kdf pw salt 2048 64)))

;;; ----------------------------------------------------------------------------
;;; wallet bridge
;;; ----------------------------------------------------------------------------

(defun make-wallet-from-mnemonic (mnemonic &key (type :p2wpkh) (passphrase "")
                                                (account 0) (gap-limit 20))
  "Build an HD wallet directly from a BIP39 MNEMONIC (validated first), deriving the
   seed with the optional PASSPHRASE and handing it to wallet:make-wallet-from-seed."
  (unless (validate-mnemonic mnemonic)
    (error "invalid BIP39 mnemonic (bad word or checksum)"))
  (wal:make-wallet-from-seed (mnemonic->seed mnemonic passphrase)
                             :type type :account account :gap-limit gap-limit))

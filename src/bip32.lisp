;;;; src/bip32.lisp
;;;;
;;;; BIP32 hierarchical-deterministic key derivation: a master key from a seed, then
;;;; child keys down a path (m/84'/0'/0'/0/0).  Private (CKD-priv, hardened or normal)
;;;; and public (CKD-pub, normal only) derivation, xprv/xpub serialization.  Curve ops
;;;; from secp256k1-fast; HMAC-SHA512 / SHA512 from ironclad (as wire already uses
;;;; ironclad for ripemd160).

(defpackage #:cl-consensus.bip32
  (:use #:cl)
  (:nicknames #:btc-bip32)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:w #:cl-consensus.wire)
                    (#:enc #:cl-consensus.encoding) (#:ic #:ironclad))
  (:export
   #:xkey #:xkey-p #:xkey-depth #:xkey-chain-code #:xkey-key #:xkey-private-p
   #:master-from-seed #:ckd-priv #:ckd-pub #:derive-path #:neuter
   #:xkey-pubpoint #:xkey-pubkey #:xkey-privkey #:fingerprint
   #:serialize-xkey #:compressed-pubkey #:+hardened+))

(in-package #:cl-consensus.bip32)

(defconstant +hardened+ #x80000000)
(defparameter *xprv-version* #x0488ade4)   ; mainnet
(defparameter *xpub-version* #x0488b21e)

(defun bytes (&rest seqs)
  (apply #'concatenate '(vector (unsigned-byte 8)) seqs))

(defun ascii->bytes (s)
  (map '(vector (unsigned-byte 8)) #'char-code s))

(defun hmac-sha512 (key data)
  (let ((h (ic:make-hmac (coerce key '(vector (unsigned-byte 8))) :sha512)))
    (ic:update-hmac h (coerce data '(vector (unsigned-byte 8))))
    (ic:hmac-digest h)))

(defun ser32 (i)
  (vector (logand (ash i -24) #xff) (logand (ash i -16) #xff)
          (logand (ash i -8) #xff) (logand i #xff)))

(defstruct (xkey (:predicate xkey-p))
  (version 0) (depth 0) (parent-fp #(0 0 0 0)) (child-number 0)
  chain-code              ; 32 bytes
  key                     ; private: integer k; public: point (cons x . y)
  (private-p t))

(defun compressed-pubkey (point)
  "33-byte compressed SEC public key for POINT (02/03 by y-parity || x)."
  (bytes (vector (if (evenp (secp:secp-y point)) 2 3))
         (secp:int-to-bytes32 (secp:secp-x point))))

(defun xkey-pubpoint (xk)
  (if (xkey-private-p xk) (secp:secp-pubkey (xkey-key xk)) (xkey-key xk)))

(defun xkey-pubkey (xk) (compressed-pubkey (xkey-pubpoint xk)))
(defun xkey-privkey (xk)
  (unless (xkey-private-p xk) (error "no private key (this is an xpub)"))
  (secp:int-to-bytes32 (xkey-key xk)))

(defun fingerprint (xk)
  (subseq (w:hash160 (xkey-pubkey xk)) 0 4))

(defun master-from-seed (seed)
  "BIP32 master key from a SEED (typically a BIP39 512-bit seed)."
  (let* ((i (hmac-sha512 (ascii->bytes "Bitcoin seed") seed))
         (il (subseq i 0 32)) (ir (subseq i 32 64))
         (k (secp:bytes-to-int il)))
    (when (or (zerop k) (>= k secp:*secp256k1-n*)) (error "invalid master key"))
    (make-xkey :version *xprv-version* :depth 0 :chain-code ir :key k :private-p t)))

(defun ckd-priv (xk i)
  "Derive child private key at index I (>= +hardened+ for a hardened child)."
  (unless (xkey-private-p xk) (error "ckd-priv needs a private key"))
  (let* ((data (if (>= i +hardened+)
                   (bytes (vector 0) (secp:int-to-bytes32 (xkey-key xk)) (ser32 i))
                   (bytes (xkey-pubkey xk) (ser32 i))))
         (big (hmac-sha512 (xkey-chain-code xk) data))
         (il (secp:bytes-to-int (subseq big 0 32))) (ir (subseq big 32 64))
         (ki (mod (+ il (xkey-key xk)) secp:*secp256k1-n*)))
    (when (or (>= il secp:*secp256k1-n*) (zerop ki))
      (error "invalid derived key at index ~d (use next index)" i))
    (make-xkey :version (xkey-version xk) :depth (1+ (xkey-depth xk))
               :parent-fp (fingerprint xk) :child-number i
               :chain-code ir :key ki :private-p t)))

(defun ckd-pub (xk i)
  "Derive child PUBLIC key at index I (normal children only)."
  (when (>= i +hardened+) (error "cannot derive a hardened child of an xpub"))
  (let* ((data (bytes (xkey-pubkey xk) (ser32 i)))
         (big (hmac-sha512 (xkey-chain-code xk) data))
         (il (secp:bytes-to-int (subseq big 0 32))) (ir (subseq big 32 64))
         (point (secp:secp-add-points (secp:secp-pubkey il) (xkey-pubpoint xk))))
    (when (>= il secp:*secp256k1-n*) (error "invalid derived key at index ~d" i))
    (make-xkey :version *xpub-version* :depth (1+ (xkey-depth xk))
               :parent-fp (fingerprint xk) :child-number i
               :chain-code ir :key point :private-p nil)))

(defun neuter (xk)
  "The public (xpub) form of a private xkey."
  (if (xkey-private-p xk)
      (make-xkey :version *xpub-version* :depth (xkey-depth xk)
                 :parent-fp (xkey-parent-fp xk) :child-number (xkey-child-number xk)
                 :chain-code (xkey-chain-code xk) :key (xkey-pubpoint xk) :private-p nil)
      xk))

(defun parse-path (path)
  "Parse \"m/84'/0'/0'/0/0\" -> a list of child indices (hardened components add
   +hardened+).  A leading m/M is dropped."
  (let ((parts (remove "" (uiop-split path #\/) :test #'string=)))
    (when (and parts (member (first parts) '("m" "M") :test #'string=)) (pop parts))
    (mapcar (lambda (p)
              (let* ((h (and (plusp (length p)) (member (char p (1- (length p))) '(#\' #\h #\H))))
                     (num (parse-integer (if h (subseq p 0 (1- (length p))) p))))
                (if h (+ num +hardened+) num)))
            parts)))

(defun uiop-split (string ch)
  (loop with start = 0 for i = (position ch string :start start)
        collect (subseq string start i)
        while i do (setf start (1+ i))))

(defun derive-path (xk path)
  "Derive XK down PATH (a string like \"m/84'/0'/0'/0/0\").  Uses CKD-priv on a private
   key (so hardened steps work), CKD-pub on a public key."
  (let ((k xk))
    (dolist (i (parse-path path) k)
      (setf k (if (xkey-private-p k) (ckd-priv k i) (ckd-pub k i))))))

(defun serialize-xkey (xk)
  "BIP32 Base58Check serialization (xprv if private, xpub if public)."
  (let* ((version (if (xkey-private-p xk) *xprv-version* *xpub-version*))
         (keybytes (if (xkey-private-p xk)
                       (bytes (vector 0) (secp:int-to-bytes32 (xkey-key xk)))
                       (xkey-pubkey xk)))
         (payload (bytes (ser32 version) (vector (xkey-depth xk))
                         (xkey-parent-fp xk) (ser32 (xkey-child-number xk))
                         (xkey-chain-code xk) keybytes)))
    (enc:base58check-encode payload)))

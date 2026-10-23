;;;;; src/bip32.lisp
;;;;
;;;; BIP32 hierarchical-deterministic key derivation: a master key from a seed, then
;;;; child keys down a path (m/84'/0'/0'/0/0).  Private (CKD-priv, hardened or normal)
;;;; and public (CKD-pub, normal only) derivation, xprv/xpub serialization.
;;;;
;;;; A PRIVATE xkey holds its key and chain code in pooled FIXED buffers (never
;;;; integers, never heap vectors), owned by the xkey -- XKEY-WIPE returns them, and a
;;;; dropped xkey returns them through FIXED:OWN.  HMAC-SHA512 runs in natrium over
;;;; parts into fixed scratch; the child key is SECKEY-TWEAK-ADD-INTO.  A PUBLIC xkey's
;;;; arithmetic is public and uses ordinary integers and points.

(defpackage #:cl-consensus.bip32
  (:use #:cl)
  (:nicknames #:btc-bip32)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:w #:cl-consensus.wire)
                    (#:enc #:cl-consensus.encoding))
  (:export
   #:xkey #:xkey-p #:xkey-depth #:xkey-chain-code #:xkey-key #:xkey-private-p
   #:master-from-seed #:ckd-priv #:ckd-pub #:derive-path #:neuter #:xkey-wipe
   #:xkey-pubpoint #:xkey-pubkey #:fingerprint
   #:serialize-xkey #:compressed-pubkey #:+hardened+))

(in-package #:cl-consensus.bip32)

(defconstant +hardened+ #x80000000)
(defparameter *xprv-version* #x0488ade4)   ; mainnet
(defparameter *xpub-version* #x0488b21e)

(defun bytes (&rest seqs)
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) seqs))

(defun ascii->bytes (s)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))

(defvar +bitcoin-seed+ (ascii->bytes "Bitcoin seed"))
(defvar +zero1+ (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0))

(defun ser32 (i)
  (let ((v (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref v 0) (ldb (byte 8 24) i) (aref v 1) (ldb (byte 8 16) i)
          (aref v 2) (ldb (byte 8 8) i) (aref v 3) (ldb (byte 8 0) i))
    v))

(defstruct (xkey (:predicate xkey-p))
  (version 0) (depth 0) (parent-fp #(0 0 0 0)) (child-number 0)
  chain-code              ; 32 bytes (private: a pooled fixed buffer)
  key                     ; private: pooled fixed 32-byte key; public: point (x . y)
  (private-p t)
  (pub-cache nil))        ; cached public point

(defun %make-private-xkey (key chain &rest initargs)
  "A private xkey owning the pooled buffers KEY and CHAIN."
  (let ((xk (apply #'make-xkey :key key :chain-code chain :private-p t initargs)))
    (gossamer:own xk key chain)))

(defun xkey-wipe (xk)
  "Wipe a private XK's key and chain code and return them to the pool.  XK is
unusable afterwards.  A no-op on a public xkey."
  (when (and (xkey-private-p xk) (xkey-key xk))
    (gossamer:disown xk)
    (gossamer:free (xkey-key xk)) (gossamer:free (xkey-chain-code xk))
    (setf (xkey-key xk) nil (xkey-chain-code xk) nil))
  xk)

(defun %live-key (xk)
  (or (xkey-key xk) (error "use of a wiped xkey")))

(defun compressed-pubkey (point)
  "33-byte compressed SEC public key for POINT (02/03 by y-parity || x)."
  (bytes (vector (if (evenp (secp:secp-y point)) 2 3))
         (secp:int-to-bytes32 (secp:secp-x point))))

(defun xkey-pubpoint (xk)
  (if (xkey-private-p xk)
      (or (xkey-pub-cache xk)
          (setf (xkey-pub-cache xk) (secp:secp-pubkey (%live-key xk))))
      (xkey-key xk)))


(defun xkey-pubkey (xk) (compressed-pubkey (xkey-pubpoint xk)))

(defun fingerprint (xk)
  (subseq (w:hash160 (xkey-pubkey xk)) 0 4))

(defun master-from-seed (seed)
  "BIP32 master key from a SEED (typically a BIP39 512-bit seed, a fixed buffer)."
  (gossamer:check-fixed seed "BIP-32 seed")
  (let ((key (gossamer:acquire :octets 32)) (chain (gossamer:acquire :octets 32)))
    (gossamer:with-fixed-scratch ((i :octets 64))
      (natrium:hmac-sha512-into +bitcoin-seed+ seed i)
      (replace key i :end2 32) (replace chain i :start2 32))
    (unless (secp:seckey-valid-p key)
      (gossamer:free key) (gossamer:free chain) (error "invalid master key"))
    (%make-private-xkey key chain :version *xprv-version* :depth 0)))

(defun ckd-priv (xk i)
  "Derive child private key at index I (>= +hardened+ for a hardened child)."
  (unless (xkey-private-p xk) (error "ckd-priv needs a private key"))
  (let ((parent (%live-key xk))
        (key (gossamer:acquire :octets 32)) (chain (gossamer:acquire :octets 32)))
    (handler-case
        (gossamer:with-fixed-scratch ((big :octets 64))
          (natrium:hmac-sha512-into (xkey-chain-code xk)
                                    (if (>= i +hardened+)
                                        (list +zero1+ parent (ser32 i))
                                        (list (xkey-pubkey xk) (ser32 i)))
                                    big)
          (secp:seckey-tweak-add-into parent big key)
          (replace chain big :start2 32))
      (error ()
        (gossamer:free key) (gossamer:free chain)
        (error "invalid derived key at index ~d (use next index)" i)))
    (%make-private-xkey key chain :version (xkey-version xk) :depth (1+ (xkey-depth xk))
                        :parent-fp (fingerprint xk) :child-number i)))

(defun ckd-pub (xk i)
  "Derive child PUBLIC key at index I (normal children only).  Everything here is
public: IL is derivable from the xpub."
  (when (>= i +hardened+) (error "cannot derive a hardened child of an xpub"))
  (let* ((data (bytes (xkey-pubkey xk) (ser32 i)))
         (big (natrium:hmac-sha512 (bytes (xkey-chain-code xk)) data))
         (il (secp:bytes-to-int (subseq big 0 32))) (ir (subseq big 32 64)))
    (when (or (zerop il) (>= il secp:*secp256k1-n*)) (error "invalid derived key at index ~d" i))
    (let ((point (secp:secp-add-points (secp:secp-mul-point il (secp:secp-generator))
                                       (xkey-pubpoint xk))))
      (make-xkey :version *xpub-version* :depth (1+ (xkey-depth xk))
                 :parent-fp (fingerprint xk) :child-number i
                 :chain-code ir :key point :private-p nil))))

(defun neuter (xk)
  "The public (xpub) form of a private xkey."
  (if (xkey-private-p xk)
      (make-xkey :version *xpub-version* :depth (xkey-depth xk)
                 :parent-fp (xkey-parent-fp xk) :child-number (xkey-child-number xk)
                 :chain-code (bytes (xkey-chain-code xk)) :key (xkey-pubpoint xk) :private-p nil)
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
   key (so hardened steps work), CKD-pub on a public key.  Intermediate private keys
   are wiped as soon as their child exists; XK itself is the caller's."
  (let ((k xk))
    (dolist (i (parse-path path) k)
      (let ((next (if (xkey-private-p k) (ckd-priv k i) (ckd-pub k i))))
        (unless (eq k xk) (xkey-wipe k))
        (setf k next)))))

(defun serialize-xkey (xk)
  "BIP32 Base58Check serialization (xprv if private, xpub if public).  An xprv is an
EXPORT of the private key: the result is an ordinary heap string."
  (let* ((version (if (xkey-private-p xk) *xprv-version* *xpub-version*))
         (keybytes (if (xkey-private-p xk)
                       (bytes (vector 0) (%live-key xk))
                       (xkey-pubkey xk)))
         (payload (bytes (ser32 version) (vector (xkey-depth xk))
                         (xkey-parent-fp xk) (ser32 (xkey-child-number xk))
                         (xkey-chain-code xk) keybytes)))
    (enc:base58check-encode payload)))

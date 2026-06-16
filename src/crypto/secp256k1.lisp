;;; shared/crypto/secp256k1.lisp
;;;
;;; secp256k1 curve operations + ECDSA signing with RFC 6979.
;;;
;;; Curve math (constants, modular arithmetic, point operations, scalar
;;; multiplication) is vendored verbatim from the operator's other Lisp
;;; project, modus (https://github.com/ynniv/modus, MIT licensed,
;;; copyright 2025 The Modus Development Team), where it powers
;;; Nostr/Bitcoin BIP-340 Schnorr signatures. Modus's Schnorr is not
;;; reproduced here; we add ECDSA-with-RFC6979 instead, which is what
;;; Ethereum (and therefore Polymarket) needs.
;;;
;;; ECDSA is built on top of ironclad for HMAC-SHA-256 (RFC 6979) and
;;; raw secp256k1 curve ops above. Result of SECP-ECDSA-SIGN-RAW is the
;;; canonical (r, s, v) triple — r and s as integers, v as the 0/1
;;; recovery byte that Ethereum signatures append (offset to 27/28 by
;;; the higher-level EIP-712 layer).


(defpackage #:cl-consensus.crypto.secp256k1
  (:use #:cl)
  (:local-nicknames (#:ic #:ironclad))
  (:export ;; constants and basic conversions
           #:*secp256k1-p* #:*secp256k1-n*
           #:secp-init #:secp-generator
           #:bytes-to-int #:int-to-bytes32
           ;; field & curve ops (re-exported for callers building on top)
           #:secp-mod #:secp-add #:secp-sub #:secp-mul #:secp-sq #:secp-neg
           #:secp-inv #:secp-double #:secp-add-points #:secp-mul-point
           #:secp-on-curve-p #:secp-pubkey
           ;; ECDSA
           #:ecdsa-sign-raw #:ecdsa-verify
           #:rfc6979-k))

(in-package #:cl-consensus.crypto.secp256k1)

;;; -----------------------------------------------------------------------
;;; Curve math (vendored from modus/crypto/secp256k1.lisp lines 12-135)
;;; -----------------------------------------------------------------------

(defparameter *secp256k1-p* nil)
(defparameter *secp256k1-n* nil)
(defparameter *secp256k1-gx* nil)
(defparameter *secp256k1-gy* nil)

(defun bytes-to-int (bytes)
  "Convert byte array to integer (big-endian)."
  (let ((result 0))
    (dotimes (i (length bytes))
      (setf result (+ (ash result 8) (aref bytes i))))
    result))

(defun int-to-bytes32 (n)
  "Convert integer to 32-byte array (big-endian)."
  (let ((result (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element 0)))
    (dotimes (i 32)
      (setf (aref result (- 31 i)) (ldb (byte 8 (* i 8)) n)))
    result))

(defun secp-init ()
  "Initialize secp256k1 constants from canonical big-endian byte arrays."
  (unless *secp256k1-p*
    (setf *secp256k1-p*
          (bytes-to-int #(#xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFE #xFF #xFF #xFC #x2F)))
    (setf *secp256k1-n*
          (bytes-to-int #(#xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFE
                          #xBA #xAE #xDC #xE6 #xAF #x48 #xA0 #x3B
                          #xBF #xD2 #x5E #x8C #xD0 #x36 #x41 #x41)))
    (setf *secp256k1-gx*
          (bytes-to-int #(#x79 #xBE #x66 #x7E #xF9 #xDC #xBB #xAC
                          #x55 #xA0 #x62 #x95 #xCE #x87 #x0B #x07
                          #x02 #x9B #xFC #xDB #x2D #xCE #x28 #xD9
                          #x59 #xF2 #x81 #x5B #x16 #xF8 #x17 #x98)))
    (setf *secp256k1-gy*
          (bytes-to-int #(#x48 #x3A #xDA #x77 #x26 #xA3 #xC4 #x65
                          #x5D #xA4 #xFB #xFC #x0E #x11 #x08 #xA8
                          #xFD #x17 #xB4 #x48 #xA6 #x85 #x54 #x19
                          #x9C #x47 #xD0 #x8F #xFB #x10 #xD4 #xB8))))
  t)

(defparameter *secp256k1-infinity* (cons :infinity nil))

(defun secp-mod (x) (mod x *secp256k1-p*))
(defun secp-add (a b) (secp-mod (+ a b)))
(defun secp-sub (a b) (secp-mod (- a b)))
(defun secp-mul (a b) (secp-mod (* a b)))
(defun secp-sq  (a)   (secp-mod (* a a)))
(defun secp-neg (a)   (secp-mod (- *secp256k1-p* a)))

(defun secp-inv (a)
  "Modular inverse using extended Euclidean algorithm."
  (let ((t0 0) (t1 1)
        (r0 *secp256k1-p*) (r1 (mod a *secp256k1-p*)))
    (loop while (not (zerop r1)) do
      (let* ((q (floor r0 r1))
             (new-r1 (- r0 (* q r1)))
             (new-t1 (- t0 (* q t1))))
        (setf r0 r1
              r1 new-r1
              t0 t1
              t1 new-t1)))
    (if (< t0 0) (+ t0 *secp256k1-p*) t0)))

(defun secp-inf-p (p) (eq (car p) :infinity))
(defun secp-x (p) (car p))
(defun secp-y (p) (cdr p))

(defun secp-double (p)
  "Double a point."
  (when (secp-inf-p p) (return-from secp-double p))
  (let ((x (secp-x p)) (y (secp-y p)))
    (when (zerop y) (return-from secp-double *secp256k1-infinity*))
    (let* ((lam (secp-mul (secp-mul 3 (secp-sq x))
                          (secp-inv (secp-mul 2 y))))
           (x3 (secp-sub (secp-sq lam) (secp-mul 2 x)))
           (y3 (secp-sub (secp-mul lam (secp-sub x x3)) y)))
      (cons x3 y3))))

(defun secp-add-points (p1 p2)
  "Add two points."
  (cond
    ((secp-inf-p p1) p2)
    ((secp-inf-p p2) p1)
    (t
     (let ((x1 (secp-x p1)) (y1 (secp-y p1))
           (x2 (secp-x p2)) (y2 (secp-y p2)))
       (cond
         ((and (= x1 x2) (= y1 (secp-neg y2))) *secp256k1-infinity*)
         ((and (= x1 x2) (= y1 y2)) (secp-double p1))
         (t
          (let* ((lam (secp-mul (secp-sub y2 y1)
                                (secp-inv (secp-sub x2 x1))))
                 (x3 (secp-sub (secp-sub (secp-sq lam) x1) x2))
                 (y3 (secp-sub (secp-mul lam (secp-sub x1 x3)) y1)))
            (cons x3 y3))))))))

(defun secp-mul-point (k p)
  "Scalar multiplication k*P via double-and-add."
  (secp-init)
  (let ((result *secp256k1-infinity*)
        (temp p)
        (n (mod k *secp256k1-n*)))
    (loop while (> n 0) do
      (when (oddp n)
        (setf result (secp-add-points result temp)))
      (setf temp (secp-double temp))
      (setf n (ash n -1)))
    result))

(defun secp-generator ()
  "Return generator point G."
  (secp-init)
  (cons *secp256k1-gx* *secp256k1-gy*))

(defun secp-pubkey (privkey)
  "Compute public key point from private-key integer."
  (secp-mul-point privkey (secp-generator)))

(defun secp-on-curve-p (p)
  "Check if point is on curve y² = x³ + 7."
  (secp-init)
  (if (secp-inf-p p) t
      (let ((x (secp-x p)) (y (secp-y p)))
        (= (secp-sq y) (secp-mod (+ (secp-mul x (secp-sq x)) 7))))))

;;; -----------------------------------------------------------------------
;;; ECDSA + RFC 6979 (deterministic k)
;;; -----------------------------------------------------------------------
;;;
;;; RFC 6979 derives k from the message hash and private key via
;;; HMAC-SHA-256 in a fixed-point construction. Reference: RFC 6979 §3.2.
;;; This is what every Ethereum signer (geth, ethers.js, web3.py,
;;; py-clob-client, …) uses, and it's what makes our signatures
;;; reproducible against test vectors.

(defun secp-inv-mod (a m)
  "Modular inverse of A mod M (extended Euclidean) — used with M = N
   (curve order) inside ECDSA, where SECP-INV (mod P) doesn't apply."
  (let ((t0 0) (t1 1) (r0 m) (r1 (mod a m)))
    (loop while (not (zerop r1)) do
      (let* ((q (floor r0 r1))
             (nr (- r0 (* q r1)))
             (nt (- t0 (* q t1))))
        (setf r0 r1 r1 nr t0 t1 t1 nt)))
    (if (< t0 0) (+ t0 m) t0)))

(defun bytes-mod-n (bytes n)
  "RFC 6979 'bits2int mod n': convert BYTES big-endian to integer, then mod N."
  (mod (bytes-to-int bytes) n))

(defun bytes2octets (b n)
  "RFC 6979 bits2octets: int(b) mod n, then encode as 32-byte big-endian."
  (int-to-bytes32 (bytes-mod-n b n)))

(defun hmac-sha256 (key msg)
  "Keyed HMAC-SHA-256 returning a 32-byte array."
  (let ((mac (ic:make-hmac key :sha256)))
    (ic:update-hmac mac msg)
    (ic:hmac-digest mac)))

(defun rfc6979-k (privkey-int hash-bytes &optional (n nil))
  "Deterministic K per RFC 6979 §3.2 over secp256k1 curve order N.
   PRIVKEY-INT is the integer private key, HASH-BYTES is the message
   hash (32 bytes for keccak-256). Returns an integer k in [1, N-1]."
  (secp-init)
  (let* ((n (or n *secp256k1-n*))
         (x (int-to-bytes32 privkey-int))
         (h1 hash-bytes)
         ;; Step b: V = 0x01 0x01 ... (32 bytes)
         (v (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element #x01))
         ;; Step c: K = 0x00 0x00 ... (32 bytes)
         (k (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element #x00))
         (h1-octets (bytes2octets h1 n)))
    (flet ((cat (&rest arrays)
             (let* ((total (loop for a in arrays sum (length a)))
                    (out (make-array total :element-type '(unsigned-byte 8)))
                    (p 0))
               (dolist (a arrays out)
                 (loop for b across a do (setf (aref out p) b) (incf p))))))
      ;; Step d: K = HMAC_K(V || 0x00 || x || h1)
      (setf k (hmac-sha256 k (cat v #(#x00) x h1-octets)))
      ;; Step e: V = HMAC_K(V)
      (setf v (hmac-sha256 k v))
      ;; Step f: K = HMAC_K(V || 0x01 || x || h1)
      (setf k (hmac-sha256 k (cat v #(#x01) x h1-octets)))
      ;; Step g: V = HMAC_K(V)
      (setf v (hmac-sha256 k v))
      ;; Step h: loop until we find a candidate k in [1, n-1].
      (loop
        (setf v (hmac-sha256 k v))
        (let ((candidate (bytes-to-int v)))
          (when (and (plusp candidate) (< candidate n))
            (return candidate)))
        ;; not in range — bump K, V and retry.
        (setf k (hmac-sha256 k (cat v #(#x00))))
        (setf v (hmac-sha256 k v))))))

(defun ecdsa-sign-raw (privkey-int hash-bytes)
  "Sign HASH-BYTES (32-byte digest) under PRIVKEY-INT. Returns (values
   r s v) where R and S are integers in [1, N-1] and V is the 0/1
   recovery id (Ethereum offsets it by 27 to get the on-the-wire value
   in legacy signatures).

   S is canonicalized to the lower half (R, S ≤ N/2) per BIP-62 / EIP-2,
   which is what Ethereum nodes accept post-Homestead."
  (secp-init)
  (let* ((n *secp256k1-n*)
         (z (mod (bytes-to-int hash-bytes) n)))
    (loop
      (let* ((k (rfc6979-k privkey-int hash-bytes))
             (kg (secp-mul-point k (secp-generator)))
             (r  (mod (secp-x kg) n)))
        (when (zerop r) (return-from ecdsa-sign-raw nil))   ; retry path
        (let* ((k-inv (mod (secp-inv-mod k n) n))
               (s (mod (* k-inv (mod (+ z (* r privkey-int)) n)) n)))
          (when (zerop s)
            ;; degenerate — RFC 6979 says move on; very rare.
            (return-from ecdsa-sign-raw nil))
          (let* ((y (secp-y kg))
                 ;; Canonicalize S: low-S form (BIP-62 / EIP-2).
                 (high-s? (> s (ash n -1)))
                 (s-can (if high-s? (- n s) s))
                 ;; Recovery id: bit 0 = parity of R.y, bit 1 = R.x ≥ N
                 ;; (the latter is rare when we keep r = R.x mod n).
                 (v0 (if (oddp y) 1 0))
                 (v  (if high-s? (logxor v0 1) v0)))
            (return (values r s-can v))))))))

(defun ecdsa-verify (pubkey-pt hash-bytes r s)
  "Verify (R, S) against HASH-BYTES under PUBKEY-PT. Returns T or NIL."
  (secp-init)
  (let ((n *secp256k1-n*))
    (cond
      ((not (and (< 0 r n) (< 0 s n))) nil)
      (t
       (let* ((z (mod (bytes-to-int hash-bytes) n))
              (s-inv (secp-inv-mod s n))
              (u1 (mod (* z s-inv) n))
              (u2 (mod (* r s-inv) n))
              (p1 (secp-mul-point u1 (secp-generator)))
              (p2 (secp-mul-point u2 pubkey-pt))
              (sum (secp-add-points p1 p2)))
         (and (not (secp-inf-p sum))
              (= r (mod (secp-x sum) n))))))))

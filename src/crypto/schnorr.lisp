;;; shared/crypto/schnorr.lisp
;;;
;;; BIP-340 Schnorr signatures over secp256k1 — the scheme Nostr uses for
;;; event signatures (and Bitcoin Taproot). Built on the curve ops in
;;; cl-consensus.crypto.secp256k1 (points are (x . y) conses, infinity is
;;; (:infinity . nil)). VERIFY is what siteglass needs for agent auth
;;; (Nostr NIP-98); SIGN is included for tests/round-trips.
;;;
;;; Verified against the canonical bitcoin/bips bip-0340 test vectors.


(defpackage #:cl-consensus.crypto.schnorr
  (:use #:cl)
  (:local-nicknames (#:secp #:cl-consensus.crypto.secp256k1) (#:ic #:ironclad))
  (:export #:schnorr-verify #:schnorr-sign #:tagged-hash #:pubkey-xonly))

(in-package #:cl-consensus.crypto.schnorr)

(defun sha256 (bytes) (ic:digest-sequence :sha256 bytes))
(defun cat (&rest vs) (apply #'concatenate '(vector (unsigned-byte 8)) vs))

(defun tagged-hash (tag msg)
  "BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."
  (let ((th (sha256 (ic:ascii-string-to-byte-array tag))))
    (sha256 (cat th th msg))))

(defun p () secp:*secp256k1-p*)
(defun n () secp:*secp256k1-n*)
(defun ptx (pt) (car pt))
(defun pty (pt) (cdr pt))
(defun infp (pt) (eq (car pt) :infinity))

(defun lift-x (x)
  "BIP-340 lift_x: the point with even Y whose X is X, or NIL."
  (secp:secp-init)
  (when (and (>= x 0) (< x (p)))
    (let* ((c (secp:secp-mod (+ (secp:secp-mul (secp:secp-mul x x) x) 7)))
           (y (ic:expt-mod c (floor (+ (p) 1) 4) (p))))
      (when (= (secp:secp-mod (* y y)) c)
        (cons x (if (evenp y) y (- (p) y)))))))

(defun pubkey-xonly (privkey-int)
  "32-byte x-only public key for a private key integer."
  (secp:secp-init)
  (secp:int-to-bytes32 (ptx (secp:secp-mul-point privkey-int (secp:secp-generator)))))

(defun schnorr-verify (pubkey32 msg32 sig64)
  "T iff SIG64 is a valid BIP-340 signature of MSG32 under x-only PUBKEY32.
   All args are (unsigned-byte 8) vectors (32/32/64)."
  (secp:secp-init)
  (handler-case
      (let* ((px (secp:bytes-to-int pubkey32))
             (pt (lift-x px)))
        (when pt
          (let ((r (secp:bytes-to-int (subseq sig64 0 32)))
                (s (secp:bytes-to-int (subseq sig64 32 64))))
            (when (and (< r (p)) (< s (n)))
              (let* ((e (mod (secp:bytes-to-int
                              (tagged-hash "BIP0340/challenge"
                                           (cat (subseq sig64 0 32) pubkey32 msg32)))
                             (n)))
                     (sg (secp:secp-mul-point s (secp:secp-generator)))
                     (ep (secp:secp-mul-point (mod (- (n) e) (n)) pt))
                     (rr (secp:secp-add-points sg ep)))
                (and (not (infp rr)) (evenp (pty rr)) (= (ptx rr) r)))))))
    (error () nil)))

(defun schnorr-sign (privkey-int msg32 &optional (aux (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
  "BIP-340 sign. Returns a 64-byte signature. (Mostly for tests.)"
  (secp:secp-init)
  (let* ((dp privkey-int)
         (pt (secp:secp-mul-point dp (secp:secp-generator)))
         (d (if (evenp (pty pt)) dp (- (n) dp)))
         (px (secp:int-to-bytes32 (ptx pt)))
         (tt (logxor d (secp:bytes-to-int (tagged-hash "BIP0340/aux" aux))))
         (rand (tagged-hash "BIP0340/nonce" (cat (secp:int-to-bytes32 tt) px msg32)))
         (k0 (mod (secp:bytes-to-int rand) (n))))
    (when (zerop k0) (error "schnorr-sign: k=0"))
    (let* ((rpt (secp:secp-mul-point k0 (secp:secp-generator)))
           (k (if (evenp (pty rpt)) k0 (- (n) k0)))
           (rx (secp:int-to-bytes32 (ptx rpt)))
           (e (mod (secp:bytes-to-int (tagged-hash "BIP0340/challenge" (cat rx px msg32))) (n)))
           (sig-s (secp:int-to-bytes32 (mod (+ k (* e d)) (n)))))
      (cat rx sig-s))))

;;;; src/encoding.lisp
;;;;
;;;; Address/key text encodings: Base58Check (legacy P2PKH, WIF, BIP32 xprv/xpub) and
;;;; Bech32 / Bech32m (BIP173/BIP350 — native segwit P2WPKH/P2WSH and taproot P2TR).
;;;; Pure ANSI-CL; checksums via wire's double-SHA256.

(defpackage #:cl-consensus.encoding
  (:use #:cl)
  (:nicknames #:btc-encoding)
  (:local-nicknames (#:w #:cl-consensus.wire))
  (:export
   #:base58-encode #:base58-decode #:base58check-encode #:base58check-decode
   #:bech32-encode #:bech32-decode #:segwit-encode #:segwit-decode
   #:encode-p2pkh #:encode-p2sh #:encode-p2wpkh #:encode-p2wsh #:encode-p2tr))

(in-package #:cl-consensus.encoding)

;;; ----------------------------------------------------------------------------
;;; Base58 / Base58Check
;;; ----------------------------------------------------------------------------

(defparameter +b58+ "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(defun base58-encode (bytes)
  "Base58-encode a byte vector (big-endian integer, leading zero bytes -> '1's)."
  (let ((n (reduce (lambda (acc b) (+ (* acc 256) b)) bytes :initial-value 0))
        (out '()))
    (loop while (plusp n) do
      (multiple-value-bind (q r) (floor n 58)
        (push (char +b58+ r) out) (setf n q)))
    (loop for b across bytes while (zerop b) do (push (char +b58+ 0) out))
    (coerce out 'string)))

(defun base58-decode (str)
  "Decode a Base58 string back to a byte vector."
  (let ((n 0) (zeros 0) (seen nil))
    (loop for ch across str
          for v = (position ch +b58+)
          do (unless v (error "bad base58 char ~c" ch))
             (when (and (not seen) (zerop v)) (incf zeros))
             (when (plusp v) (setf seen t))
             (setf n (+ (* n 58) v)))
    (let ((body '()))
      (loop while (plusp n) do (multiple-value-bind (q r) (floor n 256)
                                 (push r body) (setf n q)))
      (let ((vec (make-array (+ zeros (length body)) :element-type '(unsigned-byte 8)
                             :initial-element 0)))
        (loop for b in body for i from zeros do (setf (aref vec i) b))
        vec))))

(defun base58check-encode (payload)
  "Base58Check: append the 4-byte double-SHA256 checksum, then Base58-encode."
  (let* ((p (coerce payload '(vector (unsigned-byte 8))))
         (chk (subseq (w:hash256 p) 0 4)))
    (base58-encode (concatenate '(vector (unsigned-byte 8)) p chk))))

(defun base58check-decode (str)
  "Decode + verify a Base58Check string -> the payload bytes (sans checksum)."
  (let* ((raw (base58-decode str)) (n (length raw)))
    (when (< n 4) (error "base58check too short"))
    (let ((payload (subseq raw 0 (- n 4))) (chk (subseq raw (- n 4))))
      (unless (equalp chk (subseq (w:hash256 payload) 0 4))
        (error "base58check checksum mismatch"))
      payload)))

;;; ----------------------------------------------------------------------------
;;; Bech32 / Bech32m  (BIP173 / BIP350)
;;; ----------------------------------------------------------------------------

(defparameter +bech32-charset+ "qpzry9x8gf2tvdw0s3jn54khce6mua7l")
(defparameter +bech32-const+ 1)
(defparameter +bech32m-const+ #x2bc830a3)

(defun %bech32-polymod (values)
  (let ((gen #(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3))
        (chk 1))
    (dolist (v values chk)
      (let ((top (ash chk -25)))
        (setf chk (logxor (ash (logand chk #x1ffffff) 5) v))
        (dotimes (i 5)
          (when (logbitp i top) (setf chk (logxor chk (aref gen i)))))))))

(defun %hrp-expand (hrp)
  (append (loop for c across hrp collect (ash (char-code c) -5))
          (list 0)
          (loop for c across hrp collect (logand (char-code c) 31))))

(defun %bech32-checksum (hrp data const)
  (let* ((vals (append (%hrp-expand hrp) data (list 0 0 0 0 0 0)))
         (pm (logxor (%bech32-polymod vals) const)))
    (loop for i from 0 below 6 collect (logand (ash pm (* -5 (- 5 i))) 31))))

(defun bech32-encode (hrp data &key (const +bech32-const+))
  "Encode 5-bit DATA under HRP with the given checksum constant (bech32 vs bech32m)."
  (let ((full (append data (%bech32-checksum hrp data const))))
    (concatenate 'string hrp "1"
                 (map 'string (lambda (v) (char +bech32-charset+ v)) full))))

(defun bech32-decode (str)
  "Decode a bech32/bech32m string -> (values hrp data const) where CONST identifies the
   variant; signals on a bad checksum/charset."
  (let* ((str (string-downcase str))
         (pos (position #\1 str :from-end t)))
    (unless (and pos (>= pos 1) (<= (+ pos 7) (length str))) (error "bad bech32 layout"))
    (let* ((hrp (subseq str 0 pos))
           (data (loop for i from (1+ pos) below (length str)
                       for v = (position (char str i) +bech32-charset+)
                       do (unless v (error "bad bech32 char")) collect v))
           (pm (logxor (%bech32-polymod (append (%hrp-expand hrp) data)))))
      (let ((const (cond ((= pm +bech32-const+) +bech32-const+)
                         ((= pm +bech32m-const+) +bech32m-const+)
                         (t (error "bad bech32 checksum")))))
        (values hrp (subseq data 0 (- (length data) 6)) const)))))

(defun %convert-bits (data from to pad)
  "Regroup DATA values from FROM-bit groups into TO-bit groups (BIP173)."
  (let ((acc 0) (bits 0) (out '()) (maxv (1- (ash 1 to))))
    (dolist (v data)
      (setf acc (logior (ash acc from) v) bits (+ bits from))
      (loop while (>= bits to) do
        (decf bits to)
        (push (logand (ash acc (- bits)) maxv) out)))
    (when (and pad (plusp bits)) (push (logand (ash acc (- to bits)) maxv) out))
    (nreverse out)))

(defun segwit-encode (hrp witver program)
  "Encode a segwit address: WITVER (0..16) + PROGRAM bytes under HRP.  Witver 0 uses
   bech32; witver >= 1 uses bech32m (BIP350)."
  (let* ((prog5 (%convert-bits (coerce program 'list) 8 5 t))
         (data (cons witver prog5))
         (const (if (zerop witver) +bech32-const+ +bech32m-const+)))
    (bech32-encode hrp data :const const)))

(defun segwit-decode (str &optional (expected-hrp "bc"))
  "Decode a segwit address -> (values witver program-bytes).  Validates the bech32 vs
   bech32m variant against the witness version (BIP350)."
  (multiple-value-bind (hrp data const) (bech32-decode str)
    (unless (string= hrp expected-hrp) (error "wrong hrp ~a" hrp))
    (let* ((witver (first data))
           (program (coerce (%convert-bits (rest data) 5 8 nil) '(vector (unsigned-byte 8)))))
      (unless (<= 0 witver 16) (error "bad witness version"))
      (unless (= const (if (zerop witver) +bech32-const+ +bech32m-const+))
        (error "wrong bech32 variant for witver ~d" witver))
      (values witver program))))

;;; ----------------------------------------------------------------------------
;;; Address constructors (mainnet)
;;; ----------------------------------------------------------------------------

(defparameter *p2pkh-version* #x00)
(defparameter *p2sh-version*  #x05)
(defparameter *bech32-hrp*    "bc")

(defun %pre (version payload)
  (base58check-encode (concatenate '(vector (unsigned-byte 8)) (vector version) payload)))

(defun encode-p2pkh (hash160) (%pre *p2pkh-version* hash160))
(defun encode-p2sh  (hash160) (%pre *p2sh-version* hash160))
(defun encode-p2wpkh (hash160) (segwit-encode *bech32-hrp* 0 hash160))
(defun encode-p2wsh  (sha256)  (segwit-encode *bech32-hrp* 0 sha256))
(defun encode-p2tr   (xonly)   (segwit-encode *bech32-hrp* 1 xonly))

;;;; src/shamir.lisp — Shamir secret sharing over GF(2^8), the SLIP-0039 field.
;;;;
;;;; Two layers live here, both pure sharing math (no serialization/encryption — that
;;;; is slip39.lisp):
;;;;   * a minimal textbook t-of-n:  SHAMIR-SPLIT / SHAMIR-COMBINE (secret at x=0), and
;;;;   * the SLIP-0039 sharing primitives SPLIT-SECRET / RECOVER-SECRET, which reserve
;;;;     x=255 for the secret and x=254 for a 4-byte HMAC "digest" share so a wrong or
;;;;     corrupt combination is detected rather than silently returning garbage.
;;;;
;;;; GF(2^8) uses the AES reduction polynomial x^8+x^4+x^3+x+1 (0x11b) with generator
;;;; (x+1)=3 — identical tables to the SLIP-0039 reference, so the interpolation matches
;;;; byte-for-byte.

(defpackage #:cl-consensus.shamir
  (:use #:common-lisp)
  (:local-nicknames (#:ic #:ironclad))
  (:export #:gf-mul #:gf-div #:interpolate
           #:split-secret #:recover-secret #:+digest-length+
           #:+digest-index+ #:+secret-index+ #:+max-share-count+
           #:shamir-split #:shamir-combine #:random-bytes #:shamir-error))

(in-package #:cl-consensus.shamir)

(define-condition shamir-error (error)
  ((msg :initarg :msg :reader shamir-error-msg))
  (:report (lambda (c s) (format s "shamir: ~a" (shamir-error-msg c)))))
(defun serr (fmt &rest args) (error 'shamir-error :msg (apply #'format nil fmt args)))

(deftype u8 () '(unsigned-byte 8))
(deftype u8vec () '(simple-array (unsigned-byte 8) (*)))
(defun u8vec (n &optional (init 0)) (make-array n :element-type 'u8 :initial-element init))
(defun as-u8vec (seq) (coerce seq 'u8vec))

;;; ---- GF(2^8): exp/log tables (generator x+1, reduction 0x11b) ----------------------

(defparameter *exp* (make-array 255 :element-type '(unsigned-byte 16)))
(defparameter *log* (make-array 256 :element-type '(unsigned-byte 16)))
(let ((poly 1))
  (dotimes (i 255)
    (setf (aref *exp* i) poly
          (aref *log* poly) i)
    ;; multiply poly by (x+1): poly<<1 XOR poly, then reduce by 0x11b
    (setf poly (logxor (ash poly 1) poly))
    (when (logtest poly #x100) (setf poly (logxor poly #x11b)))))

(declaim (inline gf-mul))
(defun gf-mul (a b)
  (if (or (zerop a) (zerop b)) 0
      (aref *exp* (mod (+ (aref *log* a) (aref *log* b)) 255))))

(defun gf-div (a b)                     ; a / b  (b must be nonzero)
  (when (zerop b) (serr "GF division by zero"))
  (if (zerop a) 0
      (aref *exp* (mod (- (+ (aref *log* a) 255) (aref *log* b)) 255))))

;;; ---- Lagrange interpolation over GF(2^8), byte-wise -------------------------------

(defun interpolate (shares x)
  "SHARES is a list of (index . y-bytes), all y the same length, indices distinct.
   Return the y-vector of the unique polynomial through them evaluated at X."
  (let* ((len (length (cdr (first shares))))
         (out (u8vec len)))
    (dolist (si shares out)
      (let ((xi (car si)) (yi (cdr si)) (coef 1))
        ;; Lagrange basis at X for point i: prod_{j/=i} (X xor xj) / (xi xor xj)
        (dolist (sj shares)
          (let ((xj (car sj)))
            (unless (= xi xj)
              (setf coef (gf-div (gf-mul coef (logxor x xj)) (logxor xi xj))))))
        (dotimes (k len)
          (setf (aref out k) (logxor (aref out k) (gf-mul coef (aref yi k)))))))))

;;; ---- SLIP-0039 sharing primitives (digest-checked) -------------------------------

(defparameter +digest-length+ 4)
(defparameter +digest-index+ 254)
(defparameter +secret-index+ 255)
(defparameter +max-share-count+ 16)

(defun random-bytes (n)
  "N cryptographically-random bytes: the OS CSPRNG, ironclad Fortuna as fallback."
  (handler-case
      (with-open-file (f "/dev/urandom" :element-type 'u8 :if-does-not-exist :error)
        (let ((b (u8vec n))) (read-sequence b f) b))
    (error () (ic:random-data n (ic:make-prng :fortuna)))))

(defun create-digest (random-data shared-secret)
  "First 4 bytes of HMAC-SHA256(key=RANDOM-DATA, msg=SHARED-SECRET)."
  (let ((mac (ic:make-mac :hmac (as-u8vec random-data) :sha256)))
    (ic:update-mac mac (as-u8vec shared-secret))
    (subseq (ic:produce-mac mac) 0 +digest-length+)))

(defun split-secret (threshold count secret)
  "Split SECRET (bytes) into COUNT shares, any THRESHOLD of which recover it.
   Returns a list of (index . share-bytes) with index in 0..COUNT-1."
  (let ((secret (as-u8vec secret)))
    (when (or (< threshold 1) (< count threshold) (> count +max-share-count+))
      (serr "invalid threshold/count ~d-of-~d" threshold count))
    (if (= threshold 1)
        (loop for i below count collect (cons i (copy-seq secret)))
        (let* ((n (length secret))
               (rlen (- threshold 2))
               (randoms (loop for i below rlen collect (cons i (random-bytes n))))
               (rand-part (random-bytes (- n +digest-length+)))
               (digest-share (concatenate 'u8vec (create-digest rand-part secret) rand-part))
               (base (append randoms
                             (list (cons +digest-index+ digest-share)
                                   (cons +secret-index+ secret)))))
          (append randoms
                  (loop for i from rlen below count
                        collect (cons i (interpolate base i))))))))

(defun recover-secret (threshold shares)
  "Recover the secret from >= THRESHOLD (index . bytes) SHARES; signal on digest mismatch."
  (if (= threshold 1)
      (copy-seq (cdr (first shares)))
      (let* ((secret (interpolate shares +secret-index+))
             (digest-share (interpolate shares +digest-index+))
             (digest (subseq digest-share 0 +digest-length+))
             (rand-part (subseq digest-share +digest-length+)))
        (unless (equalp digest (create-digest rand-part secret))
          (serr "invalid digest — shares are wrong, mismatched, or corrupt"))
        secret)))

;;; ---- Minimal textbook t-of-n (secret at x=0) — standalone use --------------------

(defun shamir-split (secret threshold count)
  "Plain Shamir t-of-n over GF(2^8): SECRET at x=0, shares at x=1..COUNT.
   Returns (index . bytes) with index 1..COUNT.  (No digest — see SPLIT-SECRET for that.)"
  (let* ((secret (as-u8vec secret))
         (n (length secret)))
    (when (or (< threshold 1) (< count threshold) (> count 255))
      (serr "invalid threshold/count ~d-of-~d" threshold count))
    ;; one random degree-(threshold-1) polynomial per byte, constant term = secret byte
    (let ((coeffs (loop for k below n
                        collect (concatenate 'u8vec (vector (aref secret k))
                                             (random-bytes (1- threshold))))))
      (loop for x from 1 to count
            collect (cons x (let ((y (u8vec n)))
                              (dotimes (k n y)
                                (let ((acc 0) (poly (nth k coeffs)))
                                  (loop for c across (reverse poly)
                                        do (setf acc (logxor (gf-mul acc x) c)))
                                  (setf (aref y k) acc)))))))))

(defun shamir-combine (shares)
  "Recover the x=0 secret from >= threshold (index . bytes) SHARES of SHAMIR-SPLIT."
  (interpolate shares 0))

;;;; utxo-disk.lisp — disk-backed UTXO store (Core-style: mmap'd open-addressing
;;;; slot table for the committed set + OS page cache as the read cache; an
;;;; in-RAM staging buffer is the write-back layer, flushed to the mmap at each
;;;; checkpoint with an atomic marker so the on-disk set is always consistent at
;;;; a verified height and restart is instant.
;;;;
;;;; This file implements only the low-level mmap slot table (UDB): fixed 128-byte
;;;; open-addressing slots with inline coins (rare oversized scriptPubKeys spill
;;;; to an append-only overflow file).  The staging/flush/marker layer and the
;;;; utxo-set API live above it.

;;; Coin-agnostic: operates on raw fields (value/height/coinbase/script) so it
;;; loads BEFORE utxo.lisp with no dependency cycle; utxo.lisp wraps these into
;;; COIN structs and layers staging/flush on top.
(defpackage #:cl-consensus.utxo-disk
  (:use #:cl)
  (:export #:open-udb #:close-udb #:udb-put #:udb-get #:udb-del
           #:udb-count #:udb-capacity #:udb-map-slots #:udb-sync #:udb-ovf-end))
(in-package #:cl-consensus.utxo-disk)

(defconstant +slot-bytes+ 128)
(defconstant +key-off+ 16)              ; 36-byte outpoint key (txid32 + u32 index)
(defconstant +script-off+ 52)           ; inline script region
(defconstant +script-inline-max+ 76)    ; 52 + 76 = 128
;; state byte values
(defconstant +empty+ 0) (defconstant +inline+ 1) (defconstant +tomb+ 2) (defconstant +overflow+ 3)

(defstruct udb
  fd sap capacity (count 0)
  ovf-stream                            ; append file for oversized scripts
  (ovf-end 0) (lock-path nil))

(defun %pid-alive-p (pid) (and (integerp pid) (probe-file (format nil "/proc/~d/" pid))))

(defun udb-acquire-lock (path)
  "Exclusive PID lock-file at PATH.lock — prevents two processes mapping the same
   udb MAP_SHARED (which races and corrupts).  Steals a stale lock whose owner is
   dead.  (flock isn't available in this SBCL build; a PID file is portable.)"
  (let ((lp (concatenate 'string (namestring path) ".lock")))
    (when (probe-file lp)
      (let ((owner (ignore-errors (with-open-file (s lp) (read s nil nil)))))
        (if (%pid-alive-p owner)
            (error "udb ~a is locked by live process ~a" path owner)
            (ignore-errors (delete-file lp)))))    ; stale owner: steal
    (with-open-file (s lp :direction :output :if-exists :error :if-does-not-exist :create)
      (princ (sb-posix:getpid) s))
    lp))

(declaim (inline slot-sap u64-at set-u64 u32-at set-u32 u16-at set-u16 u8-at set-u8))
(defun u8-at  (sap off) (sb-sys:sap-ref-8 sap off))
(defun set-u8 (sap off v) (setf (sb-sys:sap-ref-8 sap off) v))
(defun u16-at (sap off) (sb-sys:sap-ref-16 sap off))
(defun set-u16 (sap off v) (setf (sb-sys:sap-ref-16 sap off) v))
(defun u32-at (sap off) (sb-sys:sap-ref-32 sap off))
(defun set-u32 (sap off v) (setf (sb-sys:sap-ref-32 sap off) v))
(defun u64-at (sap off) (sb-sys:sap-ref-64 sap off))
(defun set-u64 (sap off v) (setf (sb-sys:sap-ref-64 sap off) v))

(defun outpoint-hash (txid index capacity)
  "64-bit-ish hash of the outpoint folded into [0,capacity).  txids are already
   uniform, so the low 8 bytes make a fine hash."
  (declare (type (simple-array (unsigned-byte 8) (*)) txid))
  (let ((h (logxor (the (unsigned-byte 64)
                        (logior (aref txid 0) (ash (aref txid 1) 8) (ash (aref txid 2) 16) (ash (aref txid 3) 24)
                                (ash (aref txid 4) 32) (ash (aref txid 5) 40) (ash (aref txid 6) 48) (ash (aref txid 7) 56)))
                   (* (1+ index) 1099511628211))))      ; mix the index (FNV prime)
    (mod (logand h #xFFFFFFFFFFFFFFFF) capacity)))

(defun key-matches-p (sap slot-base txid index)
  (declare (type (simple-array (unsigned-byte 8) (*)) txid))
  (and (= index (u32-at sap (+ slot-base +key-off+ 32)))
       (loop for i below 32 always (= (aref txid i) (u8-at sap (+ slot-base +key-off+ i))))))

(defun write-key (sap slot-base txid index)
  (declare (type (simple-array (unsigned-byte 8) (*)) txid))
  (dotimes (i 32) (set-u8 sap (+ slot-base +key-off+ i) (aref txid i)))
  (set-u32 sap (+ slot-base +key-off+ 32) index))

(defun open-udb (path capacity)
  "Open/create the mmap slot table at PATH sized for CAPACITY slots (a sparse
   file of CAPACITY*128 bytes).  OVERFLOW file is PATH.ovf."
  (let* ((lock (udb-acquire-lock path))      ; signals if another live process holds it
         (bytes (* capacity +slot-bytes+))
         (fd (sb-posix:open path (logior sb-posix:o-rdwr sb-posix:o-creat) #o644)))
    (sb-posix:ftruncate fd bytes)
    (let ((sap (sb-posix:mmap nil bytes (logior sb-posix:prot-read sb-posix:prot-write)
                              sb-posix:map-shared fd 0))
          (ovf-path (concatenate 'string (namestring path) ".ovf")))
      (let ((ostream (open ovf-path :direction :io :element-type '(unsigned-byte 8)
                                    :if-exists :overwrite :if-does-not-exist :create)))
        (make-udb :fd fd :sap sap :capacity capacity :ovf-stream ostream
                  :ovf-end (file-length ostream) :lock-path lock)))))

(defun close-udb (db)
  (sb-posix:munmap (udb-sap db) (* (udb-capacity db) +slot-bytes+))
  (sb-posix:close (udb-fd db))
  (when (udb-lock-path db) (ignore-errors (delete-file (udb-lock-path db))))
  (close (udb-ovf-stream db)))

(defun udb-sync (db)
  (sb-posix:msync (udb-sap db) (* (udb-capacity db) +slot-bytes+) sb-posix:ms-sync)
  (finish-output (udb-ovf-stream db)))

(defun write-overflow (db script)
  "Append SCRIPT to the overflow file, return its offset."
  (let ((s (udb-ovf-stream db)) (off (udb-ovf-end db)))
    (file-position s off)
    (let ((w (make-array 4 :element-type '(unsigned-byte 8))))
      (dotimes (i 4) (setf (aref w i) (ldb (byte 8 (* 8 i)) (length script))))
      (write-sequence w s))
    (write-sequence script s)
    (setf (udb-ovf-end db) (+ off 4 (length script)))
    off))

(defun read-overflow (db off)
  (let ((s (udb-ovf-stream db)))
    (file-position s off)
    (let ((w (make-array 4 :element-type '(unsigned-byte 8))))
      (read-sequence w s)
      (let* ((len (logior (aref w 0) (ash (aref w 1) 8) (ash (aref w 2) 16) (ash (aref w 3) 24)))
             (buf (make-array len :element-type '(unsigned-byte 8))))
        (read-sequence buf s) buf))))

(defun store-fields (db slot-base value height cb script)
  "Write a coin's raw fields into the slot (state/value/height/cb/script)."
  (let ((sap (udb-sap db)))
    (set-u8  sap (+ slot-base 1) (if cb 1 0))
    (set-u32 sap (+ slot-base 4) height)
    (set-u64 sap (+ slot-base 8) (logand value #xFFFFFFFFFFFFFFFF))
    (cond
      ((<= (length script) +script-inline-max+)
       (set-u8  sap slot-base +inline+)
       (set-u16 sap (+ slot-base 2) (length script))
       (dotimes (i (length script)) (set-u8 sap (+ slot-base +script-off+ i) (aref script i))))
      (t
       (set-u8  sap slot-base +overflow+)
       (set-u64 sap (+ slot-base +script-off+) (write-overflow db script))))))

(defun load-fields (db slot-base)
  "Return (values value height coinbase-p script) for the coin in this slot."
  (let* ((sap (udb-sap db)) (state (u8-at sap slot-base))
         (cb (= 1 (u8-at sap (+ slot-base 1))))
         (height (u32-at sap (+ slot-base 4)))
         (value (u64-at sap (+ slot-base 8)))
         (script (if (= state +overflow+)
                     (read-overflow db (u64-at sap (+ slot-base +script-off+)))
                     (let* ((len (u16-at sap (+ slot-base 2)))
                            (s (make-array len :element-type '(unsigned-byte 8))))
                       (dotimes (i len s) (setf (aref s i) (u8-at sap (+ slot-base +script-off+ i))))))))
    (values value height cb script)))

(defun udb-get (db txid index)
  "Return (values found value height coinbase-p script)."
  (let* ((cap (udb-capacity db)) (sap (udb-sap db))
         (i (outpoint-hash txid index cap)))
    (loop
      (let* ((base (* i +slot-bytes+)) (state (u8-at sap base)))
        (cond
          ((= state +empty+) (return (values nil 0 0 nil nil)))
          ((and (/= state +tomb+) (key-matches-p sap base txid index))
           (multiple-value-bind (v h cb s) (load-fields db base) (return (values t v h cb s))))
          (t (setf i (mod (1+ i) cap))))))))

(defun udb-put (db txid index value height cb script)
  "Insert the coin.  Reuses the first tombstone/empty slot; overwrites if the
   key is already present (idempotent re-apply)."
  (let* ((cap (udb-capacity db)) (sap (udb-sap db))
         (i (outpoint-hash txid index cap)) (first-tomb -1))
    (loop
      (let* ((base (* i +slot-bytes+)) (state (u8-at sap base)))
        (cond
          ((= state +empty+)
           (let ((slot (if (>= first-tomb 0) first-tomb base)))
             (write-key sap slot txid index) (store-fields db slot value height cb script)
             (incf (udb-count db)) (return)))
          ((= state +tomb+) (when (< first-tomb 0) (setf first-tomb base))
                            (setf i (mod (1+ i) cap)))
          ((key-matches-p sap base txid index)            ; already present: overwrite
           (store-fields db base value height cb script) (return))
          (t (setf i (mod (1+ i) cap))))))))

(defun udb-del (db txid index)
  "Remove the outpoint; return (values found value height coinbase-p script)."
  (let* ((cap (udb-capacity db)) (sap (udb-sap db))
         (i (outpoint-hash txid index cap)))
    (loop
      (let* ((base (* i +slot-bytes+)) (state (u8-at sap base)))
        (cond
          ((= state +empty+) (return (values nil 0 0 nil nil)))
          ((and (/= state +tomb+) (key-matches-p sap base txid index))
           (multiple-value-bind (v h cb s) (load-fields db base)
             (set-u8 sap base +tomb+) (decf (udb-count db)) (return (values t v h cb s))))
          (t (setf i (mod (1+ i) cap))))))))

(defun udb-map-slots (db fn)
  "Call (FN txid-bytes index value height coinbase-p script) for every live slot."
  (let ((sap (udb-sap db)))
    (dotimes (i (udb-capacity db))
      (let ((base (* i +slot-bytes+)))
        (when (let ((s (u8-at sap base))) (or (= s +inline+) (= s +overflow+)))
          (let ((txid (make-array 32 :element-type '(unsigned-byte 8))))
            (dotimes (k 32) (setf (aref txid k) (u8-at sap (+ base +key-off+ k))))
            (multiple-value-bind (v h cb s) (load-fields db base)
              (funcall fn txid (u32-at sap (+ base +key-off+ 32)) v h cb s))))))))

;;;; utxo-pagetree.lisp — pagetree-backed UTXO store (alternative to the mmap udb).
;;;;
;;;; A second disk backend for the UTXO set, living BEHIND the same utxo.lisp
;;;; interface as the in-RAM map and the mmap "udb".  It stores coins in a
;;;; pagetree copy-on-write B+tree (pure CL, no mmap/sb-posix), which is the
;;;; modus-portable, Pi-friendly, compact store described in pagetree/PLAN.md.
;;;;
;;;; This backend deliberately relies ONLY on the pagetree public API
;;;; (open-store/close-store, with-write-txn/with-read-txn, tput/tget/tdel,
;;;; tcursor/cursor-first/cursor-next/cursor-key/cursor-value) plus standard CL.
;;;; The udb backend (utxo-disk.lisp) is left untouched so the two can be A/B'd.
;;;;
;;;; Layout on disk:
;;;;   key   = outpoint:  txid(32 bytes, internal order) || index(u32 little-endian)
;;;;           => 36 bytes, byte-comparable, identical to the udb key layout.
;;;;   value = COMPACT coin:
;;;;             varint( (height << 1) | (coinbase ? 1 : 0) )
;;;;             varint( value-in-satoshis )                 ; unsigned, fits 64-bit
;;;;             scriptPubKey bytes                          ; length = rest of value
;;;;   meta key (a reserved 1-byte key #(0), shorter than any 36-byte outpoint so
;;;;   it never collides with a real coin) holds the running (height,total,count):
;;;;             u32 height || u64 total-value || u64 count
;;;;
;;;; The compact varint coin encoding is the space win over the udb's fixed
;;;; 128-byte slots; combined with the B+tree's lack of hash-table load-factor
;;;; slack it is several times smaller on disk.

(defpackage #:cl-consensus.utxo-pagetree
  (:use #:cl)
  (:local-nicknames (#:pt #:pagetree))
  (:export
   #:open-pagetree-utxo
   ;; raw helpers reused by utxo.lisp's dispatcher
   #:ptu #:make-ptu #:ptu-store #:ptu-height #:ptu-total #:ptu-count #:ptu-path
   #:ptu-get #:ptu-put #:ptu-del #:ptu-flush #:ptu-close #:ptu-map-coins
   #:encode-coin #:decode-coin #:encode-key))
(in-package #:cl-consensus.utxo-pagetree)

;;; ----------------------------------------------------------------------------
;;; Varint codec (LEB128-style, base-128, little-endian groups) — self-contained
;;; so the backend stays pure ANSI CL and independent of the wire package.
;;; ----------------------------------------------------------------------------

(defun put-varint (out n)
  "Append the LEB128 encoding of non-negative integer N to adjustable byte vector OUT."
  (declare (type (integer 0) n))
  (loop
    (let ((b (logand n #x7f)))
      (setf n (ash n -7))
      (if (zerop n)
          (progn (vector-push-extend b out) (return))
          (vector-push-extend (logior b #x80) out)))))

(defun get-varint (vec pos)
  "Decode a LEB128 integer from byte VEC starting at POS.
   Returns (values value next-pos)."
  (let ((result 0) (shift 0) (i pos))
    (loop
      (let ((b (aref vec i)))
        (incf i)
        (setf result (logior result (ash (logand b #x7f) shift)))
        (when (zerop (logand b #x80)) (return))
        (incf shift 7)))
    (values result i)))

;;; ----------------------------------------------------------------------------
;;; Outpoint key codec: txid(32) || index(u32 LE) = 36 bytes.
;;; ----------------------------------------------------------------------------

(defun encode-key (txid index)
  "36-byte outpoint key: the 32 txid bytes followed by the index as u32 LE."
  (declare (type (simple-array (unsigned-byte 8) (*)) txid))
  (let ((k (make-array 36 :element-type '(unsigned-byte 8))))
    (dotimes (i 32) (setf (aref k i) (aref txid i)))
    (dotimes (i 4) (setf (aref k (+ 32 i)) (logand (ash index (* -8 i)) #xff)))
    k))

(declaim (inline key-txid key-index))
(defun key-txid (k)
  "The 32-byte txid out of a 36-byte outpoint key (fresh copy)."
  (subseq k 0 32))
(defun key-index (k)
  "The u32 LE index out of a 36-byte outpoint key."
  (logior (aref k 32) (ash (aref k 33) 8) (ash (aref k 34) 16) (ash (aref k 35) 24)))

;;; ----------------------------------------------------------------------------
;;; Compact coin value codec.
;;; ----------------------------------------------------------------------------

(defun encode-coin (value height coinbase-p script)
  "Compact coin bytes: varint(height<<1|cb) || varint(value) || script."
  (declare (type (simple-array (unsigned-byte 8) (*)) script))
  (let ((out (make-array 16 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0)))
    (put-varint out (logior (ash height 1) (if coinbase-p 1 0)))
    (put-varint out value)
    (loop for b across script do (vector-push-extend b out))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun decode-coin (vec)
  "Decode compact coin bytes.  Returns (values value height coinbase-p script)."
  (multiple-value-bind (hc pos) (get-varint vec 0)
    (multiple-value-bind (value pos2) (get-varint vec pos)
      (let ((script (subseq vec pos2)))
        (values value (ash hc -1) (= 1 (logand hc 1)) script)))))

;;; ----------------------------------------------------------------------------
;;; The backend handle.
;;; ----------------------------------------------------------------------------

(defstruct ptu
  store                ; the open pagetree store
  path                 ; file path (nil => in-RAM mem store, for tests)
  (height 0)           ; height of the last committed flush
  (total 0)            ; running total value (satoshis)
  (count 0)            ; running live coin count
  page-size cache-bytes)

(defparameter +meta-key+ (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)
  "Reserved 1-byte key holding (height,total,count).  Shorter than any 36-byte
   outpoint key, so it can never collide with a real coin and always sorts first.")

(defun %read-meta (store)
  "Load (values height total count) from the meta key, or (0 0 0) if absent."
  (pt:with-read-txn (txn store)
    (let ((v (pt:tget txn +meta-key+)))
      (if (and v (>= (length v) 20))
          (values (logior (aref v 0) (ash (aref v 1) 8) (ash (aref v 2) 16) (ash (aref v 3) 24))
                  (let ((acc 0)) (dotimes (i 8 acc) (setf acc (logior acc (ash (aref v (+ 4 i)) (* 8 i))))))
                  (let ((acc 0)) (dotimes (i 8 acc) (setf acc (logior acc (ash (aref v (+ 12 i)) (* 8 i)))))))
          (values 0 0 0)))))

(defun %write-meta (txn height total count)
  (let ((v (make-array 20 :element-type '(unsigned-byte 8))))
    (dotimes (i 4) (setf (aref v i) (logand (ash height (* -8 i)) #xff)))
    (dotimes (i 8) (setf (aref v (+ 4 i)) (logand (ash total (* -8 i)) #xff)))
    (dotimes (i 8) (setf (aref v (+ 12 i)) (logand (ash count (* -8 i)) #xff)))
    (pt:tput txn +meta-key+ v)))

;;; ----------------------------------------------------------------------------
;;; Open / close.
;;; ----------------------------------------------------------------------------

(defun open-pagetree-utxo (path &key page-size cache-bytes)
  "Open/create a pagetree-backed UTXO store at PATH (NIL => in-RAM mem store).
   Returns a PTU handle; read its committed height with PTU-HEIGHT."
  (let ((store (pt:open-store path :page-size page-size :cache-bytes cache-bytes
                                   :create t)))
    (multiple-value-bind (height total count) (%read-meta store)
      (make-ptu :store store :path path :height height :total total :count count
                :page-size page-size :cache-bytes cache-bytes))))

(defun ptu-close (ptu)
  (when (ptu-store ptu)
    (pt:close-store (ptu-store ptu))
    (setf (ptu-store ptu) nil)))

;;; ----------------------------------------------------------------------------
;;; Point ops.  These open a short-lived txn each; the utxo.lisp layer batches
;;; through its own staging buffer so the hot path never hits these per-coin.
;;; They are kept simple/correct and are exercised by the digest/recovery oracle.
;;; ----------------------------------------------------------------------------

(defun ptu-get (ptu txid index)
  "Return (values found value height coinbase-p script) for an outpoint."
  (pt:with-read-txn (txn (ptu-store ptu))
    (let ((v (pt:tget txn (encode-key txid index))))
      (if v
          (multiple-value-bind (value h cb s) (decode-coin v)
            (values t value h cb s))
          (values nil 0 0 nil nil)))))

(defun ptu-put (ptu txn txid index value height cb script)
  "Insert/overwrite a coin within an open write TXN (no count/total bookkeeping;
   the caller keeps those running, mirroring the udb backend)."
  (pt:tput txn (encode-key txid index) (encode-coin value height cb script)))

(defun ptu-del (ptu txn txid index)
  (pt:tdel txn (encode-key txid index)))

;;; ----------------------------------------------------------------------------
;;; Batch flush: apply a staging hash-table (key (txid . index) -> coin | :SPENT)
;;; as ONE pagetree write txn (CoW + atomic meta swap = crash-safe, no WAL),
;;; then commit the (height,total,count) meta in the SAME txn.
;;; ----------------------------------------------------------------------------

(defun %key< (a b)
  "Byte-lexicographic compare on encoded outpoint keys — the SAME order the
   B+tree uses, so a batch sorted by this can be applied with :sorted t."
  (declare (type (simple-array (unsigned-byte 8) (*)) a b))
  (let ((m (min (length a) (length b))))
    (dotimes (i m)
      (let ((x (aref a i)) (y (aref b i)))
        (when (< x y) (return-from %key< t))
        (when (> x y) (return-from %key< nil))))
    (< (length a) (length b))))

(defun ptu-flush (ptu staging height total count
                  &key coin-value coin-height coin-coinbase-p coin-script)
  "Apply STAGING to the store as ONE atomic batched write txn — sorted bulk apply
   (~7-20x faster than per-key), then commit the (height,total,count) meta in the
   SAME txn (CoW + atomic meta swap = crash-safe, no WAL).  COIN-* are accessors
   so this stays decoupled from the COIN struct in utxo.lisp."
  (let ((ops (make-array (hash-table-count staging))) (i 0))
    (maphash
     (lambda (key v)
       (let ((ek (encode-key (car key) (cdr key))))
         (setf (aref ops i)
               (cons ek (if (eq v :spent)
                            :delete
                            (encode-coin (funcall coin-value v) (funcall coin-height v)
                                         (funcall coin-coinbase-p v) (funcall coin-script v)))))
         (incf i)))
     staging)
    (sort ops #'%key< :key #'car)        ; staging keys are unique (one entry per outpoint)
    (pt:with-write-txn (txn (ptu-store ptu))
      (pt:tapply-batch txn ops :sorted t)
      (%write-meta txn height total count)))
  (setf (ptu-height ptu) height (ptu-total ptu) total (ptu-count ptu) count)
  height)

;;; ----------------------------------------------------------------------------
;;; Ordered scan over all committed coins (skips the reserved meta key).
;;; Calls (FN txid-bytes index value height coinbase-p script) for each live coin.
;;; This is what the set-digest walks.
;;; ----------------------------------------------------------------------------

(defun ptu-map-coins (ptu fn)
  (pt:with-read-txn (txn (ptu-store ptu))
    (let ((cur (pt:tcursor txn)))
      (when (pt:cursor-first cur)
        (loop
          (let ((k (pt:cursor-key cur)))
            (when (= (length k) 36)        ; a real 36-byte outpoint (skip meta key)
              (multiple-value-bind (value h cb s) (decode-coin (pt:cursor-value cur))
                (funcall fn (key-txid k) (key-index k) value h cb s))))
          (unless (pt:cursor-next cur) (return)))))))

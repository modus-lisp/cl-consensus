;;;; src/blockstore.lisp
;;;;
;;;; Append-only raw-block store, so the node can SERVE blocks (getdata) it has
;;;; already downloaded.  Format is deliberately trivial and crash-tolerant:
;;;;
;;;;   blocks.dat = [u32 LE len][raw block wire bytes] [u32 LE len][raw block bytes] ...
;;;;
;;;; Append-only means a reader (the serving daemon) can stream out a block while a
;;;; writer is appending the next one — the bytes a reader sees never move or change.
;;;; The hash->(offset,len) index lives in RAM, rebuilt by scanning the file at open
;;;; (cheap: read the 4-byte len + 80-byte header per record, hash the header, skip
;;;; the body).  A torn tail record (partial append after a crash) is detected during
;;;; the scan and the file is truncated back to the last whole record.
;;;;
;;;; Pure ANSI-CL stream I/O — no FFI, no mmap.

(defpackage #:cl-consensus.blockstore
  (:use #:cl)
  (:nicknames #:btc-blockstore)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:bt #:bordeaux-threads))
  (:export
   #:block-store #:open-block-store #:close-block-store
   #:store-block #:get-block-bytes #:block-store-has-p
   #:block-store-count #:block-store-path))

(in-package #:cl-consensus.blockstore)

(defstruct (block-store (:constructor %make-block-store))
  path                                  ; pathname of blocks.dat
  stream                                ; open :io binary stream
  (index (make-hash-table :test 'equal)) ; hash-hex -> (cons body-offset len)
  (end 0)                               ; file length in bytes (next append offset)
  (lock (bt:make-lock "block-store")))

;;; --- little-endian u32 helpers on a byte stream ----------------------------

(defun %read-u32-le (stream)
  "Read 4 bytes LE from STREAM, or NIL at clean EOF."
  (let ((b0 (read-byte stream nil :eof)))
    (when (eq b0 :eof) (return-from %read-u32-le nil))
    (let ((b1 (read-byte stream nil :eof))
          (b2 (read-byte stream nil :eof))
          (b3 (read-byte stream nil :eof)))
      (when (or (eq b1 :eof) (eq b2 :eof) (eq b3 :eof))
        (return-from %read-u32-le :torn))   ; partial length field
      (logior b0 (ash b1 8) (ash b2 16) (ash b3 24)))))

(defun %write-u32-le (stream n)
  (write-byte (logand n #xff) stream)
  (write-byte (logand (ash n -8) #xff) stream)
  (write-byte (logand (ash n -16) #xff) stream)
  (write-byte (logand (ash n -24) #xff) stream))

;;; --- index scan -------------------------------------------------------------

(defun %scan-index (store)
  "Rebuild the in-RAM index by walking the file from the start.  Each record is a
   u32 LE length followed by that many raw block bytes; we read just the 80-byte
   header to derive the block hash, then skip the body.  A torn tail (short read)
   truncates the file back to the last whole record."
  (let ((s (block-store-stream store))
        (index (block-store-index store))
        (good-end 0))
    (clrhash index)
    (file-position s 0)
    (loop
      (let* ((rec-start (file-position s))
             (len (%read-u32-le s)))
        (cond
          ((null len) (return))                 ; clean EOF
          ((eq len :torn) (return))             ; partial length -> stop
          ((< len 80) (return))                 ; impossible: header alone is 80
          (t
           (let ((hdr (make-array 80 :element-type '(unsigned-byte 8))))
             (let ((got (read-sequence hdr s)))
               (when (< got 80) (return))       ; torn header -> stop
               (let ((body-offset (+ rec-start 4))
                     (next (+ rec-start 4 len)))
                 ;; ensure the whole body is present before accepting the record
                 (file-position s next)
                 (when (< (file-position s) next) (return)) ; couldn't seek past -> torn
                 (let ((hx (w:hash->hex (w:hash256 hdr))))
                   (setf (gethash hx index) (cons body-offset len)))
                 (setf good-end next))))))))
    ;; truncate any torn tail so a future scan can't mis-parse leftover bytes
    (let ((real (file-length s)))
      (when (> real good-end)
        (finish-output s)
        (ignore-errors (sb-posix:ftruncate (sb-sys:fd-stream-fd s) good-end))))
    (setf (block-store-end store) good-end)
    (file-position s good-end)
    store))

(defun open-block-store (path)
  "Open (creating if needed) the append-only block store at PATH and rebuild its
   index.  Returns a BLOCK-STORE."
  (let ((s (open path :direction :io
                      :element-type '(unsigned-byte 8)
                      :if-exists :overwrite
                      :if-does-not-exist :create)))
    (let ((store (%make-block-store :path (pathname path) :stream s)))
      (%scan-index store)
      store)))

(defun close-block-store (store)
  (bt:with-lock-held ((block-store-lock store))
    (ignore-errors (finish-output (block-store-stream store)))
    (ignore-errors (close (block-store-stream store)))
    (setf (block-store-stream store) nil)))

;;; --- write / read -----------------------------------------------------------

(defun store-block (store raw)
  "Append RAW block wire bytes (must start with the 80-byte header) to STORE,
   keyed by its block hash.  No-op (returns NIL) if already present.  Returns the
   block hash-hex on a fresh store."
  (declare (type (simple-array (unsigned-byte 8) (*)) raw))
  (when (< (length raw) 80)
    (error "store-block: raw block too short (~d bytes)" (length raw)))
  (let ((hx (w:hash->hex (w:hash256 (subseq raw 0 80)))))
    (bt:with-lock-held ((block-store-lock store))
      (when (gethash hx (block-store-index store))
        (return-from store-block nil))
      (let* ((s (block-store-stream store))
             (rec-start (block-store-end store))
             (len (length raw)))
        (file-position s rec-start)
        (%write-u32-le s len)
        (write-sequence raw s)
        (finish-output s)
        (setf (gethash hx (block-store-index store)) (cons (+ rec-start 4) len))
        (setf (block-store-end store) (+ rec-start 4 len))
        hx))))

(defun get-block-bytes (store hash-hex)
  "Return the raw block wire bytes for HASH-HEX, or NIL if not stored."
  (bt:with-lock-held ((block-store-lock store))
    (let ((entry (gethash hash-hex (block-store-index store))))
      (when entry
        (let* ((s (block-store-stream store))
               (offset (car entry))
               (len (cdr entry))
               (buf (make-array len :element-type '(unsigned-byte 8))))
          (file-position s offset)
          (let ((got (read-sequence buf s)))
            (file-position s (block-store-end store)) ; restore append point
            (when (= got len) buf)))))))

(defun block-store-has-p (store hash-hex)
  (bt:with-lock-held ((block-store-lock store))
    (and (gethash hash-hex (block-store-index store)) t)))

(defun block-store-count (store)
  (bt:with-lock-held ((block-store-lock store))
    (hash-table-count (block-store-index store))))

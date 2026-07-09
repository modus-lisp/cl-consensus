;;;; src/blockstore.lisp
;;;;
;;;; Append-only raw-block store, so the node can SERVE blocks (getdata) it has
;;;; already downloaded.  Format is deliberately trivial and crash-tolerant:
;;;;
;;;;   blocks.dat = [u32 LE len][raw block wire bytes] [u32 LE len][raw block bytes] ...
;;;;
;;;; Append-only means a reader (the serving daemon) can stream out a block while a
;;;; writer is appending the next one — the bytes a reader sees never move or change.
;;;; The hash->(offset,len) index lives in RAM.
;;;;
;;;; INDEX PERSISTENCE.  Rebuilding the index by scanning the whole file at open is
;;;; O(blocks) random reads — fine at a few GB, ~40 min once the archive is ~800 GB.
;;;; So the index is mirrored to a sidecar `blocks.dat.idx` of fixed 44-byte records
;;;;   [block hash: 32][body-offset: u64 LE][len: u32 LE]
;;;; written as each block is stored.  At open we load the sidecar (a fast sequential
;;;; read) and then scan blocks.dat only from where the sidecar leaves off.
;;;;
;;;; Crash-safety: the block is written + flushed to blocks.dat BEFORE its sidecar
;;;; entry, so the sidecar can only ever LAG blocks.dat — a crash in between leaves an
;;;; un-indexed tail that open re-scans (and re-appends to the sidecar).  A torn tail
;;;; in either file (partial trailing record, incl. a truncated block body) is detected
;;;; and dropped.  If the sidecar is missing or inconsistent (covers more than
;;;; blocks.dat holds), open falls back to a full scan and rewrites it.  (Writes use
;;;; FINISH-OUTPUT — OS-buffer durable, so this survives a process crash; power-loss
;;;; reordering is caught by the same open-time torn-tail / covered>len self-healing.)
;;;;
;;;; Pure ANSI-CL stream I/O — no FFI, no mmap.

(defpackage #:cl-consensus.blockstore
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:bt #:bordeaux-threads))
  (:export
   #:block-store #:open-block-store #:close-block-store
   #:store-block #:get-block-bytes #:block-store-has-p
   #:block-store-count #:block-store-path #:rebuild-index #:prune-to))

(in-package #:cl-consensus.blockstore)

(defstruct (block-store (:constructor %make-block-store))
  path                                  ; pathname of blocks.dat
  stream                                ; open :io binary stream
  (index (make-hash-table :test 'equal)) ; hash-hex -> (cons body-offset len)
  (end 0)                               ; file length in bytes (next append offset)
  idx-path                              ; pathname of the sidecar index (blocks.dat.idx)
  idx-stream                            ; open :io binary stream for the sidecar
  (lock (bt:make-lock "block-store")))

(defconstant +idx-record-len+ 44)       ; 32 (hash) + 8 (offset u64) + 4 (len u32)

;;; --- little-endian integer helpers -----------------------------------------

(defun %read-u32-le (stream)
  "Read 4 bytes LE from STREAM, or NIL at clean EOF, or :TORN on a partial field."
  (let ((b0 (read-byte stream nil :eof)))
    (when (eq b0 :eof) (return-from %read-u32-le nil))
    (let ((b1 (read-byte stream nil :eof))
          (b2 (read-byte stream nil :eof))
          (b3 (read-byte stream nil :eof)))
      (when (or (eq b1 :eof) (eq b2 :eof) (eq b3 :eof))
        (return-from %read-u32-le :torn))
      (logior b0 (ash b1 8) (ash b2 16) (ash b3 24)))))

(defun %write-u32-le (stream n)
  (write-byte (logand n #xff) stream)
  (write-byte (logand (ash n -8) #xff) stream)
  (write-byte (logand (ash n -16) #xff) stream)
  (write-byte (logand (ash n -24) #xff) stream))

(defun %u32-le (buf off)
  (logior (aref buf off) (ash (aref buf (+ off 1)) 8)
          (ash (aref buf (+ off 2)) 16) (ash (aref buf (+ off 3)) 24)))

(defun %u64-le (buf off)
  (let ((n 0)) (dotimes (i 8 n) (setf n (logior n (ash (aref buf (+ off i)) (* 8 i)))))))

;;; --- sidecar index ----------------------------------------------------------

(defun %append-idx-entry (store hash-bytes body-offset len)
  "Append one 44-byte sidecar record (at the idx stream's current — end — position)."
  (let ((s (block-store-idx-stream store))
        (rec (make-array +idx-record-len+ :element-type '(unsigned-byte 8))))
    (replace rec hash-bytes :end1 32)
    (dotimes (i 8) (setf (aref rec (+ 32 i)) (logand (ash body-offset (* -8 i)) #xff)))
    (dotimes (i 4) (setf (aref rec (+ 40 i)) (logand (ash len (* -8 i)) #xff)))
    (write-sequence rec s)
    (finish-output s)))

(defun %reset-sidecar (store)
  "Empty the sidecar and seek to its start (for a full rebuild)."
  (let ((s (block-store-idx-stream store)))
    (finish-output s)
    (ignore-errors (sb-posix:ftruncate (sb-sys:fd-stream-fd s) 0))
    (file-position s 0)))

(defun %load-sidecar (store)
  "Populate the RAM index from whole sidecar records; return the covered-end offset
   in blocks.dat (max body-offset+len), or NIL if the sidecar is empty/absent.  A
   torn trailing record is dropped and the sidecar truncated to the last whole one."
  (let ((s (block-store-idx-stream store))
        (index (block-store-index store))
        (covered 0) (n 0)
        (rec (make-array +idx-record-len+ :element-type '(unsigned-byte 8))))
    (file-position s 0)
    (loop
      (let ((got (read-sequence rec s)))
        (when (< got +idx-record-len+) (return))    ; EOF or torn trailing record
        (let ((off (%u64-le rec 32)) (len (%u32-le rec 40)))
          (setf (gethash (w:hash->hex (subseq rec 0 32)) index) (cons off len))
          (setf covered (max covered (+ off len)))
          (incf n))))
    ;; drop any torn trailing partial record and position for appends at the end
    (let ((good (* n +idx-record-len+)))
      (finish-output s)
      (when (> (file-length s) good)
        (ignore-errors (sb-posix:ftruncate (sb-sys:fd-stream-fd s) good)))
      (file-position s good))
    (when (plusp n) covered)))

;;; --- block index scan -------------------------------------------------------

(defun %scan-blocks (store start write-idx)
  "Index blocks.dat records from byte offset START to EOF: fill the RAM index,
   optionally append each new record to the sidecar (WRITE-IDX), truncate a torn
   tail, and set the store's END (next append offset).  Returns STORE."
  (let ((s (block-store-stream store))
        (index (block-store-index store))
        (good-end start)
        (blen (file-length (block-store-stream store))))
    (file-position s start)
    (loop
      (let* ((rec-start (file-position s))
             (len (%read-u32-le s)))
        (cond
          ((null len) (return))                 ; clean EOF
          ((eq len :torn) (return))             ; partial length field
          ((< len 80) (return))                 ; impossible: header alone is 80
          (t
           (let ((hdr (make-array 80 :element-type '(unsigned-byte 8))))
             (let ((got (read-sequence hdr s)))
               (when (< got 80) (return))       ; torn header
               (let ((body-offset (+ rec-start 4))
                     (next (+ rec-start 4 len)))
                 ;; body not fully present (torn tail) — seeking past EOF SUCCEEDS on
                 ;; an :io stream, so check the length explicitly, don't probe by seek.
                 (when (> next blen) (return))
                 (file-position s next)
                 (let ((hash (w:hash256 hdr)))
                   (setf (gethash (w:hash->hex hash) index) (cons body-offset len))
                   (when write-idx (%append-idx-entry store hash body-offset len)))
                 (setf good-end next))))))))
    ;; truncate any torn tail so a future scan can't mis-parse leftover bytes
    (let ((real (file-length s)))
      (when (> real good-end)
        (finish-output s)
        (ignore-errors (sb-posix:ftruncate (sb-sys:fd-stream-fd s) good-end))))
    (setf (block-store-end store) good-end)
    (file-position s good-end)
    store))

;;; --- open / close -----------------------------------------------------------

(defun open-block-store (path)
  "Open (creating if needed) the append-only block store at PATH and build its index,
   loading the persisted sidecar when present and scanning only the un-indexed tail.
   Returns a BLOCK-STORE."
  (let* ((s (open path :direction :io
                       :element-type '(unsigned-byte 8)
                       :if-exists :overwrite
                       :if-does-not-exist :create))
         (ipath (concatenate 'string (namestring (truename path)) ".idx"))
         (is (open ipath :direction :io
                         :element-type '(unsigned-byte 8)
                         :if-exists :overwrite
                         :if-does-not-exist :create))
         (store (%make-block-store :path (pathname path) :stream s
                                   :idx-path (pathname ipath) :idx-stream is)))
    (let ((covered (%load-sidecar store))
          (blen (file-length s)))
      (cond
        ((and covered (<= covered blen))
         ;; sidecar valid — index only the tail blocks.dat grew past it (usually none)
         (%scan-blocks store covered t))
        (t
         ;; missing or inconsistent (covers more than blocks.dat holds) — full rebuild
         (clrhash (block-store-index store))
         (%reset-sidecar store)
         (%scan-blocks store 0 t))))
    store))

(defun close-block-store (store)
  (bt:with-lock-held ((block-store-lock store))
    (ignore-errors (finish-output (block-store-stream store)))
    (ignore-errors (finish-output (block-store-idx-stream store)))
    (ignore-errors (close (block-store-stream store)))
    (ignore-errors (close (block-store-idx-stream store)))
    (setf (block-store-stream store) nil
          (block-store-idx-stream store) nil)))

(defun rebuild-index (store)
  "Force a full rescan of blocks.dat and rewrite the sidecar from scratch.  For
   recovering from a suspected-bad sidecar without deleting files by hand."
  (bt:with-lock-held ((block-store-lock store))
    (clrhash (block-store-index store))
    (%reset-sidecar store)
    (%scan-blocks store 0 t)
    (block-store-count store)))

;;; --- write / read -----------------------------------------------------------

(defun store-block (store raw)
  "Append RAW block wire bytes (must start with the 80-byte header) to STORE,
   keyed by its block hash.  No-op (returns NIL) if already present.  Returns the
   block hash-hex on a fresh store."
  (declare (type (simple-array (unsigned-byte 8) (*)) raw))
  (when (< (length raw) 80)
    (error "store-block: raw block too short (~d bytes)" (length raw)))
  (let* ((hash (w:hash256 (subseq raw 0 80)))
         (hx (w:hash->hex hash)))
    (bt:with-lock-held ((block-store-lock store))
      (when (gethash hx (block-store-index store))
        (return-from store-block nil))
      (let* ((s (block-store-stream store))
             (rec-start (block-store-end store))
             (len (length raw))
             (body-offset (+ rec-start 4)))
        (file-position s rec-start)
        (%write-u32-le s len)
        (write-sequence raw s)
        (finish-output s)                       ; block flushed BEFORE its index entry
        (setf (gethash hx (block-store-index store)) (cons body-offset len))
        (setf (block-store-end store) (+ rec-start 4 len))
        (%append-idx-entry store hash body-offset len)
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

(defun prune-to (store keep-hashes)
  "Compact STORE, keeping only blocks whose HASH-HEX is in KEEP-HASHES (a list or
   hash-set) — a pruned node keeps just a recent window and discards the rest.  Copies
   the kept blocks to a temp file, atomically renames it over blocks.dat, reopens, and
   rebuilds the in-RAM index + sidecar.  Reclaims the disk of the pruned blocks.
   Returns (values kept-count pruned-count)."
  (bt:with-lock-held ((block-store-lock store))
    (let* ((keep (if (hash-table-p keep-hashes) keep-hashes
                     (let ((h (make-hash-table :test 'equal)))
                       (dolist (k keep-hashes h) (setf (gethash k h) t)))))
           (s (block-store-stream store))
           (tmp (concatenate 'string (namestring (block-store-path store)) ".tmp"))
           (new-index (make-hash-table :test 'equal))
           (ordered '())                        ; (hash-bytes offset len) in FILE order
           (pos 0) (kept 0) (pruned 0))
      (with-open-file (out tmp :direction :output :element-type '(unsigned-byte 8)
                               :if-exists :supersede :if-does-not-exist :create)
        (maphash
         (lambda (hx entry)
           (cond ((gethash hx keep)
                  (let* ((len (cdr entry))
                         (buf (make-array len :element-type '(unsigned-byte 8))))
                    (file-position s (car entry))
                    (read-sequence buf s)
                    (%write-u32-le out len)
                    (write-sequence buf out)
                    (setf (gethash hx new-index) (cons (+ pos 4) len))
                    (push (list (w:hex->hash hx) (+ pos 4) len) ordered)  ; record in write order
                    (incf pos (+ 4 len)) (incf kept)))
                 (t (incf pruned))))
         (block-store-index store))
        (setf ordered (nreverse ordered)))       ; now ascending by file offset
      ;; swap the compacted file in for blocks.dat, then reopen at its new end
      (ignore-errors (finish-output s))
      (close s)
      (sb-posix:rename tmp (namestring (block-store-path store)))
      (setf (block-store-stream store)
            (open (block-store-path store) :direction :io :element-type '(unsigned-byte 8)
                                           :if-exists :overwrite :if-does-not-exist :create)
            (block-store-index store) new-index
            (block-store-end store) pos)
      (file-position (block-store-stream store) pos)
      ;; Rebuild the sidecar IN FILE ORDER so it stays a contiguous prefix of blocks.dat:
      ;; a crash mid-rebuild then leaves a valid prefix [0,covered) that open self-heals
      ;; by re-scanning the tail (rebuilding in hash-table order would strand kept blocks).
      (%reset-sidecar store)
      (dolist (e ordered) (%append-idx-entry store (first e) (second e) (third e)))
      (values kept pruned))))

(defun block-store-count (store)
  (bt:with-lock-held ((block-store-lock store))
    (hash-table-count (block-store-index store))))

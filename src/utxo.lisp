;;;; shared/bitcoind/utxo.lisp
;;;;
;;;; Phase 5a — the UTXO set (chainstate).  Maps each unspent outpoint
;;;; (txid, index) to its coin (value, scriptPubKey, creation height, whether it
;;;; came from a coinbase).  This is what block validation reads to find the
;;;; output a given input spends, and what it mutates as blocks connect/disconnect.
;;;;
;;;; Backend here is an in-memory hash table (correctness-first, per ROADMAP).
;;;; It carries the early chain comfortably; a disk-backed backend replaces it
;;;; once the rules are proven and the set outgrows RAM.


(defpackage #:cl-consensus.utxo
  (:use #:cl)
  (:nicknames #:btc-utxo)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:d #:cl-consensus.utxo-disk))
  (:export
   #:coin #:make-coin #:coin-value #:coin-script #:coin-height #:coin-coinbase-p
   #:utxo-set #:make-utxo-set #:utxo-count #:utxo-set-total-value
   #:utxo-get #:utxo-add #:utxo-spend #:utxo-key #:utxo-digest
   #:save-utxo #:load-utxo
   #:open-disk-utxo #:flush-utxo #:close-utxo #:utxo-disk-p #:+udb-tip-capacity+
   #:prefetch-resolve #:set-prefetch #:clear-prefetch))

(in-package #:cl-consensus.utxo)

(defstruct coin
  value          ; satoshis (int64)
  script         ; scriptPubKey bytes
  height         ; block height where created
  coinbase-p)    ; t if from a coinbase tx (for maturity rule)

(defstruct (utxo-set (:constructor %make-utxo-set))
  ;; In-RAM backend: EQUALP map keyed by (txid-bytes . index).
  (map (make-hash-table :test 'equalp :size 1024))
  (total-value 0)
  ;; Disk backend (when DISK is non-nil): the mmap committed table + an in-RAM
  ;; STAGING buffer of changes since the last flush (a coin = added, :SPENT =
  ;; removed).  COUNT/total are kept running; PATH is the meta-file path.
  ;; PREFETCH: a per-block map (outpoint -> coin) of committed coins resolved in
  ;; parallel before the serial pass, so utxo-spend skips the mmap cache-miss.
  ;; WAL: PATH.wal records the staging delta (fsync'd) BEFORE it is applied to
  ;; the mmap, so a crash/kill mid-flush is replayable instead of corrupting the
  ;; store (the mmap is mutated in place; the marker commits last).
  (disk nil) (staging nil) (count 0) (path nil) (prefetch nil) (wal nil))

(defun utxo-disk-p (set) (and (utxo-set-disk set) t))
(defun make-utxo-set () (%make-utxo-set))

(declaim (inline utxo-key))
(defun utxo-key (txid-bytes index)
  "Outpoint key: a cons of the txid bytes (compared by content under EQUALP) and
   the index.  Reuses the caller's existing txid vector — no allocation beyond
   the cons, no string formatting."
  (cons txid-bytes index))

(defun utxo-count (set)
  (if (utxo-set-disk set) (utxo-set-count set) (hash-table-count (utxo-set-map set))))

(defun utxo-get (set txid-bytes index)
  (if (utxo-set-disk set)
      (let ((st (gethash (utxo-key txid-bytes index) (utxo-set-staging set) :miss)))
        (cond ((eq st :spent) nil)
              ((eq st :miss)
               (multiple-value-bind (found v h cb s) (d:udb-get (utxo-set-disk set) txid-bytes index)
                 (and found (make-coin :value v :height h :coinbase-p cb :script s))))
              (t st)))                  ; staged fresh coin
      (gethash (utxo-key txid-bytes index) (utxo-set-map set))))

(defun utxo-add (set txid-bytes index coin)
  (cond
    ((utxo-set-disk set)
     (setf (gethash (utxo-key txid-bytes index) (utxo-set-staging set)) coin)
     (incf (utxo-set-count set)))
    (t (setf (gethash (utxo-key txid-bytes index) (utxo-set-map set)) coin)))
  (incf (utxo-set-total-value set) (coin-value coin))
  coin)

(defun utxo-spend (set txid-bytes index)
  "Remove and return the coin at this outpoint, or NIL if absent (double-spend
   / missing input — the caller treats NIL as a consensus failure)."
  (if (utxo-set-disk set)
      (let* ((key (utxo-key txid-bytes index))
             (st (gethash key (utxo-set-staging set) :miss)))
        (cond
          ((eq st :spent) nil)
          ((eq st :miss)                ; spend a coin that lives in the mmap
           (let ((pc (let ((pf (utxo-set-prefetch set))) (and pf (gethash key pf)))))
             (cond
               (pc                       ; resolved in parallel — no mmap touch here
                (setf (gethash key (utxo-set-staging set)) :spent)
                (decf (utxo-set-total-value set) (coin-value pc)) (decf (utxo-set-count set))
                pc)
               (t
                (multiple-value-bind (found v h cb s) (d:udb-get (utxo-set-disk set) txid-bytes index)
                  (when found
                    (setf (gethash key (utxo-set-staging set)) :spent)
                    (decf (utxo-set-total-value set) v) (decf (utxo-set-count set))
                    (make-coin :value v :height h :coinbase-p cb :script s)))))))
          (t                            ; spend a still-staged fresh coin (never flushed)
           (remhash key (utxo-set-staging set))
           (decf (utxo-set-total-value set) (coin-value st)) (decf (utxo-set-count set))
           st)))
      (let* ((key (utxo-key txid-bytes index))
             (coin (gethash key (utxo-set-map set))))
        (when coin
          (remhash key (utxo-set-map set))
          (decf (utxo-set-total-value set) (coin-value coin)))
        coin)))

;;; ----------------------------------------------------------------------------
;;; Disk backend: open / flush / close + the on-disk marker (height, totals).
;;; ----------------------------------------------------------------------------

(defconstant +udb-tip-capacity+ 500000003
  "Open-addressing slots — sized ~2.5x the ~180M-coin tip set (a sparse mmap;
   the OS only pages live regions).")

(defun open-disk-utxo (udb-path &optional (capacity +udb-tip-capacity+))
  "Open/create the disk-backed UTXO at UDB-PATH (+ .ovf + .meta).  Returns
   (values utxo-set height) — height 0 for a fresh store, else the marker."
  (let* ((db (d:open-udb udb-path capacity))
         (meta-path (concatenate 'string (namestring udb-path) ".meta"))
         (wal-path (concatenate 'string (namestring udb-path) ".wal"))
         (height 0) (total 0) (count 0))
    ;; crash recovery: an interrupted flush left a .wal — re-apply it (idempotent)
    ;; and advance the marker BEFORE we trust the marker below.
    (%replay-wal db meta-path wal-path)
    (when (probe-file meta-path)
      (with-open-file (s meta-path :element-type '(unsigned-byte 8))
        (let* ((v (make-array (file-length s) :element-type '(unsigned-byte 8))))
          (read-sequence v s)
          (let ((r (w:make-reader v)))
            (setf height (w:r-u32 r) total (w:r-u64 r) count (w:r-u64 r))
            (setf (d::udb-count db) count)))))
    (values (%make-utxo-set :disk db :staging (make-hash-table :test 'equalp)
                            :total-value total :count count :path meta-path :wal wal-path)
            height)))

(defun %write-marker (meta-path height total count)
  "Atomically commit the marker (height + totals) via temp file + rename."
  (let ((wr (w:make-writer)) (tmp (concatenate 'string meta-path ".tmp")))
    (w:w-u32 wr height) (w:w-u64 wr total) (w:w-u64 wr count)
    (with-open-file (s tmp :direction :output :element-type '(unsigned-byte 8)
                           :if-exists :supersede :if-does-not-exist :create)
      (write-sequence (w:writer-bytes wr) s)
      (finish-output s)
      (ignore-errors (sb-posix:fsync (sb-sys:fd-stream-fd s))))
    (rename-file tmp meta-path)))

(defun %write-wal (set height)
  "Durably serialize the staging delta + the post-flush (height,total,count) to
   PATH.wal (fsync'd, atomic via temp+rename) BEFORE applying it to the mmap."
  (let* ((wr (w:make-writer)) (st (utxo-set-staging set))
         (wal (utxo-set-wal set)) (tmp (concatenate 'string wal ".tmp")))
    (w:w-u32 wr height) (w:w-u64 wr (utxo-set-total-value set)) (w:w-u64 wr (utxo-set-count set))
    (w:w-u64 wr (hash-table-count st))
    (maphash (lambda (key v)
               (w:w-bytes wr (car key)) (w:w-u32 wr (cdr key))
               (if (eq v :spent)
                   (w:w-u8 wr 0)
                   (progn (w:w-u8 wr 1)
                          (w:w-u64 wr (coin-value v)) (w:w-u32 wr (coin-height v))
                          (w:w-u8 wr (if (coin-coinbase-p v) 1 0))
                          (w:w-u32 wr (length (coin-script v))) (w:w-bytes wr (coin-script v)))))
             st)
    (with-open-file (s tmp :direction :output :element-type '(unsigned-byte 8)
                           :if-exists :supersede :if-does-not-exist :create)
      (write-sequence (w:writer-bytes wr) s)
      (finish-output s)
      (ignore-errors (sb-posix:fsync (sb-sys:fd-stream-fd s))))
    (rename-file tmp wal)))               ; a COMPLETE .wal now exists, or none

(defun %apply-wal-bytes (db v)
  "Apply a serialized WAL (idempotent udb-put/udb-del) to DB.  Returns
   (values height total count)."
  (let* ((r (w:make-reader v))
         (height (w:r-u32 r)) (total (w:r-u64 r)) (count (w:r-u64 r))
         (n (w:r-u64 r)))
    (dotimes (i n)
      (let ((txid (w:r-bytes r 32)) (index (w:r-u32 r)) (tag (w:r-u8 r)))
        (if (zerop tag)
            (d:udb-del db txid index)
            (let* ((value (w:r-u64 r)) (h (w:r-u32 r)) (cb (= 1 (w:r-u8 r)))
                   (slen (w:r-u32 r)) (script (w:r-bytes r slen)))
              (d:udb-put db txid index value h cb script)))))
    (values height total count)))

(defun %replay-wal (db meta-path wal-path)
  "If WAL-PATH exists, the previous flush was interrupted: re-apply it (idempotent
   — putting/deleting the same outpoint twice is a no-op), sync, advance the
   marker, then delete the WAL.  Leaves the store consistent at the WAL's height."
  (when (probe-file wal-path)
    (let ((v (with-open-file (s wal-path :element-type '(unsigned-byte 8))
               (let ((b (make-array (file-length s) :element-type '(unsigned-byte 8))))
                 (read-sequence b s) b))))
      (multiple-value-bind (height total count) (%apply-wal-bytes db v)
        (setf (d::udb-count db) count)
        (d:udb-sync db)
        (%write-marker meta-path height total count)
        (delete-file wal-path)
        (format t "~&[utxo] replayed interrupted flush from WAL -> height ~d~%" height)
        (force-output)
        height))))

(defun flush-utxo (set height)
  "Apply the staging buffer to the mmap, msync, and atomically write the marker
   at HEIGHT — leaving the on-disk store consistent at a verified height.  The
   delta is WAL-logged first so an interrupted flush is replayable, not corrupting."
  (let ((db (utxo-set-disk set)))
    (%write-wal set height)             ; durable delta BEFORE mutating the mmap
    (maphash (lambda (key v)
               (let ((txid (car key)) (index (cdr key)))
                 (if (eq v :spent)
                     (d:udb-del db txid index)
                     (d:udb-put db txid index (coin-value v) (coin-height v)
                                (coin-coinbase-p v) (coin-script v)))))
             (utxo-set-staging set))
    (clrhash (utxo-set-staging set))
    (d:udb-sync db)
    (%write-marker (utxo-set-path set) height (utxo-set-total-value set) (utxo-set-count set))
    (ignore-errors (delete-file (utxo-set-wal set)))   ; flush complete: drop the WAL
    height))

(defun close-utxo (set)
  (when (utxo-set-disk set) (d:close-udb (utxo-set-disk set))))

;;; Parallel UTXO-lookup prefetch.  Input lookups are independent read-only mmap
;;; accesses (cache-miss + coin alloc) — the bulk of the single-threaded
;;; connect-block pass.  Resolve them across cores BEFORE the serial pass, then
;;; utxo-spend consumes the prefetch map (hot) instead of touching the mmap.
(defun prefetch-resolve (set txid-bytes index)
  "Read-only: the committed (mmap) coin for this outpoint, or NIL if absent.
   Thread-safe (pure mmap reads + fresh allocation; staged coins are resolved by
   the serial pass and intentionally not prefetched)."
  (multiple-value-bind (found v h cb s) (d:udb-get (utxo-set-disk set) txid-bytes index)
    (and found (make-coin :value v :height h :coinbase-p cb :script s))))

(defun set-prefetch (set map) (setf (utxo-set-prefetch set) map))
(defun clear-prefetch (set) (setf (utxo-set-prefetch set) nil))

;;; ----------------------------------------------------------------------------
;;; Order-independent set digest — an additive (MuHash-style) commitment to the
;;; whole UTXO set.  Used to prove a connect/disconnect round-trip restores the
;;; set exactly, and to detect reorg correctness.  (This is our own scheme, not
;;; Core's hash_serialized; matching gettxoutsetinfo needs Core's exact coin
;;; serialization and is a separate task once RPC creds land.)
;;; ----------------------------------------------------------------------------

(defun coin-commitment (key coin)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (car key))            ; txid bytes
    (w:w-u32 wr (cdr key))              ; index
    (w:w-i64 wr (coin-value coin))
    (w:w-u32 wr (coin-height coin))
    (w:w-bool wr (coin-coinbase-p coin))
    (w:w-bytes wr (coin-script coin))
    (let ((h (w:hash256 (w:writer-bytes wr))) (acc 0))
      (dotimes (i 32 acc) (setf acc (logior acc (ash (aref h i) (* 8 i))))))))

(defun utxo-digest (set)
  "A 32-byte order-independent digest of the whole set (sum of per-coin
   commitments mod 2^256).  For the disk backend, combines the committed mmap
   slots with the staging buffer (staged spends mask mmap coins)."
  (let ((acc 0) (m (ash 1 256)))
    (flet ((add (k c) (setf acc (mod (+ acc (coin-commitment k c)) m))))
      (cond
        ((utxo-set-disk set)
         (let ((staging (utxo-set-staging set)))
           ;; committed mmap coins not overridden by a staged spend/re-add
           (d:udb-map-slots (utxo-set-disk set)
             (lambda (txid index v h cb s)
               (unless (nth-value 1 (gethash (cons txid index) staging))   ; in staging? skip (handled below)
                 (add (cons txid index) (make-coin :value v :height h :coinbase-p cb :script s)))))
           ;; staged fresh adds (coins); staged :spent contribute nothing
           (maphash (lambda (k v) (unless (eq v :spent) (add k v))) staging)))
        (t (maphash #'add (utxo-set-map set)))))
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 32 out) (setf (aref out i) (logand (ash acc (* -8 i)) #xff))))))

;;; ----------------------------------------------------------------------------
;;; Persistence — flat dump of the live set (key\0value records).  Simple and
;;; resumable; superseded when we move to a real on-disk KV backend.
;;; ----------------------------------------------------------------------------

(defun save-utxo (set path height)
  (when (utxo-set-disk set)            ; disk backend: flush + marker, ignore PATH
    (return-from save-utxo (flush-utxo set height)))
  (ensure-directories-exist path)
  (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                          :if-exists :supersede :if-does-not-exist :create)
    (let ((hdr (w:make-writer)))
      (w:w-u32 hdr height)
      (w:w-u64 hdr (utxo-count set))
      (write-sequence (w:writer-bytes hdr) s))
    (maphash
     (lambda (key coin)
       (let ((wr (w:make-writer))
             (kb (car key)))            ; txid bytes; index stored separately
         (w:w-varint wr (length kb)) (w:w-bytes wr kb)
         (w:w-u32 wr (cdr key))
         (w:w-i64 wr (coin-value coin))
         (w:w-u32 wr (coin-height coin))
         (w:w-bool wr (coin-coinbase-p coin))
         (w:w-varint wr (length (coin-script coin)))
         (w:w-bytes wr (coin-script coin))
         (write-sequence (w:writer-bytes wr) s)))
     (utxo-set-map set)))
  height)

(defun load-utxo (path)
  "Returns (values utxo-set height) or (values nil nil) if no file."
  (unless (probe-file path) (return-from load-utxo (values nil nil)))
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let* ((all (let ((v (make-array (file-length s) :element-type '(unsigned-byte 8))))
                  (read-sequence v s) v))
           (r (w:make-reader all))
           (height (w:r-u32 r))
           (n (w:r-u64 r))
           (set (make-utxo-set)))
      (dotimes (i n)
        (let* ((klen (w:r-varint r))
               (txid (w:r-bytes r klen))
               (index (w:r-u32 r))
               (key (cons txid index))
               (value (w:r-i64 r))
               (h (w:r-u32 r))
               (cb (w:r-bool r))
               (slen (w:r-varint r))
               (script (w:r-bytes r slen)))
          (setf (gethash key (utxo-set-map set))
                (make-coin :value value :script script :height h :coinbase-p cb))
          (incf (utxo-set-total-value set) value)))
      (values set height))))

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
  (:local-nicknames (#:w #:cl-consensus.wire))
  (:export
   #:coin #:make-coin #:coin-value #:coin-script #:coin-height #:coin-coinbase-p
   #:utxo-set #:make-utxo-set #:utxo-count #:utxo-set-total-value
   #:utxo-get #:utxo-add #:utxo-spend #:utxo-key #:utxo-digest
   #:save-utxo #:load-utxo))

(in-package #:cl-consensus.utxo)

(defstruct coin
  value          ; satoshis (int64)
  script         ; scriptPubKey bytes
  height         ; block height where created
  coinbase-p)    ; t if from a coinbase tx (for maturity rule)

(defstruct (utxo-set (:constructor %make-utxo-set))
  ;; EQUALP map keyed by (txid-bytes . index): compares the 32 txid bytes by
  ;; content + the integer index.  (Was a per-op `format`ed hex STRING key — the
  ;; format/hex-encode dominated connect-block at ~16us/op and bloated memory.)
  (map (make-hash-table :test 'equalp :size 1024))
  (total-value 0))

(defun make-utxo-set () (%make-utxo-set))

(declaim (inline utxo-key))
(defun utxo-key (txid-bytes index)
  "Outpoint key: a cons of the txid bytes (compared by content under EQUALP) and
   the index.  Reuses the caller's existing txid vector — no allocation beyond
   the cons, no string formatting."
  (cons txid-bytes index))

(defun utxo-count (set) (hash-table-count (utxo-set-map set)))

(defun utxo-get (set txid-bytes index)
  (gethash (utxo-key txid-bytes index) (utxo-set-map set)))

(defun utxo-add (set txid-bytes index coin)
  (setf (gethash (utxo-key txid-bytes index) (utxo-set-map set)) coin)
  (incf (utxo-set-total-value set) (coin-value coin))
  coin)

(defun utxo-spend (set txid-bytes index)
  "Remove and return the coin at this outpoint, or NIL if absent (double-spend
   / missing input — the caller treats NIL as a consensus failure)."
  (let* ((key (utxo-key txid-bytes index))
         (coin (gethash key (utxo-set-map set))))
    (when coin
      (remhash key (utxo-set-map set))
      (decf (utxo-set-total-value set) (coin-value coin)))
    coin))

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
   commitments mod 2^256)."
  (let ((acc 0))
    (maphash (lambda (k c) (setf acc (mod (+ acc (coin-commitment k c)) (ash 1 256))))
             (utxo-set-map set))
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 32 out) (setf (aref out i) (logand (ash acc (* -8 i)) #xff))))))

;;; ----------------------------------------------------------------------------
;;; Persistence — flat dump of the live set (key\0value records).  Simple and
;;; resumable; superseded when we move to a real on-disk KV backend.
;;; ----------------------------------------------------------------------------

(defun save-utxo (set path height)
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

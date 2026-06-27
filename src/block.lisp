;;;; shared/bitcoind/block.lisp
;;;;
;;;; Phase 3b — full blocks: parse (header + transactions), compute the merkle
;;;; root over txids and check it against the header, and download blocks from a
;;;; peer over getdata/block (requesting witness data, MSG_WITNESS_BLOCK).
;;;;
;;;; Milestone check: for any block, our computed block hash AND merkle root must
;;;; equal what the header commits to — and known txids (e.g. block 170's
;;;; Satoshi->Hal Finney tx) must come out right.


(defpackage #:cl-consensus.block
  (:use #:cl)
  (:nicknames #:btc-block)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:p #:cl-consensus.peer)
                    (#:c #:cl-consensus.chain) (#:tx #:cl-consensus.tx)
                    (#:bt #:bordeaux-threads))
  (:export
   #:block* #:block-header #:block-txs #:block-hash #:block-hash-hex
   #:parse-block #:merkle-root #:compute-merkle-root #:verify-merkle
   #:get-block #:get-block-raw #:get-block-at-height #:get-blocks
   #:+msg-block+ #:+msg-witness-block+ #:witness-commitment))

(in-package #:cl-consensus.block)

(defstruct (block* (:constructor %make-block) (:conc-name block-))
  header     ; a cl-consensus.chain:header
  txs)       ; vector of cl-consensus.tx:tx

(defun block-hash (b) (c:header-hash (block-header b)))
(defun block-hash-hex (b) (c:header-hash-hex (block-header b)))

;;; ----------------------------------------------------------------------------
;;; Merkle root
;;; ----------------------------------------------------------------------------

(defun compute-merkle-root (leaves)
  "Bitcoin merkle root over a list/vector of 32-byte hashes (internal LE).
   Odd levels duplicate the final node.  Empty -> 32 zero bytes."
  (let ((level (coerce leaves 'vector)))
    (when (zerop (length level))
      (return-from compute-merkle-root
        (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop while (> (length level) 1) do
      (let* ((n (length level))
             (pairs (ceiling n 2))
             (next (make-array pairs)))
        (dotimes (i pairs)
          (let* ((a (aref level (* 2 i)))
                 (b (if (< (1+ (* 2 i)) n) (aref level (1+ (* 2 i))) a)))
            (setf (aref next i)
                  (w:hash256 (concatenate '(simple-array (unsigned-byte 8) (*)) a b)))))
        (setf level next)))
    (aref level 0)))

(defun merkle-root (b)
  "Merkle root of block B over its transaction txids."
  (compute-merkle-root (map 'list #'tx:tx-txid (block-txs b))))

(defun verify-merkle (b)
  "True iff the computed merkle root equals the header's committed merkle root."
  (equalp (merkle-root b) (c:header-merkle (block-header b))))

;;; ----------------------------------------------------------------------------
;;; Parsing
;;; ----------------------------------------------------------------------------

(defun parse-block (bytes)
  "Parse a full serialized block (header + tx_count + txs)."
  (let* ((r (w:make-reader bytes))
         (header (c:parse-header r))
         (ntx (w:r-varint r)))
    ;; Bound the count before allocating: each tx is >= 1 byte, so a tx-count larger
    ;; than the bytes remaining is malformed — reject it rather than make-array a
    ;; gigantic vector from an attacker-controlled varint (DoS).
    (when (> ntx (w:reader-remaining r))
      (error "block tx count ~d exceeds ~d remaining bytes" ntx (w:reader-remaining r)))
    (let ((txs (make-array ntx)))
      (dotimes (i ntx)
        (setf (aref txs i) (tx:parse-tx r)))
      (%make-block :header header :txs txs))))

;;; ----------------------------------------------------------------------------
;;; Witness commitment (coinbase) — merkle root over wtxids (coinbase wtxid=0)
;;; ----------------------------------------------------------------------------

(defun witness-commitment (b)
  "Compute the witness merkle root: HASH256 is taken over wtxids where the
   coinbase wtxid is defined as all zeros.  The block's committed value lives in
   a coinbase OP_RETURN output (0x6a24aa21a9ed||commitment) — checking that match
   is a Phase-5 consensus rule; this just computes the root."
  (let ((wtxids (map 'list #'tx:tx-wtxid (block-txs b))))
    (when wtxids
      (setf (first wtxids) (make-array 32 :element-type '(unsigned-byte 8)
                                          :initial-element 0)))
    (compute-merkle-root wtxids)))

;;; ----------------------------------------------------------------------------
;;; Download — getdata / block
;;; ----------------------------------------------------------------------------

(defconstant +msg-block+ 2)
(defconstant +msg-witness-block+ #x40000002)   ; MSG_BLOCK | WITNESS_FLAG

(defun build-getdata-payload (type hash)
  (let ((wr (w:make-writer)))
    (w:w-varint wr 1)
    (w:w-u32 wr type)
    (w:w-hash wr hash)
    (w:writer-bytes wr)))

(defun get-block (peer hash &key (timeout 30) (witness t))
  "Request the block named by 32-byte HASH from PEER and return a parsed BLOCK*.
   Verifies the returned block's hash matches what we asked for."
  (let ((result nil) (err nil) (done (bt:make-semaphore)))
    (p:on peer "block"
          (lambda (pr payload)
            (declare (ignore pr))
            (handler-case
                (let ((b (parse-block payload)))
                  (if (equalp (block-hash b) hash)
                      (progn (setf result b) (bt:signal-semaphore done))
                      nil))                    ; not ours; keep waiting
              (serious-condition (c) (setf err c) (bt:signal-semaphore done)))))
    (p:send peer "getdata"
            (build-getdata-payload (if witness +msg-witness-block+ +msg-block+) hash))
    (unless (bt:wait-on-semaphore done :timeout timeout)
      (error "timed out waiting for block ~a" (w:hash->hex hash)))
    (when err (error err))
    result))

(defun get-block-raw (peer hash &key (timeout 30) (witness t))
  "Like GET-BLOCK but return the RAW block wire bytes (the 'block' message payload),
   not a parsed BLOCK*.  Verifies the 80-byte header hashes to HASH before accepting.
   Used by the block store to keep the exact serialized bytes for re-serving."
  (let ((result nil) (done (bt:make-semaphore)))
    (p:on peer "block"
          (lambda (pr payload)
            (declare (ignore pr))
            (when (and (>= (length payload) 80)
                       (equalp (w:hash256 (subseq payload 0 80)) hash))
              (setf result payload)
              (bt:signal-semaphore done))))
    (p:send peer "getdata"
            (build-getdata-payload (if witness +msg-witness-block+ +msg-block+) hash))
    (unless (bt:wait-on-semaphore done :timeout timeout)
      (error "timed out waiting for raw block ~a" (w:hash->hex hash)))
    result))

(defun get-block-at-height (peer height &key (witness t))
  "Convenience: look up the hash at HEIGHT in the synced header chain and fetch
   that block."
  (let ((h (c:header-at-height height)))
    (unless h (error "no header at height ~d (sync headers first)" height))
    (get-block peer (c:header-hash h) :witness witness)))

(defun build-getdata-batch (hashes type)
  (let ((wr (w:make-writer)))
    (w:w-varint wr (length hashes))
    (dolist (h hashes) (w:w-u32 wr type) (w:w-hash wr h))
    (w:writer-bytes wr)))

(defun get-blocks (peer hashes &key (timeout 60) (retries 8) (witness t))
  "Request a batch of blocks (list of 32-byte hashes) and collect the responses.
   Returns a vector of BLOCK* in HASHES order.  A peer can transiently stall mid-
   batch; rather than fail the whole IBD, re-request the still-missing blocks each
   TIMEOUT window for up to RETRIES attempts (real nodes re-request stalled
   blocks).  Duplicate arrivals are ignored (want-set gate)."
  (let ((want (make-hash-table :test 'equal))
        (results (make-hash-table :test 'equal))
        (lock (bt:make-lock)) (remaining (length hashes)))
    (when (zerop remaining) (return-from get-blocks #()))
    (dolist (h hashes) (setf (gethash (w:hash->hex h) want) t))
    (p:on peer "block"
          (lambda (pr payload)
            (declare (ignore pr))
            (handler-case
                (let* ((b (parse-block payload)) (hx (block-hash-hex b)))
                  (bt:with-lock-held (lock)
                    (when (gethash hx want)
                      (setf (gethash hx results) b) (remhash hx want) (decf remaining))))
              (serious-condition () nil))))
    (let ((typ (if witness +msg-witness-block+ +msg-block+)))
      (loop for attempt from 1 to retries
            for missing = (bt:with-lock-held (lock)
                            (loop for h in hashes when (gethash (w:hash->hex h) want) collect h))
            while missing do
        (when (> attempt 1)
          (format t "~&[peer] re-requesting ~d stalled block(s) (attempt ~d)~%" (length missing) attempt)
          (force-output))
        (p:send peer "getdata" (build-getdata-batch missing typ))
        ;; poll until this window's deadline or batch complete
        (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
          (loop until (or (zerop remaining) (> (get-internal-real-time) deadline)) do (sleep 0.05)))))
    (when (plusp remaining)
      (error "block batch: ~d of ~d still missing after retries" remaining (length hashes)))
    (map 'vector (lambda (h) (gethash (w:hash->hex h) results)) hashes)))

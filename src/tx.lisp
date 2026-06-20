;;;; shared/bitcoind/tx.lisp
;;;;
;;;; Phase 3a — Bitcoin transactions: parse and (re)serialize, both the legacy
;;;; and BIP144 segwit encodings.  The two serializations matter:
;;;;
;;;;   txid  = HASH256(legacy serialization)            -- identifies the tx,
;;;;                                                        feeds the block merkle root
;;;;   wtxid = HASH256(segwit serialization w/ witness) -- feeds the witness
;;;;                                                        commitment in coinbase
;;;;
;;;; Weight (BIP141) = 3*base_size + total_size; vsize = ceil(weight/4).


(defpackage #:cl-consensus.tx
  (:use #:cl)
  (:nicknames #:btc-tx)
  (:local-nicknames (#:w #:cl-consensus.wire))
  (:export
   #:tx #:make-tx #:tx-version #:tx-inputs #:tx-outputs #:tx-witnesses #:tx-locktime
   #:tx-segwit-p #:tx-txid #:tx-wtxid #:tx-base-size #:tx-total-size
   #:tx-bip143-hp #:tx-bip143-hs #:tx-bip143-ho #:compute-bip143-midstate
   #:tx-weight #:tx-vsize #:tx-coinbase-p #:finalize-tx
   #:txin #:make-txin #:txin-prev-hash #:txin-prev-index #:txin-script #:txin-sequence
   #:txout #:make-txout #:txout-value #:txout-script
   #:parse-tx #:serialize-tx #:txid-hex #:wtxid-hex))

(in-package #:cl-consensus.tx)

(defstruct txin
  prev-hash      ; 32-byte outpoint txid (internal LE)
  prev-index     ; uint32 outpoint index (0xffffffff for coinbase)
  script         ; scriptSig bytes
  sequence)      ; uint32

(defstruct txout
  value          ; int64 satoshis
  script)        ; scriptPubKey bytes

(defstruct tx
  version
  inputs
  outputs
  witnesses      ; list parallel to inputs; each a list of byte vectors (may be nil)
  locktime
  segwit-p
  txid           ; 32-byte (internal LE)
  wtxid
  base-size      ; legacy serialization length
  total-size     ; full (segwit) serialization length
  ;; BIP143 midstate (SIGHASH_ALL case): hashPrevouts/hashSequence/hashOutputs
  ;; are over ALL inputs/outputs — identical for every input of the tx.  Computed
  ;; ONCE at parse (single-threaded) and cached so concurrent verify workers read
  ;; rather than recompute it per-input (was O(n^2) hashing+allocation, the
  ;; dominant allocator that drove SBCL's threaded GC to corrupt under load).
  bip143-hp bip143-hs bip143-ho)

;;; ----------------------------------------------------------------------------
;;; Serialization
;;; ----------------------------------------------------------------------------

(defun write-input (wr in)
  (w:w-hash wr (txin-prev-hash in))
  (w:w-u32 wr (txin-prev-index in))
  (w:w-varint wr (length (txin-script in)))
  (w:w-bytes wr (txin-script in))
  (w:w-u32 wr (txin-sequence in)))

(defun write-output (wr out)
  (w:w-i64 wr (txout-value out))
  (w:w-varint wr (length (txout-script out)))
  (w:w-bytes wr (txout-script out)))

(defun serialize-tx (tx &key (witness t))
  "Serialize TX.  With WITNESS and a segwit tx, emit the marker/flag + witness
   stacks (the wtxid/relay form); otherwise emit the legacy form (the txid form)."
  (let ((wr (w:make-writer))
        (segwit (and witness (tx-segwit-p tx))))
    (w:w-i32 wr (tx-version tx))
    (when segwit (w:w-u8 wr 0) (w:w-u8 wr 1))   ; marker, flag
    (w:w-varint wr (length (tx-inputs tx)))
    (dolist (in (tx-inputs tx)) (write-input wr in))
    (w:w-varint wr (length (tx-outputs tx)))
    (dolist (out (tx-outputs tx)) (write-output wr out))
    (when segwit
      (dolist (stack (tx-witnesses tx))
        (w:w-varint wr (length stack))
        (dolist (item stack)
          (w:w-varint wr (length item))
          (w:w-bytes wr item))))
    (w:w-u32 wr (tx-locktime tx))
    (w:writer-bytes wr)))

;;; ----------------------------------------------------------------------------
;;; Parsing
;;; ----------------------------------------------------------------------------

(defun parse-tx (r)
  "Parse one transaction from reader R, computing txid/wtxid and sizes.
   Handles both legacy and BIP144 segwit encodings."
  (let* ((start (w:reader-pos r))
         (version (w:r-i32 r))
         (segwit nil)
         (inputs '()) (outputs '()) (witnesses '()))
    ;; segwit detection: a 0x00 marker where the input count would be, then flag.
    (let ((maybe-marker (aref (cl-consensus.wire::reader-buf r) (w:reader-pos r))))
      (when (zerop maybe-marker)
        (w:r-u8 r)                            ; consume marker 0x00
        (let ((flag (w:r-u8 r)))
          (declare (ignore flag))
          (setf segwit t))))
    (let ((nin (w:r-varint r)))
      (dotimes (i nin)
        (let ((prev-hash (w:r-hash r))
              (prev-index (w:r-u32 r))
              (script (w:r-bytes r (w:r-varint r)))
              (sequence (w:r-u32 r)))
          (push (make-txin :prev-hash prev-hash :prev-index prev-index
                           :script script :sequence sequence)
                inputs))))
    (setf inputs (nreverse inputs))
    (let ((nout (w:r-varint r)))
      (dotimes (i nout)
        (let ((value (w:r-i64 r))
              (script (w:r-bytes r (w:r-varint r))))
          (push (make-txout :value value :script script) outputs))))
    (setf outputs (nreverse outputs))
    (when segwit
      (dolist (in inputs)
        (declare (ignore in))
        (let ((items (w:r-varint r)) (stack '()))
          (dotimes (j items)
            (push (w:r-bytes r (w:r-varint r)) stack))
          (push (nreverse stack) witnesses)))
      (setf witnesses (nreverse witnesses)))
    (let* ((locktime (w:r-u32 r))
           (end (w:reader-pos r))
           (total-size (- end start))
           (tx (make-tx :version version :inputs inputs :outputs outputs
                        :witnesses witnesses :locktime locktime :segwit-p segwit
                        :total-size total-size)))
      ;; txid = HASH256(legacy); wtxid = HASH256(segwit-or-legacy)
      (let* ((legacy (serialize-tx tx :witness nil)))
        (setf (tx-base-size tx) (length legacy)
              (tx-txid tx) (w:hash256 legacy)
              (tx-wtxid tx) (if segwit
                                (w:hash256 (subseq (cl-consensus.wire::reader-buf r) start end))
                                (tx-txid tx))))
      ;; precompute the BIP143 midstate for segwit txs (single-threaded here)
      (when segwit (compute-bip143-midstate tx))
      tx)))

;;; ----------------------------------------------------------------------------
;;; Derived quantities
;;; ----------------------------------------------------------------------------

(defun compute-bip143-midstate (tx)
  "Compute & cache the SIGHASH_ALL BIP143 midstate (hashPrevouts, hashSequence,
   hashOutputs) — each over all inputs/outputs, identical for every input.  Done
   once, single-threaded; concurrent verify workers then read the cache."
  (let ((wp (w:make-writer)) (ws (w:make-writer)) (wo (w:make-writer)))
    (dolist (in (tx-inputs tx))
      (w:w-hash wp (txin-prev-hash in)) (w:w-u32 wp (txin-prev-index in))
      (w:w-u32 ws (txin-sequence in)))
    (dolist (out (tx-outputs tx))
      (w:w-i64 wo (txout-value out))
      (w:w-varint wo (length (txout-script out)))
      (w:w-bytes wo (txout-script out)))
    (setf (tx-bip143-hp tx) (w:hash256 (w:writer-bytes wp))
          (tx-bip143-hs tx) (w:hash256 (w:writer-bytes ws))
          (tx-bip143-ho tx) (w:hash256 (w:writer-bytes wo))))
  tx)

(defun finalize-tx (tx)
  "Compute txid/wtxid/sizes for a hand-built TX (PARSE-TX already does this for
   parsed txs).  Returns TX."
  (let ((legacy (serialize-tx tx :witness nil))
        (full (serialize-tx tx :witness t)))
    (setf (tx-base-size tx) (length legacy)
          (tx-total-size tx) (length full)
          (tx-txid tx) (w:hash256 legacy)
          (tx-wtxid tx) (if (tx-segwit-p tx) (w:hash256 full) (tx-txid tx))))
  tx)

(defun tx-weight (tx)
  "BIP141 weight: 3*base + total."
  (+ (* 3 (tx-base-size tx)) (tx-total-size tx)))

(defun tx-vsize (tx) (ceiling (tx-weight tx) 4))

(defun tx-coinbase-p (tx)
  "A coinbase has exactly one input whose outpoint is the null hash / 0xffffffff."
  (and (= 1 (length (tx-inputs tx)))
       (let ((in (first (tx-inputs tx))))
         (and (= #xffffffff (txin-prev-index in))
              (every #'zerop (txin-prev-hash in))))))

(defun txid-hex (tx) (w:hash->hex (tx-txid tx)))
(defun wtxid-hex (tx) (w:hash->hex (tx-wtxid tx)))

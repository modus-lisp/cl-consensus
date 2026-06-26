;;;; shared/bitcoind/validate.lisp
;;;;
;;;; Phase 5b — block-level consensus validation and the IBD (initial block
;;;; download) driver.  CONNECT-BLOCK applies a block to the UTXO set while
;;;; enforcing the rules: every input must spend an existing unspent coin (no
;;;; double-spend), coinbase outputs must mature 100 blocks, scripts must verify
;;;; (height-gated soft forks), value must be conserved (outputs <= inputs), and
;;;; the coinbase may claim at most subsidy + fees.
;;;;
;;;; Verified by replaying real mainnet blocks from genesis and checking every
;;;; rule holds; with RPC creds, the resulting UTXO set is cross-checked against
;;;; the epyc node's gettxoutsetinfo.


(defpackage #:cl-consensus.validate
  (:use #:cl)
  (:nicknames #:btc-validate)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:p #:cl-consensus.peer)
                    (#:c #:cl-consensus.chain) (#:tx #:cl-consensus.tx)
                    (#:blk #:cl-consensus.block) (#:s #:cl-consensus.script)
                    (#:u #:cl-consensus.utxo)
                    (#:bt #:bordeaux-threads) (#:secp #:secp256k1-fast))
  (:export
   #:block-subsidy #:connect-block #:disconnect-block #:consensus-error
   #:run-ibd #:resume-ibd #:run-ibd-async #:chainstate-path #:consensus-flags
   #:*verify-workers*
   #:block-undo #:make-block-undo #:block-undo-spent #:block-undo-created
   #:block-weight #:count-sigops
   #:+bip16-height+ #:+segwit-height+ #:+taproot-height+ #:+bip34-height+
   #:*coinbase-maturity* #:*max-block-weight* #:*max-block-sigops*))

(in-package #:cl-consensus.validate)

(define-condition consensus-error (error)
  ((msg :initarg :msg :reader consensus-error-msg)
   (height :initarg :height :initform nil :reader consensus-error-height))
  (:report (lambda (c s) (format s "consensus failure~@[ at height ~d~]: ~a"
                                 (consensus-error-height c) (consensus-error-msg c)))))

(defun cerr (height fmt &rest args)
  (error 'consensus-error :height height :msg (apply #'format nil fmt args)))

;;; soft-fork activation heights (mainnet)
(defconstant +bip16-height+ 173805)     ; P2SH
(defconstant +bip34-height+ 227931)     ; coinbase height in scriptSig
(defconstant +segwit-height+ 481824)    ; BIP141
(defconstant +taproot-height+ 709632)   ; BIP341/342
(defparameter *coinbase-maturity* 100)
(defparameter *max-block-weight* 4000000)
(defparameter *max-block-sigops* 80000) ; weighted sigop cost

;;; BIP30 historical exceptions: two pairs of blocks with duplicate coinbase
;;; txids (pre-BIP34) where the later block was allowed to overwrite.
(defparameter *bip30-exceptions* '(91842 91880))

;;; ----------------------------------------------------------------------------
;;; Undo data — what a block changed, so it can be disconnected on a reorg
;;; ----------------------------------------------------------------------------

(defstruct block-undo
  (spent '())      ; list of (txid-bytes index coin) consumed, in apply order
  (created '()))   ; list of (txid-bytes . index) added, in apply order

(defconstant +bip66-height+ 363725)     ; strict DER (DERSIG)
(defconstant +cltv-height+ 388381)      ; BIP65
(defconstant +csv-height+ 419328)       ; BIP112

(defun height-of (fork)
  "Activation height of FORK (:p2sh :dersig :cltv :csv :bip34 :segwit :taproot) on the
   active network (mainnet's real schedule; early on regtest/testnet)."
  (getf (w:net-heights w:*network*) fork))

(defun consensus-flags (height)
  "The SCRIPT_VERIFY flags consensus-active at HEIGHT on the active network.
   Policy-only flags (LOW_S, STRICTENC, MINIMALDATA) are intentionally excluded."
  (let ((f '()))
    (when (>= height (height-of :p2sh)) (push :p2sh f))
    (when (>= height (height-of :dersig)) (push :dersig f))
    (when (>= height (height-of :cltv)) (push :cltv f))
    (when (>= height (height-of :csv)) (push :csv f))
    (when (>= height (height-of :segwit)) (push :witness f) (push :nulldummy f))
    (when (>= height (height-of :taproot)) (push :taproot f))
    f))

(defun block-subsidy (height)
  "Block reward in satoshis: 50 BTC halving every 210,000 blocks."
  (let ((halvings (floor height 210000)))
    (if (>= halvings 64) 0 (ash 5000000000 (- halvings)))))

(defun unspendable-p (script)
  "Provably unspendable outputs (OP_RETURN) are never added to the UTXO set —
   matching Core, so set sizes/values line up."
  (and (plusp (length script)) (= (aref script 0) s::+op-return+)))

;;; ----------------------------------------------------------------------------
;;; connect-block — apply one block to the chainstate with full validation
;;; ----------------------------------------------------------------------------

(defun block-weight (block)
  "BIP141 weight of a whole block: 3*base_size + total_size, computed exactly
   from the transactions plus header + tx-count overhead."
  (let* ((txs (blk:block-txs block))
         (ntx (length txs))
         (overhead (+ 80 (varint-len ntx)))
         (base (+ overhead (reduce #'+ txs :key #'tx:tx-base-size :initial-value 0)))
         (total (+ overhead (reduce #'+ txs :key #'tx:tx-total-size :initial-value 0))))
    (+ (* 3 base) total)))

(defun varint-len (n)
  (cond ((< n #xfd) 1) ((<= n #xffff) 3) ((<= n #xffffffff) 5) (t 9)))

(defun script-sigops (script &optional accurate-multisig)
  "Legacy sigop count of a script.  CHECKSIG=1, CHECKMULTISIG=20 (or, when
   ACCURATE-MULTISIG, the N pushed immediately before)."
  (let ((ops (handler-case (s:parse-script script) (error () (return-from script-sigops 0))))
        (count 0) (prev nil))
    (dolist (op ops count)
      (cond
        ((and (integerp op) (or (= op 172) (= op 173))) (incf count))          ; CHECKSIG(VERIFY)
        ((and (integerp op) (or (= op 174) (= op 175)))                        ; CHECKMULTISIG(VERIFY)
         (incf count (if (and accurate-multisig (consp prev)) 20
                         (if (and accurate-multisig (integerp prev) (<= 81 prev 96))
                             (- prev 80) 20))))
        (t nil))
      (setf prev op))))

(defun count-sigops (block)
  "Weighted legacy sigop cost of a block (* 4, the segwit scaling).  A coarse
   but conservative bound — enough to enforce the 80k limit on real blocks."
  (let ((n 0))
    (loop for txn across (blk:block-txs block) do
      (dolist (in (tx:tx-inputs txn)) (incf n (script-sigops (tx:txin-script in))))
      (dolist (out (tx:tx-outputs txn)) (incf n (script-sigops (tx:txout-script out)))))
    (* 4 n)))

;;; ----------------------------------------------------------------------------
;;; Time-locks: IsFinalTx (BIP113) and BIP68 relative sequence locks
;;; ----------------------------------------------------------------------------

(defconstant +lt-threshold+ 500000000)   ; nLockTime < this => height, else unix time
(defconstant +seq-final+ #xffffffff)
(defconstant +seq-disable+ #x80000000)
(defconstant +seq-type-flag+ #x00400000)  ; relative lock is time-based (512s units)
(defconstant +seq-mask+ #x0000ffff)
(defconstant +bip113-height+ 419328)      ; median-time-past for locktime (== CSV height)

(defun block-mtp (height)
  "The median-time-past used for time-locks at HEIGHT: the MTP of the parent
   block (BIP113).  Falls back to 0 if the header isn't available."
  (let ((parent (c:header-at-height (1- height))))
    (if parent (c:median-time-past parent) 0)))

(defun final-tx-p (txn height mtp)
  "IsFinalTx: a tx is final if its locktime is 0/elapsed or all inputs are final."
  (let ((lt (tx:tx-locktime txn)))
    (or (zerop lt)
        (< lt (if (< lt +lt-threshold+) height mtp))
        (every (lambda (in) (= (tx:txin-sequence in) +seq-final+)) (tx:tx-inputs txn)))))

(defun sequence-lock-ok (coin seq height mtp)
  "BIP68: a version>=2 input's relative lock-time must be satisfied.  COIN is the
   spent coin (carries its creation height); HEIGHT/MTP are the spending block's."
  (or (/= 0 (logand seq +seq-disable+))            ; relative lock disabled
      (if (zerop (logand seq +seq-type-flag+))
          ;; height-based: (spend_height - coin_height) >= relative
          (>= (- height (u:coin-height coin)) (logand seq +seq-mask+))
          ;; time-based: 512-second units, vs the parent MTP at coin creation
          (let ((coin-mtp (block-mtp (max 1 (u:coin-height coin)))))
            (>= mtp (+ coin-mtp (ash (logand seq +seq-mask+) 9)))))))

;;; ----------------------------------------------------------------------------
;;; Witness commitment (BIP141): coinbase must commit to the witness merkle root
;;; ----------------------------------------------------------------------------

(defun find-witness-commitment (coinbase)
  "Return the 32-byte committed value from the coinbase's witness-commitment
   output (last output whose script is 6a24aa21a9ed||<32>), or NIL."
  (let ((found nil))
    (dolist (out (tx:tx-outputs coinbase) found)
      (let ((s (tx:txout-script out)))
        (when (and (>= (length s) 38)
                   (equalp (subseq s 0 6) #(#x6a #x24 #xaa #x21 #xa9 #xed)))
          (setf found (subseq s 6 38)))))))

(defun check-witness-commitment (block height)
  "Enforce BIP141: if the block carries any witness data (segwit active), the
   coinbase must commit to HASH256(witness-merkle-root || reserved-value)."
  (when (>= height (height-of :segwit))
    (let* ((txs (blk:block-txs block))
           (has-witness (some #'tx:tx-segwit-p txs))
           (coinbase (aref txs 0))
           (committed (find-witness-commitment coinbase)))
      (cond
        (committed
         (let* ((wit (first (tx:tx-witnesses coinbase)))
                (reserved (if (and wit (= (length wit) 1) (= (length (first wit)) 32))
                              (first wit)
                              (cerr height "bad coinbase witness reserved value")))
                (computed (w:hash256 (concatenate '(simple-array (unsigned-byte 8) (*))
                                                  (blk:witness-commitment block) reserved))))
           (unless (equalp computed committed)
             (cerr height "witness commitment mismatch"))))
        (has-witness
         (cerr height "block has witness data but no coinbase commitment"))))))

;;; ----------------------------------------------------------------------------
;;; Parallel script verification.  Script checks are pure functions of (tx,
;;; input, prevout-script, value, flags) and don't touch the UTXO set, so — like
;;; Core's CCheckQueue — connect-block runs the sequential UTXO pass inline but
;;; defers every CHECKSIG-bearing input to a thread pool that fans the ECDSA /
;;; Schnorr work across cores.  Each worker binds its own secp scratch.
;;; ----------------------------------------------------------------------------

(defvar *verify-workers* 64
  "Max threads to fan a block's script checks across (capped by job count).")
(defvar *parallel-verify-threshold* 16
  "Below this many script checks, verify inline (thread spawn isn't worth it).")

(defun %run-checks (checks flags lo hi abort fail lock)
  "Worker: verify CHECKS[lo,hi) in this thread's own secp scratch, stopping
   early if another worker has already failed (ABORT)."
  (secp:with-fresh-scratch
   (s:with-sighash-buffer
    (loop for i from lo below hi until (car abort) do
      (destructuring-bind (txn in-i script value tx-i prevouts) (aref checks i)
        (let ((bad (handler-case
                       (unless (s:verify-input txn in-i script value :flags flags :prevouts prevouts)
                         "script verification failed")
                     (s:script-error (e) (princ-to-string e))
                     (error (e) (princ-to-string e)))))
          (when bad
            (setf (car abort) t)
            (bt:with-lock-held (lock)
              (unless (car fail) (setf (car fail) bad (cdr fail) (list tx-i in-i)))))))))))

(defun verify-block-scripts (checks flags &optional (workers *verify-workers*))
  "Run all script CHECKS (vector of (txn in-i script value tx-i)) under FLAGS.
   Returns (values ok msg tx-i in-i).  Small batches run inline; larger ones fan
   across up to WORKERS threads."
  (let ((n (length checks)))
    (when (zerop n) (return-from verify-block-scripts (values t nil nil nil)))
    (let ((abort (cons nil nil)) (fail (cons nil nil)) (lock (bt:make-lock)))
      (if (< n *parallel-verify-threshold*)
          (%run-checks checks flags 0 n abort fail lock)
          (let* ((nw (max 1 (min workers n)))
                 (per (ceiling n nw))
                 (threads '()))
            (dotimes (w nw)
              (let ((lo (* w per)) (hi (min n (* (1+ w) per))))
                (when (< lo hi)
                  (push (bt:make-thread
                         (let ((lo lo) (hi hi))
                           (lambda () (%run-checks checks flags lo hi abort fail lock)))
                         :name (format nil "verify ~d-~d" lo hi))
                        threads))))
            (mapc #'bt:join-thread threads)))
      (if (car fail)
          (values nil (car fail) (first (cdr fail)) (second (cdr fail)))
          (values t nil nil nil)))))

;;; ----------------------------------------------------------------------------
;;; Async / pipelined IBD.  UTXO application must be ordered, but script
;;; verification needn't be — so the sequential pass (parse + UTXO mutation +
;;; non-script rules) races ahead, enqueuing each block's script checks into a
;;; bounded queue that a persistent pool of worker threads drains continuously.
;;; Verification fills ALL cores instead of per-block bursts.  A checkpoint is
;;; only written at a FULLY-VERIFIED height (a drain barrier at each save), so a
;;; resume never trusts an unverified region; on any failure we halt and report
;;; the offending (height, tx, input) once in-flight work settles.
;;; ----------------------------------------------------------------------------

;; minimal FIFO (O(1) push/pop) guarded by the vqueue lock
(defstruct (fifo (:constructor make-fifo)) (head nil) (tail nil))
(defun fifo-push (f x)
  (let ((c (cons x nil)))
    (if (fifo-tail f) (setf (cdr (fifo-tail f)) c) (setf (fifo-head f) c))
    (setf (fifo-tail f) c)))
(defun fifo-pop (f)
  (let ((c (fifo-head f)))
    (setf (fifo-head f) (cdr c))
    (unless (fifo-head f) (setf (fifo-tail f) nil))
    (car c)))

(defstruct (vqueue (:constructor %make-vqueue))
  (lock (bt:make-lock)) (fifo (make-fifo)) space items
  (pending (make-hash-table)) (maxreg -1) (verified -1) (next 0)
  (failed nil) (workers nil))

(defun make-vqueue (&key (maxq 8192) (workers 100))  ; maxq = max in-flight BATCHES (~maxq*chunk inputs)
  (let ((vq (%make-vqueue :space (bt:make-semaphore :count maxq) :items (bt:make-semaphore :count 0))))
    (setf (vqueue-workers vq)
          (loop repeat workers collect
            (bt:make-thread (lambda () (vq-worker vq)) :name "ibd-verify")))
    vq))

(defun vq-put (vq job)
  (bt:wait-on-semaphore (vqueue-space vq))
  (bt:with-lock-held ((vqueue-lock vq)) (fifo-push (vqueue-fifo vq) job))
  (bt:signal-semaphore (vqueue-items vq)))

(defun vq-get (vq)
  (bt:wait-on-semaphore (vqueue-items vq))
  (prog1 (bt:with-lock-held ((vqueue-lock vq)) (fifo-pop (vqueue-fifo vq)))
    (bt:signal-semaphore (vqueue-space vq))))

(defun %vq-advance (vq)            ; call under lock: extend the verified watermark
  (loop while (and (<= (vqueue-next vq) (vqueue-maxreg vq))
                   (null (gethash (vqueue-next vq) (vqueue-pending vq))))
        do (setf (vqueue-verified vq) (vqueue-next vq))
           (incf (vqueue-next vq))))

(defun vq-register (vq height n)   ; producer: register HEIGHT with N checks
  (bt:with-lock-held ((vqueue-lock vq))
    (setf (vqueue-maxreg vq) height)
    (when (plusp n) (setf (gethash height (vqueue-pending vq)) n))
    (%vq-advance vq)))

(defun vq-complete (vq height &optional (k 1))  ; worker: K checks of HEIGHT done
  (bt:with-lock-held ((vqueue-lock vq))
    (let ((r (decf (gethash height (vqueue-pending vq)) k)))
      (when (<= r 0) (remhash height (vqueue-pending vq)) (%vq-advance vq)))))

(defvar *prefetch-workers* 64
  "Threads to resolve a block's input coins from the mmap in parallel.")

(defun prefetch-block-inputs (set block &optional (workers *prefetch-workers*))
  "Resolve every non-coinbase input's committed (mmap) coin in parallel into
   SET's prefetch map, so the serial connect-block pass skips the mmap cache-miss
   + coin alloc.  No-op for the in-RAM backend.  Reads only (safe: the producer
   does no mmap writes between checkpoints)."
  (unless (u:utxo-disk-p set) (return-from prefetch-block-inputs))
  (let ((ops '()))
    (loop for txn across (blk:block-txs block) do
      (unless (tx:tx-coinbase-p txn)
        (dolist (in (tx:tx-inputs txn))
          (push (u:utxo-key (tx:txin-prev-hash in) (tx:txin-prev-index in)) ops))))
    (let* ((vec (coerce ops 'vector)) (n (length vec)))
      (when (plusp n)
        (let* ((nw (max 1 (min workers n))) (per (ceiling n nw))
               (parts (make-array nw :initial-element nil))
               (threads
                 (loop for w below nw
                       for lo = (* w per) for hi = (min n (* (1+ w) per))
                       when (< lo hi) collect
                       (let ((lo lo) (hi hi) (wi w))
                         (bt:make-thread
                          (lambda ()
                            (let ((acc '()))
                              (loop for i from lo below hi do
                                (let* ((k (aref vec i))
                                       (coin (u:prefetch-resolve set (car k) (cdr k))))
                                  (when coin (push (cons k coin) acc))))
                              (setf (aref parts wi) acc))))))))
          (mapc #'bt:join-thread threads)
          (let ((pf (make-hash-table :test 'equalp :size (1+ n))))
            (dotimes (w nw) (dolist (kc (aref parts w)) (setf (gethash (car kc) pf) (cdr kc))))
            (u:set-prefetch set pf)))))))

(defun vq-worker (vq)
  (secp:with-fresh-scratch
   (s:with-sighash-buffer
    (loop
      (let ((job (vq-get vq)))
        (when (eq job :stop) (return))
        ;; job = (height flags k . checks); checks = list of (txn in-i script value tx-i).
        ;; Batched (K inputs per job) so the per-job lock traffic on the queue is
        ;; ~CHUNK x lower — the single queue lock was the IBD verify bottleneck.
        (destructuring-bind (height flags k . checks) job
          (unless (vqueue-failed vq)
            (dolist (c checks)
              (destructuring-bind (txn in-i script value tx-i prevouts) c
                (let ((bad (handler-case
                               (unless (s:verify-input txn in-i script value :flags flags :prevouts prevouts)
                                 "script verification failed")
                             (s:script-error (e) (princ-to-string e))
                             (error (e) (princ-to-string e)))))
                  (when bad
                    (bt:with-lock-held ((vqueue-lock vq))
                      (unless (vqueue-failed vq) (setf (vqueue-failed vq) (list height tx-i in-i bad))))
                    (return))))))
          (vq-complete vq height k)))))))

(defparameter *vq-chunk* 128
  "Inputs per verify-queue job.  Batching amortizes the single queue lock across
   CHUNK inputs (producer + ~100 workers all serialize through it); per-input
   enqueue made that lock the IBD verify bottleneck (the dominant `sink` cost).")

(defun vq-sink (vq)
  "The CHECK-SINK closure for connect-block: register the height, enqueue jobs in
   CHUNK-sized batches.  Each job = (height flags k . checks)."
  (lambda (checks height flags)
    (let ((n (length checks)))
      (vq-register vq height n)
      (loop with grp = '() and k = 0
            for c in checks do
              (push c grp) (incf k)
              (when (= k *vq-chunk*)
                (when (vqueue-failed vq) (return))
                (vq-put vq (list* height flags k grp))
                (setf grp '() k 0))
            finally (when (and (plusp k) (not (vqueue-failed vq)))
                      (vq-put vq (list* height flags k grp)))))))

(defun vq-drained-p (vq h) (or (vqueue-failed vq) (>= (vqueue-verified vq) h)))
(defun vq-stop (vq)
  (dotimes (i (length (vqueue-workers vq))) (vq-put vq :stop))
  (mapc #'bt:join-thread (vqueue-workers vq)))

;;; ----------------------------------------------------------------------------
;;; Parallel ordered download queue.  N fetcher threads (each on its OWN peer
;;; connection — get-blocks installs one "block" handler per peer) claim batch
;;; ranges from a shared cursor and download concurrently; the consumer pulls
;;; batches back in STRICT height order via a reorder buffer.  One lock + one
;;; condition var; predicates re-checked after every wake.
;;; ----------------------------------------------------------------------------
(defstruct (ibd-q (:constructor %make-ibd-q))
  (lock (bt:make-lock)) (cv (bt:make-condition-variable))
  (next-lo 0) (to 0) (batch 64)
  (expected 0)
  (ready (make-hash-table))             ; batch-lo -> (cons hi blocks)
  (inflight 0) (max-inflight 8)         ; downloaded-but-not-consumed batches
  (live 0) (nthreads 1)                 ; fetchers still running
  (err nil))

(defun %ibd-wake-all (q)
  ;; bt:condition-notify wakes one waiter; wake every known waiter (consumer + N
  ;; fetchers) so no party starves.  State changes are per-batch, so this is cheap.
  (dotimes (i (1+ (ibd-q-nthreads q))) (bt:condition-notify (ibd-q-cv q))))

(defun ibd-fetcher (q peer0 batch to &optional peer-source)
  "Claim successive batch ranges from the shared cursor, download each from this
   fetcher's peer (outside the lock), deposit into the reorder buffer in order.
   On peer failure, if PEER-SOURCE is given, disconnect the dead peer and pull a
   fresh one to retry the SAME range (so one flaky public peer doesn't abort the
   run); only abort when no replacement is available."
  (let ((peer peer0))
    (block fetcher
      (loop
        (let (lo hi)
          (bt:with-lock-held ((ibd-q-lock q))
            (when (or (ibd-q-err q) (> (ibd-q-next-lo q) to))
              (decf (ibd-q-live q)) (%ibd-wake-all q) (return-from fetcher))
            (setf lo (ibd-q-next-lo q)
                  hi (min to (+ lo batch -1))
                  (ibd-q-next-lo q) (1+ hi)))
          (let ((hashes (loop for x from lo to hi collect (c:header-hash (c:header-at-height x))))
                (blocks nil))
            ;; download this range, swapping the peer out on failure
            (loop
              (when (ibd-q-err q) (return-from fetcher))
              (setf blocks (handler-case (blk:get-blocks peer hashes :timeout 30 :retries 3)
                             (serious-condition () nil)))
              (when blocks (return))                ; got the batch
              (ignore-errors (p:disconnect peer))   ; dead peer
              (let ((repl (and peer-source (funcall peer-source))))
                (cond
                  (repl (setf peer repl)
                        (format t "~&[ibd] fetcher swapped in fresh peer ~a:~d~%"
                                (p:peer-host repl) (p:peer-port repl)) (force-output))
                  (t (bt:with-lock-held ((ibd-q-lock q))
                       (unless (ibd-q-err q)
                         (setf (ibd-q-err q)
                               (make-condition 'simple-error
                                 :format-control "no live peer to fetch heights ~d-~d"
                                 :format-arguments (list lo hi))))
                       (decf (ibd-q-live q)) (%ibd-wake-all q))
                     (return-from fetcher)))))
            (bt:with-lock-held ((ibd-q-lock q))
              ;; backpressure: wait for a slot, UNLESS this is the batch the consumer
              ;; is starving for (lo = expected) — that one is always admitted, which
              ;; (with max-inflight >= nthreads) makes deadlock impossible.
              (loop until (or (ibd-q-err q)
                              (< (ibd-q-inflight q) (ibd-q-max-inflight q))
                              (= lo (ibd-q-expected q)))
                    do (bt:condition-wait (ibd-q-cv q) (ibd-q-lock q)))
              (when (ibd-q-err q) (decf (ibd-q-live q)) (%ibd-wake-all q) (return-from fetcher))
              (setf (gethash lo (ibd-q-ready q)) (cons hi blocks))
              (incf (ibd-q-inflight q))
              (%ibd-wake-all q))))))))

(defun ibd-pull (q)
  "Block until the batch starting at EXPECTED is ready; return (values bh blocks),
   or (values :done nil) at end-of-stream.  Re-signals the first fetch error."
  (bt:with-lock-held ((ibd-q-lock q))
    (loop
      (when (ibd-q-err q) (error (ibd-q-err q)))
      (let ((cell (gethash (ibd-q-expected q) (ibd-q-ready q))))
        (when cell
          (remhash (ibd-q-expected q) (ibd-q-ready q))
          (let ((bh (ibd-q-expected q)) (hi (car cell)) (blocks (cdr cell)))
            (setf (ibd-q-expected q) (1+ hi))
            (decf (ibd-q-inflight q))
            (%ibd-wake-all q)
            (return-from ibd-pull (values bh blocks)))))
      (when (and (> (ibd-q-next-lo q) (ibd-q-to q)) (zerop (ibd-q-live q)))
        (return-from ibd-pull (values :done nil)))
      (bt:condition-wait (ibd-q-cv q) (ibd-q-lock q)))))

(defun run-ibd-async (peer-or-peers utxo &key (from 1) (to (c:tip-height)) (batch 64)
                                     (assumevalid-below 0) (save-every 10000)
                                     (workers 100) (progress-every 1000) (maxq 8192)
                                     max-inflight peer-source undo-sink undo-checkpoint)
  "Pipelined IBD: N fetcher threads (one per peer in PEER-OR-PEERS — pass a single
   peer or a list) download blocks in parallel while connect runs them in order
   and WORKERS verify scripts asynchronously across all cores.  Below
   ASSUMEVALID-BELOW scripts are skipped.  Checkpoints (every SAVE-EVERY) drain to
   a fully-verified height first.  Returns the last verified height."
  ;; Nothing to do (already at/after the tip): return immediately.  Otherwise the
  ;; final drain loop (until vq-drained-p ... last) would spin forever, because no
  ;; blocks => no verify jobs => the queue never reaches LAST.
  (when (> from to)
    (return-from run-ibd-async (1- from)))
  (let* ((peers (if (listp peer-or-peers) peer-or-peers (list peer-or-peers)))
         (n (length peers))
         (mi (or max-inflight (max (* 2 n) 4)))
         (vq (make-vqueue :maxq maxq :workers workers))
         (sink (vq-sink vq)) (t0 (get-internal-real-time)) (last (1- from))
         (wait 0) (cn 0)                ; producer wait-for-batch vs serial-pass time
         (q (%make-ibd-q :to to :batch batch :next-lo from :expected from
                         :max-inflight mi :live n :nthreads n)))
    (labels ((fail-check ()
               (when (vqueue-failed vq)
                 (destructuring-bind (h ti ii msg) (vqueue-failed vq)
                   (vq-stop vq) (cerr h "tx ~d input ~d: ~a" ti ii msg)))))
      (let ((fetchers
              (loop for peer in peers collect
                (bt:make-thread (let ((peer peer)) (lambda () (ibd-fetcher q peer batch to peer-source)))
                                :name "ibd-fetch"))))
        (unwind-protect
          (progn
            (format t "~&[ibd] ~d fetcher(s), max-inflight ~d~%" n mi) (force-output)
            (loop
              (fail-check)
              (let (bh blocks)
                (let ((w0 (get-internal-real-time)))
                  (multiple-value-setq (bh blocks) (ibd-pull q))
                  (incf wait (- (get-internal-real-time) w0)))  ; download-bound time
                (when (eq bh :done) (return))
                ;; structural checks (pure block fns) across cores, then the
                ;; ordered serial connect pass (UTXO + verify-enqueue).
                (let ((sts (get-internal-real-time)))
                  (multiple-value-bind (ok fh msg) (prevalidate-structural blocks bh (min 32 workers))
                    (unless ok (cerr fh "~a" msg)))
                  (incf *cb-struct* (- (get-internal-real-time) sts)))
                (loop for b across blocks for h from bh do
                  (unless b (cerr h "peer did not return block"))
                  (let ((cn0 (get-internal-real-time)))
                    (multiple-value-bind (fees undo)
                        (connect-block b h utxo :verify-scripts (>= h assumevalid-below)
                                               :check-sink sink :skip-structural t)
                      (declare (ignore fees))
                      ;; record per-block undo for reorg roll-back (sink buffers it;
                      ;; UNDO-CHECKPOINT persists it in lockstep with the UTXO save).
                      (when undo-sink (funcall undo-sink h undo)))
                    (incf cn (- (get-internal-real-time) cn0)))
                  (setf last h)
                  (when (zerop (mod h progress-every))
                    (let ((secs (/ (- (get-internal-real-time) t0) internal-time-units-per-second)))
                      (format t "~&[ibd] height ~d  verified ~d  utxos ~d  total ~,4f BTC  ~,0f blk/s  [wait ~,1f cn ~,1f loop ~,1f sink ~,1f lag ~d]~%"
                              h (vqueue-verified vq) (u:utxo-count utxo) (/ (u:utxo-set-total-value utxo) 1d8)
                              (if (plusp secs) (/ (- h from -1) secs) 0)
                              (/ wait internal-time-units-per-second) (/ cn internal-time-units-per-second)
                              (/ *cb-loop* internal-time-units-per-second) (/ *cb-sink* internal-time-units-per-second)
                              (- h (vqueue-verified vq)))
                      (force-output)))
                  (when (and save-every (zerop (mod h save-every)))
                    (loop until (vq-drained-p vq h) do (sleep 0.02))
                    (fail-check) (u:save-utxo utxo (chainstate-path) h)
                    (when undo-checkpoint (funcall undo-checkpoint))
                    (format t "~&[ibd] checkpoint @ ~d (verified)~%" h) (force-output)))))
            (when (ibd-q-err q) (error (ibd-q-err q)))
            (loop until (vq-drained-p vq last) do (sleep 0.02))
            (fail-check)
            (when save-every (u:save-utxo utxo (chainstate-path) last)
                  (when undo-checkpoint (funcall undo-checkpoint)))
            last)
          (progn
            ;; force any still-running fetchers to exit, then reap them
            (bt:with-lock-held ((ibd-q-lock q))
              (unless (ibd-q-err q) (setf (ibd-q-err q) :shutdown))
              (%ibd-wake-all q))
            (ignore-errors (mapc #'bt:join-thread fetchers))
            (ignore-errors (vq-stop vq))))))))

(defvar *cb-loop* 0) (defvar *cb-sink* 0) (defvar *cb-struct* 0)   ; instrumentation

(defun check-structural (block height)
  "Block-only consensus checks (no UTXO / no ordering dependency): merkle root,
   BIP141 witness commitment, weight, sigop cost.  Pure fn of (block,height), so
   it parallelizes across a download batch.  Signals CONSENSUS-ERROR on failure."
  (unless (blk:verify-merkle block) (cerr height "merkle root mismatch"))
  (check-witness-commitment block height)
  (let ((wt (block-weight block)))
    (when (> wt *max-block-weight*) (cerr height "block weight ~d exceeds ~d" wt *max-block-weight*)))
  (let ((so (count-sigops block)))
    (when (> so *max-block-sigops*) (cerr height "sigop cost ~d exceeds ~d" so *max-block-sigops*))))

(defun prevalidate-structural (blocks from-height &optional (workers *verify-workers*))
  "Run check-structural on a batch of BLOCKS (heights FROM-HEIGHT..) across
   WORKERS threads.  Returns (values ok height msg) — the first failing block, or
   T.  One spawn set per BATCH (not per block), so thread overhead is amortised."
  (let* ((n (length blocks)) (fail (cons nil nil)) (lock (bt:make-lock)))
    (when (zerop n) (return-from prevalidate-structural (values t nil nil)))
    (let* ((nw (max 1 (min workers n))) (per (ceiling n nw)) (threads '()))
      (dotimes (w nw)
        (let ((lo (* w per)) (hi (min n (* (1+ w) per))))
          (when (< lo hi)
            (push (bt:make-thread
                   (let ((lo lo) (hi hi))
                     (lambda ()
                       (loop for i from lo below hi until (car fail) do
                         (let ((b (aref blocks i)) (h (+ from-height i)))
                           (when b
                             (handler-case (check-structural b h)
                               (consensus-error (e)
                                 (bt:with-lock-held (lock)
                                   (unless (car fail) (setf (car fail) h (cdr fail) (princ-to-string e))))))))))))
                  threads))))
      (mapc #'bt:join-thread threads))
    (if (car fail) (values nil (car fail) (cdr fail)) (values t nil nil))))

(defun connect-block (block height utxo &key (verify-scripts t) check-sink skip-structural)
  "Validate BLOCK at HEIGHT against UTXO and apply it.  Returns
   (values total-fees block-undo).  Signals CONSENSUS-ERROR on a rule violation.
   With CHECK-SINK (a function of (checks height flags)), the script checks are
   handed off instead of verified here — the async/pipelined IBD path; the UTXO
   pass and all non-script rules still run inline and in order."
  (let* ((txs (blk:block-txs block))
         (flags (consensus-flags height))
         (mtp (block-mtp height))
         (enforce-locks (>= height (height-of :csv)))
         (total-fees 0)
         (coinbase-claimed 0)
         (checks '())                   ; deferred script-verification jobs
         (undo (make-block-undo)))
    ;; block-only structural checks — skipped here when already run in parallel
    ;; across the batch (SKIP-STRUCTURAL); see PREVALIDATE-STRUCTURAL.
    (unless skip-structural
      (let ((%sts (get-internal-real-time)))
        (check-structural block height)
        (incf *cb-struct* (- (get-internal-real-time) %sts))))
    ;; coinbase structure + BIP34 (coinbase must encode its own height)
    (let ((cb (aref txs 0)))
      (unless (tx:tx-coinbase-p cb) (cerr height "first tx is not a coinbase"))
      (when (>= height (height-of :bip34))
        (let ((ss (tx:txin-script (first (tx:tx-inputs cb)))))
          (unless (bip34-height-ok ss height)
            (cerr height "BIP34: coinbase does not encode height ~d" height)))))
    ;; single pass, in order: validate a tx's inputs, then immediately add its
    ;; outputs — so a later tx may spend an earlier tx in the SAME block, but
    ;; not a later one (Bitcoin's ordering rule).
    (let ((%ls (get-internal-real-time)))
    (loop for txn across txs
          for tx-i from 0
          for coinbase = (tx:tx-coinbase-p txn) do
      ;; IsFinalTx (BIP113 uses median-time-past; older blocks use block time)
      (unless (final-tx-p txn height (if enforce-locks mtp
                                         (c:header-time (c:header-at-height height))))
        (cerr height "tx ~d is not final (locktime)" tx-i))
      (if coinbase
          (setf coinbase-claimed
                (reduce #'+ (tx:tx-outputs txn) :key #'tx:txout-value :initial-value 0))
          (let ((total-in 0) (tx-coins '()))   ; tx-coins: (value . script) per input
            (loop for in in (tx:tx-inputs txn)
                  for in-i from 0 do
              (let ((coin (u:utxo-spend utxo (tx:txin-prev-hash in) (tx:txin-prev-index in))))
                (unless coin
                  (cerr height "tx ~d input ~d: missing/spent outpoint ~a:~d"
                        tx-i in-i (w:hash->hex (tx:txin-prev-hash in)) (tx:txin-prev-index in)))
                (push (list (tx:txin-prev-hash in) (tx:txin-prev-index in) coin)
                      (block-undo-spent undo))
                ;; coinbase maturity
                (when (and (u:coin-coinbase-p coin)
                           (< (- height (u:coin-height coin)) *coinbase-maturity*))
                  (cerr height "tx ~d input ~d: premature coinbase spend (age ~d)"
                        tx-i in-i (- height (u:coin-height coin))))
                ;; BIP68 relative locktime (version>=2, active from CSV height)
                (when (and enforce-locks (>= (tx:tx-version txn) 2))
                  (unless (sequence-lock-ok coin (tx:txin-sequence in) height mtp)
                    (cerr height "tx ~d input ~d: BIP68 relative locktime not met" tx-i in-i)))
                (push (cons (u:coin-value coin) (u:coin-script coin)) tx-coins)
                (incf total-in (u:coin-value coin))))
            ;; script verification — deferred and fanned across cores after the
            ;; sequential pass (scripts don't touch the UTXO set).  The taproot
            ;; (BIP341) sighash commits to ALL of the tx's prevouts, so each check
            ;; carries the per-tx PV vector #((amount . spk) ...) in input order.
            (when verify-scripts
              (let ((pv (coerce (nreverse tx-coins) 'vector)))
                (dotimes (i (length pv))
                  (push (list txn i (cdr (aref pv i)) (car (aref pv i)) tx-i pv) checks))))
            ;; value conservation
            (let ((total-out (reduce #'+ (tx:tx-outputs txn) :key #'tx:txout-value :initial-value 0)))
              (when (> total-out total-in)
                (cerr height "tx ~d: outputs (~d) exceed inputs (~d)" tx-i total-out total-in))
              (incf total-fees (- total-in total-out)))))
      ;; add this tx's spendable outputs to the set
      (loop for out in (tx:tx-outputs txn)
            for vout from 0 do
        (unless (unspendable-p (tx:txout-script out))
          ;; BIP30: must not overwrite an existing unspent coin.  BIP34 (height
          ;; in coinbase) makes duplicate txids impossible above its activation,
          ;; so — like Core — skip the per-output lookup there (the two
          ;; pre-BIP34 duplicate-coinbase blocks are the *-exceptions*).
          (when (and (< height (height-of :bip34))
                     (not (member height *bip30-exceptions*))
                     (u:utxo-get utxo (tx:tx-txid txn) vout))
            (cerr height "BIP30: duplicate unspent outpoint ~a:~d"
                  (w:hash->hex (tx:tx-txid txn)) vout))
          (u:utxo-add utxo (tx:tx-txid txn) vout
                      (u:make-coin :value (tx:txout-value out)
                                   :script (tx:txout-script out)
                                   :height height :coinbase-p coinbase))
          (push (cons (tx:tx-txid txn) vout) (block-undo-created undo)))))
    (incf *cb-loop* (- (get-internal-real-time) %ls)))
    ;; coinbase value check: claimed <= subsidy + fees
    (let ((allowed (+ (block-subsidy height) total-fees)))
      (when (> coinbase-claimed allowed)
        (cerr height "coinbase claims ~d > allowed ~d (subsidy ~d + fees ~d)"
              coinbase-claimed allowed (block-subsidy height) total-fees)))
    ;; script checks: hand to the async sink if present (register the height even
    ;; with zero checks, so the verified-watermark advances), else verify now.
    (if check-sink
        (let ((%ss (get-internal-real-time)))
          (funcall check-sink (and verify-scripts (nreverse checks)) height flags)
          (incf *cb-sink* (- (get-internal-real-time) %ss)))
        (when (and verify-scripts checks)
          (multiple-value-bind (ok msg tx-i in-i)
              (verify-block-scripts (coerce (nreverse checks) 'vector) flags)
            (unless ok (cerr height "tx ~d input ~d: ~a" tx-i in-i msg)))))
    (values total-fees undo)))

;;; ----------------------------------------------------------------------------
;;; BIP34 — coinbase scriptSig begins with a push of the block height
;;; ----------------------------------------------------------------------------

(defun bip34-height-ok (scriptsig height)
  (and (plusp (length scriptsig))
       (let* ((n (aref scriptsig 0)))
         (and (<= 1 n 8) (<= (1+ n) (length scriptsig))
              (let ((v 0))
                (dotimes (i n) (setf v (logior v (ash (aref scriptsig (1+ i)) (* 8 i)))))
                (= v height))))))

;;; ----------------------------------------------------------------------------
;;; disconnect-block — reverse a block's effect on the UTXO set (reorg support)
;;; ----------------------------------------------------------------------------

(defun disconnect-block (undo utxo)
  "Undo a connected block: remove the coins it created, restore the coins it
   spent.  Returns UTXO."
  ;; remove created outputs
  (dolist (c (block-undo-created undo))
    (u:utxo-spend utxo (car c) (cdr c)))
  ;; restore spent coins
  (dolist (sp (block-undo-spent undo))
    (destructuring-bind (txid index coin) sp
      (u:utxo-add utxo txid index coin)))
  utxo)

;;; ----------------------------------------------------------------------------
;;; IBD driver — download + connect blocks in order
;;; ----------------------------------------------------------------------------

(defun chainstate-path (&optional height)
  (merge-pathnames (if height (format nil "chainstate-~d.dat" height) "chainstate.dat")
                   (c:data-dir)))

(defun run-ibd (peer utxo &key (from 1) (to (c:tip-height)) (batch 64)
                               (verify-scripts t) (progress-every 5000)
                               (assumevalid-below 0) (save-every nil))
  "Download and connect blocks [FROM, TO] in order, applying each to UTXO.
   Below ASSUMEVALID-BELOW, scripts are not re-verified (still applies every
   other rule).  With SAVE-EVERY, checkpoint the UTXO set to disk every N
   blocks so a long run is resumable (load-utxo + run-ibd :from height+1).
   Returns the last height connected."
  (let* ((height from) (t0 (get-internal-real-time)) (last height))
    (loop while (<= height to) do
      (let* ((hi (min to (+ height batch -1)))
             (hashes (loop for h from height to hi
                           collect (c:header-hash (c:header-at-height h))))
             (blocks (blk:get-blocks peer hashes)))
        (loop for b across blocks
              for h from height do
          (unless b (cerr h "peer did not return block"))
          (connect-block b h utxo
                         :verify-scripts (and verify-scripts (>= h assumevalid-below)))
          (setf last h)
          (when (zerop (mod h progress-every))
            (let ((secs (/ (- (get-internal-real-time) t0) internal-time-units-per-second)))
              (format t "~&[ibd] height ~d  utxos ~d  total ~,4f BTC  ~,0f blk/s~%"
                      h (u:utxo-count utxo)
                      (/ (u:utxo-set-total-value utxo) 1d8)
                      (if (plusp secs) (/ (- h from -1) secs) 0))
              (force-output)))
          (when (and save-every (zerop (mod h save-every)))
            (u:save-utxo utxo (chainstate-path) h)))
        (setf height (1+ hi))))
    (when save-every (u:save-utxo utxo (chainstate-path) last))
    last))

(defun resume-ibd (peer &key (to (c:tip-height)) (batch 64) (verify-scripts t)
                             (save-every 25000) (progress-every 5000))
  "Resume IBD from the last on-disk chainstate checkpoint (or from genesis if
   none).  Saves periodically.  Returns (values last-height utxo)."
  (multiple-value-bind (utxo height) (u:load-utxo (chainstate-path))
    (unless utxo (setf utxo (u:make-utxo-set) height 0))
    (format t "~&[resume] starting from height ~d~%" height)
    (values (run-ibd peer utxo :from (1+ height) :to to :batch batch
                     :verify-scripts verify-scripts :save-every save-every
                     :progress-every progress-every)
            utxo)))

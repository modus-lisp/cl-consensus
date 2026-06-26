;;;; src/mempool.lisp
;;;;
;;;; The mempool: accept unconfirmed transactions, validating each against the UTXO
;;;; set (and against earlier unconfirmed txs it may spend), rejecting double-spends
;;;; and value creation, and tracking fee/vsize.
;;;;
;;;; Beyond bare acceptance this layer carries the RELAY-POLICY maturity a real node
;;;; needs so it can safely gossip txs from the network:
;;;;   - a minimum relay feerate + a dynamic floor that rises as the pool fills
;;;;   - standardness gates: max tx weight, dust outputs, locktime finality
;;;;   - BIP125 opt-in Replace-By-Fee (replace conflicting txs that pay enough more)
;;;;   - in-mempool parent/child links (package awareness)
;;;;   - size-cap eviction (drop the cheapest leaf packages) + time expiry
;;;;
;;;; Verified by replaying real block N+1 txs against a UTXO set built to height N,
;;;; and by inspect/mempool-test.lisp for the policy/RBF/eviction paths.


(defpackage #:cl-consensus.mempool
  (:use #:cl)
  (:nicknames #:btc-mempool)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script) (#:u #:cl-consensus.utxo)
                    (#:v #:cl-consensus.validate))
  (:export
   #:mempool #:make-mempool #:mempool-size #:mempool-bytes #:mempool-floor-feerate
   #:entry #:entry-tx #:entry-fee #:entry-vsize #:entry-time #:entry-feerate
   #:entry-parents #:entry-children #:entry-replaceable
   #:accept-tx #:mempool-get #:mempool-txids #:mempool-conflicts-p #:mempool-remove
   #:mempool-on-block #:trim-mempool #:expire-mempool #:gather-descendants
   #:save-mempool #:load-mempool
   #:*min-relay-feerate* #:*max-standard-tx-weight* #:*max-mempool-bytes*
   #:*mempool-expiry-seconds* #:*max-rbf-replacements* #:dust-threshold #:final-tx-p
   #:rejected #:rejected-reason))

(in-package #:cl-consensus.mempool)

;;; ----------------------------------------------------------------------------
;;; Policy knobs (sat/vB for feerates, bytes for sizes, seconds for ages)
;;; ----------------------------------------------------------------------------

(defparameter *min-relay-feerate* 1
  "Floor relay feerate in sat/vB; a tx paying less is not relayed.")
(defparameter *dust-relay-feerate* 3
  "Feerate (sat/vB) used to size the dust threshold (Core's dustRelayFee = 3000/kvB).")
(defparameter *max-standard-tx-weight* 400000
  "Largest standard tx weight (Core MAX_STANDARD_TX_WEIGHT).")
(defparameter *max-mempool-bytes* (* 300 1024 1024)
  "Soft cap on mempool serialized bytes; over it, evict the cheapest leaf packages.")
(defparameter *mempool-expiry-seconds* (* 336 3600)
  "Drop entries older than this (Core default 336h = 14 days).")
(defparameter *max-rbf-replacements* 100
  "BIP125 rule 5: a replacement may evict at most this many txs.")

;;; ----------------------------------------------------------------------------
;;; Structures
;;; ----------------------------------------------------------------------------

(defstruct (mempool (:constructor %make-mempool))
  (entries (make-hash-table :test 'equal))   ; txid hex -> entry
  (spent (make-hash-table :test 'equal))     ; "txid:idx" -> spending txid hex
  (bytes 0)                                   ; sum of total-size of member txs
  (floor-feerate 0))                          ; dynamic min feerate raised by eviction

(defun make-mempool () (%make-mempool))

(defstruct entry
  tx fee vsize time
  (parents '())        ; txid-hex of in-mempool txs this spends
  (children '())       ; txid-hex of in-mempool txs that spend this
  (replaceable nil))   ; BIP125: opt-in (own signal) or inherited from a parent

(defun entry-feerate (e) (/ (entry-fee e) (max 1 (entry-vsize e)))) ; sat/vB (rational)

(defun mempool-size (mp) (hash-table-count (mempool-entries mp)))
(defun mempool-get (mp txid-hex) (gethash txid-hex (mempool-entries mp)))
(defun mempool-txids (mp)
  (loop for k being the hash-keys of (mempool-entries mp) collect k))

(define-condition rejected (error)
  ((reason :initarg :reason :reader rejected-reason))
  (:report (lambda (c st) (format st "tx rejected: ~a" (rejected-reason c)))))

(defun rej (fmt &rest args) (error 'rejected :reason (apply #'format nil fmt args)))

(defun outpoint-key (hash idx) (format nil "~a:~d" (w:hash->hex hash) idx))

;;; ----------------------------------------------------------------------------
;;; Standardness helpers
;;; ----------------------------------------------------------------------------

(defun dust-threshold (out)
  "Minimum non-dust value for output OUT, sat.  An output is dust if it costs more to
   spend than it's worth: 3 * (output size + amortized spend size) * dustRelayFee.
   Matches Core's well-known thresholds (P2PKH 546, P2WPKH 294).  OP_RETURN outputs are
   provably-unspendable and exempt (threshold 0)."
  (let ((script (tx:txout-script out)))
    (when (and (plusp (length script)) (= (aref script 0) #x6a)) ; OP_RETURN
      (return-from dust-threshold 0))
    (let* ((witness (and (>= (length script) 2) (= (aref script 0) 0)
                         (member (aref script 1) '(20 32))))
           (out-size (+ 8 1 (length script)))   ; value(8) + varint len(1) + script
           (spend-size (if witness 67 148)))    ; input incl. amortized witness/4
      (* *dust-relay-feerate* (+ out-size spend-size)))))

(defun final-tx-p (txn height time)
  "IsFinalTx: is TXN final for inclusion at HEIGHT with median-time-past TIME?  A tx
   with locktime 0, or below the height/time horizon, or with every input sequence
   final (0xffffffff), is final."
  (let ((lt (tx:tx-locktime txn)))
    (or (zerop lt)
        (< lt (if (< lt 500000000) height time))
        (every (lambda (in) (= (tx:txin-sequence in) #xffffffff)) (tx:tx-inputs txn)))))

(defun signals-rbf-p (txn)
  "BIP125 opt-in: any input with sequence < 0xfffffffe signals replaceability."
  (some (lambda (in) (< (tx:txin-sequence in) #xfffffffe)) (tx:tx-inputs txn)))

;;; ----------------------------------------------------------------------------
;;; Conflict / coin resolution
;;; ----------------------------------------------------------------------------

(defun mempool-conflicts-p (mp txn)
  "T if any of TXN's inputs is already spent by a mempool tx."
  (some (lambda (in) (gethash (outpoint-key (tx:txin-prev-hash in) (tx:txin-prev-index in))
                              (mempool-spent mp)))
        (tx:tx-inputs txn)))

(defun direct-conflicts (mp txn)
  "The set (list of txid-hex) of mempool txs that DIRECTLY conflict with TXN's inputs."
  (remove-duplicates
   (loop for in in (tx:tx-inputs txn)
         for c = (gethash (outpoint-key (tx:txin-prev-hash in) (tx:txin-prev-index in))
                          (mempool-spent mp))
         when c collect c)
   :test #'string=))

(defun lookup-coin (utxo mp hash idx)
  "Resolve an outpoint to (values amount script coinbase-p height) from the UTXO set,
   or from an unconfirmed parent already in the mempool."
  (let ((coin (and utxo (u:utxo-get utxo hash idx))))
    (if coin
        (values (u:coin-value coin) (u:coin-script coin)
                (u:coin-coinbase-p coin) (u:coin-height coin))
        (let ((parent (gethash (w:hash->hex hash) (mempool-entries mp))))
          (when parent
            (let ((out (nth idx (tx:tx-outputs (entry-tx parent)))))
              (when out (values (tx:txout-value out) (tx:txout-script out) nil -1))))))))

;;; ----------------------------------------------------------------------------
;;; Removal + package walks
;;; ----------------------------------------------------------------------------

(defun gather-descendants (mp txid-hex &optional (acc (make-hash-table :test 'equal)))
  "Collect TXID-HEX and all its in-mempool descendants into ACC (a hash set), returning
   ACC."
  (unless (gethash txid-hex acc)
    (setf (gethash txid-hex acc) t)
    (let ((e (gethash txid-hex (mempool-entries mp))))
      (when e (dolist (c (entry-children e)) (gather-descendants mp c acc)))))
  acc)

(defun %remove-entry (mp txid-hex)
  "Remove one entry, freeing its spent-outpoint claims and unlinking it from parents/
   children.  Returns T if an entry was present."
  (let ((e (gethash txid-hex (mempool-entries mp))))
    (when e
      (dolist (in (tx:tx-inputs (entry-tx e)))
        (remhash (outpoint-key (tx:txin-prev-hash in) (tx:txin-prev-index in))
                 (mempool-spent mp)))
      (dolist (p (entry-parents e))
        (let ((pe (gethash p (mempool-entries mp))))
          (when pe (setf (entry-children pe) (remove txid-hex (entry-children pe) :test #'string=)))))
      (dolist (ch (entry-children e))
        (let ((ce (gethash ch (mempool-entries mp))))
          (when ce (setf (entry-parents ce) (remove txid-hex (entry-parents ce) :test #'string=)))))
      (decf (mempool-bytes mp) (tx:tx-total-size (entry-tx e)))
      (remhash txid-hex (mempool-entries mp))
      t)))

(defun mempool-remove (mp txid-hex &key descendants)
  "Remove TXID-HEX (and, with :DESCENDANTS, everything spending it).  Returns the count
   removed.  Used when a block confirms/conflicts txs, and by eviction."
  (let ((set (if descendants (gather-descendants mp txid-hex)
                 (let ((h (make-hash-table :test 'equal))) (setf (gethash txid-hex h) t) h)))
        (n 0))
    (loop for k being the hash-keys of set do (when (%remove-entry mp k) (incf n)))
    n))

(defun mempool-on-block (mp txs)
  "Reconcile the mempool when a block confirms TXS: drop each confirmed tx, and drop any
   mempool tx that now conflicts (double-spends a just-confirmed input) along with its
   descendants.  A confirmed tx's in-mempool children stay (they now spend confirmed
   coins) — %remove-entry unlinks them.  Returns the count removed."
  (let ((n 0))
    (dolist (txn txs)
      (let ((txid-hex (tx:txid-hex txn)))
        ;; a DIFFERENT mempool tx spending one of this tx's inputs is now a dead double-spend
        (dolist (in (tx:tx-inputs txn))
          (let ((spender (gethash (outpoint-key (tx:txin-prev-hash in) (tx:txin-prev-index in))
                                  (mempool-spent mp))))
            (when (and spender (not (string= spender txid-hex)))
              (incf n (mempool-remove mp spender :descendants t)))))
        (when (gethash txid-hex (mempool-entries mp))
          (incf n (mempool-remove mp txid-hex)))))
    n))

;;; ----------------------------------------------------------------------------
;;; BIP125 Replace-By-Fee
;;; ----------------------------------------------------------------------------

(defun check-rbf (mp txn fee vsize conflicts)
  "Validate replacing CONFLICTS (direct-conflict txid-hex list) with TXN per BIP125,
   signalling REJECTED on any rule violation.  Returns the full eviction set (hash set
   of txid-hex = conflicts plus all their descendants)."
  ;; Rule 1: every directly-conflicting tx must itself be replaceable (opt-in/inherited).
  (dolist (c conflicts)
    (let ((e (gethash c (mempool-entries mp))))
      (when (and e (not (entry-replaceable e)))
        (rej "txn-mempool-conflict: conflicts with irreplaceable tx (BIP125 rule 1)"))))
  (let ((evict (make-hash-table :test 'equal)))
    (dolist (c conflicts) (gather-descendants mp c evict))
    ;; Rule 5: bound the blast radius.
    (when (> (hash-table-count evict) *max-rbf-replacements*)
      (rej "too many potential replacements: ~d > ~d (BIP125 rule 5)"
           (hash-table-count evict) *max-rbf-replacements*))
    ;; Rule 2: no NEW unconfirmed inputs — any unconfirmed input of the replacement must
    ;; have been an input of one of the txs being evicted.
    (let ((orig-inputs (make-hash-table :test 'equal)))
      (loop for c being the hash-keys of evict do
        (let ((e (gethash c (mempool-entries mp))))
          (when e (dolist (in (tx:tx-inputs (entry-tx e)))
                    (setf (gethash (outpoint-key (tx:txin-prev-hash in) (tx:txin-prev-index in))
                                   orig-inputs) t)))))
      (dolist (in (tx:tx-inputs txn))
        (let ((ph (tx:txin-prev-hash in)) (pidx (tx:txin-prev-index in)))
          (when (and (gethash (w:hash->hex ph) (mempool-entries mp)) ; unconfirmed parent
                     (not (gethash (outpoint-key ph pidx) orig-inputs)))
            (rej "replacement adds a new unconfirmed input (BIP125 rule 2)")))))
    ;; Rules 3 & 4: the replacement must raise the absolute fee AND pay for its own
    ;; bandwidth (the incremental fee over what it evicts covers its relay at min-feerate).
    (let ((evicted-fee 0))
      (loop for c being the hash-keys of evict do
        (let ((e (gethash c (mempool-entries mp)))) (when e (incf evicted-fee (entry-fee e)))))
      (when (<= fee evicted-fee)
        (rej "insufficient fee: replacement ~d <= evicted ~d (BIP125 rule 3)" fee evicted-fee))
      (when (< (- fee evicted-fee) (* vsize *min-relay-feerate*))
        (rej "insufficient fee to pay for replacement bandwidth (BIP125 rule 4)")))
    evict))

;;; ----------------------------------------------------------------------------
;;; Eviction + expiry
;;; ----------------------------------------------------------------------------

(defun trim-mempool (mp &optional (limit *max-mempool-bytes*))
  "Evict the lowest-feerate LEAF entries (no in-mempool children — so we never orphan a
   child and CPFP parents are kept while their paying child remains) until usage <=
   LIMIT.  Raises the dynamic floor to the highest evicted feerate so the trimmed txs
   aren't immediately re-accepted.  Returns the count evicted."
  (let ((n 0))
    (loop while (> (mempool-bytes mp) limit) do
      (let ((victim nil) (vfr nil))
        (loop for k being the hash-keys of (mempool-entries mp) using (hash-value e)
              when (null (entry-children e)) do
          (let ((fr (entry-feerate e)))
            (when (or (null vfr) (< fr vfr)) (setf victim k vfr fr))))
        (unless victim (return))
        (setf (mempool-floor-feerate mp) (max (mempool-floor-feerate mp)
                                              (+ vfr *min-relay-feerate*)))
        (when (%remove-entry mp victim) (incf n))))
    n))

(defun expire-mempool (mp now &optional (max-age *mempool-expiry-seconds*))
  "Remove every entry (and its descendants) whose time is older than NOW - MAX-AGE.
   Returns the count removed."
  (let ((cutoff (- now max-age)) (n 0))
    (dolist (k (mempool-txids mp))
      (let ((e (gethash k (mempool-entries mp))))
        (when (and e (< (entry-time e) cutoff))
          (incf n (mempool-remove mp k :descendants t)))))
    n))

;;; ----------------------------------------------------------------------------
;;; Acceptance
;;; ----------------------------------------------------------------------------

(defun %insert-entry (mp txn txid-hex fee vsize time)
  "Add a validated TXN to MP: create its entry, claim its inputs in the spent map, wire
   parent/child links, and compute BIP125 replaceability."
  (let ((e (make-entry :tx txn :fee fee :vsize vsize :time time))
        (ins (tx:tx-inputs txn))
        (parents '()))
    (setf (gethash txid-hex (mempool-entries mp)) e)
    (dolist (in ins)
      (setf (gethash (outpoint-key (tx:txin-prev-hash in) (tx:txin-prev-index in))
                     (mempool-spent mp))
            txid-hex)
      (let ((ph (w:hash->hex (tx:txin-prev-hash in))))
        (when (gethash ph (mempool-entries mp)) (pushnew ph parents :test #'string=))))
    (setf (entry-parents e) parents)
    (dolist (p parents)
      (let ((pe (gethash p (mempool-entries mp))))
        (pushnew txid-hex (entry-children pe) :test #'string=)))
    (setf (entry-replaceable e)
          (or (signals-rbf-p txn)
              (some (lambda (p) (entry-replaceable (gethash p (mempool-entries mp)))) parents)))
    (incf (mempool-bytes mp) (tx:tx-total-size txn))
    e))

(defun accept-tx (txn utxo mp &key (height most-positive-fixnum) (time 0) (mtp time)
                                   check-only (trim t))
  "Validate TXN and add it to mempool MP (UTXO = confirmed coin set).  Returns the ENTRY
   on success; signals REJECTED otherwise.  HEIGHT selects soft-fork rules and the
   inclusion height for coinbase-maturity/finality (pass tip+1); MTP is the median time
   past for time-based finality.  CHECK-ONLY validates without mutating
   (testmempoolaccept).  TRIM runs size-cap eviction after a successful insert."
  (when (tx:tx-coinbase-p txn) (rej "coinbase not allowed in mempool"))
  (unless (tx:tx-txid txn) (tx:finalize-tx txn))   ; hand-built tx: compute ids/sizes
  (let ((txid-hex (tx:txid-hex txn)))
    (when (gethash txid-hex (mempool-entries mp)) (rej "already in mempool"))
    ;; --- cheap standardness gates (no input resolution needed) ---
    (when (null (tx:tx-inputs txn)) (rej "no inputs"))
    (when (null (tx:tx-outputs txn)) (rej "no outputs"))
    (when (> (tx:tx-weight txn) *max-standard-tx-weight*)
      (rej "tx weight ~d exceeds standard max ~d" (tx:tx-weight txn) *max-standard-tx-weight*))
    (unless (final-tx-p txn height mtp) (rej "non-final (locktime)"))
    (loop for out in (tx:tx-outputs txn) for i from 0 do
      (when (< (tx:txout-value out) (dust-threshold out))
        (rej "output ~d below dust threshold (~d < ~d)" i (tx:txout-value out) (dust-threshold out))))
    ;; --- resolve inputs (UTXO or unconfirmed parent) ---
    (let* ((ins (tx:tx-inputs txn))
           (prevouts (make-array (length ins)))
           (total-in 0))
      (loop for in in ins for i from 0 do
        (multiple-value-bind (amount script cb h)
            (lookup-coin utxo mp (tx:txin-prev-hash in) (tx:txin-prev-index in))
          (unless amount
            (rej "missing-inputs ~a:~d" (w:hash->hex (tx:txin-prev-hash in)) (tx:txin-prev-index in)))
          (when (and cb (>= h 0) (< (- height h) v:*coinbase-maturity*))
            (rej "premature coinbase spend"))
          (setf (aref prevouts i) (cons amount script))
          (incf total-in amount)))
      ;; --- value / fee + feerate floor ---
      (let* ((total-out (reduce #'+ (tx:tx-outputs txn) :key #'tx:txout-value :initial-value 0))
             (fee (- total-in total-out))
             (vsize (tx:tx-vsize txn)))
        (when (< fee 0) (rej "outputs (~d) exceed inputs (~d)" total-out total-in))
        (let ((floor (max *min-relay-feerate* (mempool-floor-feerate mp))))
          (when (< (/ fee (max 1 vsize)) floor)
            (rej "min relay fee not met (feerate ~,3f < ~,3f sat/vB)"
                 (float (/ fee (max 1 vsize))) (float floor))))
        ;; --- conflicts: reject, or replace under BIP125 ---
        (let* ((conflicts (direct-conflicts mp txn))
               (evict (when conflicts (check-rbf mp txn fee vsize conflicts))))
          ;; --- scripts (the expensive check, done last) ---
          (loop for in in ins for i from 0 do
            (handler-case
                (unless (s:verify-input txn i (cdr (aref prevouts i)) (car (aref prevouts i))
                                        :prevouts prevouts)
                  (rej "input ~d script verification failed" i))
              (s:script-error (e) (rej "input ~d: ~a" i e))))
          ;; --- commit ---
          (if check-only
              (make-entry :tx txn :fee fee :vsize vsize :time time)
              (progn
                (when evict
                  (loop for k being the hash-keys of evict do (%remove-entry mp k)))
                (let ((e (%insert-entry mp txn txid-hex fee vsize time)))
                  (when trim (trim-mempool mp))
                  ;; a just-inserted tx can itself be trimmed if it's the cheapest leaf
                  (if (gethash txid-hex (mempool-entries mp)) e
                      (rej "mempool full: feerate below eviction floor"))))))))))

;;; ----------------------------------------------------------------------------
;;; Persistence — survive a restart (re-validated against the current UTXO)
;;; ----------------------------------------------------------------------------

(defparameter +mempool-file-version+ 1)

(defun %read-file-bytes (path)
  (with-open-file (f path :element-type '(unsigned-byte 8))
    (let ((buf (make-array (file-length f) :element-type '(unsigned-byte 8))))
      (read-sequence buf f) buf)))

(defun save-mempool (mp path)
  "Write MP to PATH atomically (temp + rename): u32 version, varint count, then per tx
   [u64 entry-time, varint len, raw witness tx bytes].  Returns the count written.
   Policy/links/fees are NOT stored — they're recomputed on load by re-accepting."
  (let ((wr (w:make-writer)))
    (w:w-u32 wr +mempool-file-version+)
    (w:w-varint wr (mempool-size mp))
    (maphash (lambda (k e)
               (declare (ignore k))
               (let ((b (tx:serialize-tx (entry-tx e) :witness t)))
                 (w:w-u64 wr (entry-time e))
                 (w:w-varint wr (length b))
                 (w:w-bytes wr b)))
             (mempool-entries mp))
    (let ((tmp (concatenate 'string (namestring path) ".tmp")))
      (with-open-file (f tmp :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
        (write-sequence (w:writer-bytes wr) f)
        (finish-output f))
      (sb-posix:rename tmp (namestring path)))
    (mempool-size mp)))

(defun load-mempool (mp utxo path &key (height most-positive-fixnum) (mtp 0))
  "Re-populate MP from PATH, re-validating every tx against UTXO + current policy at
   HEIGHT/MTP — txs that no longer apply (inputs spent/confirmed while down, now below
   the fee floor, etc.) are silently dropped.  Each tx keeps its original entry-time.
   Re-adds in dependency order (retry rounds until no further progress, so a child saved
   before its in-mempool parent still lands).  Returns the count restored."
  (unless (probe-file path) (return-from load-mempool 0))
  (let* ((r (w:make-reader (%read-file-bytes path)))
         (ver (w:r-u32 r)))
    (unless (= ver +mempool-file-version+)
      (warn "mempool file version ~d (expected ~d); ignoring" ver +mempool-file-version+)
      (return-from load-mempool 0))
    (let ((n (w:r-varint r)) (pending '()))
      (dotimes (i n)
        (let* ((tm (w:r-u64 r)) (len (w:r-varint r)) (b (w:r-bytes r len))
               (txn (handler-case (tx:parse-tx (w:make-reader b)) (serious-condition () nil))))
          (when txn (push (cons tm txn) pending))))
      (let ((added 0))
        (loop
          (let ((progress nil) (still '()))
            (dolist (pt pending)
              (handler-case
                  (progn (accept-tx (cdr pt) utxo mp :height height :time (car pt) :mtp mtp :trim nil)
                         (incf added) (setf progress t))
                (rejected (e)
                  (when (search "missing-inputs" (rejected-reason e)) (push pt still)))
                (serious-condition () nil)))   ; any other failure -> drop that tx
            (setf pending still)
            (unless (and progress pending) (return))))
        added))))

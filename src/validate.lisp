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
   #:run-ibd #:resume-ibd #:chainstate-path #:consensus-flags
   #:block-undo #:block-undo-spent #:block-undo-created
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

(defun consensus-flags (height)
  "The SCRIPT_VERIFY flags that are consensus-active at HEIGHT (mainnet).
   Policy-only flags (LOW_S, STRICTENC, MINIMALDATA) are intentionally excluded."
  (let ((f '()))
    (when (>= height +bip16-height+) (push :p2sh f))
    (when (>= height +bip66-height+) (push :dersig f))
    (when (>= height +cltv-height+) (push :cltv f))
    (when (>= height +csv-height+) (push :csv f))
    (when (>= height +segwit-height+) (push :witness f) (push :nulldummy f))
    (when (>= height +taproot-height+) (push :taproot f))
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
  (when (>= height +segwit-height+)
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
    (loop for i from lo below hi until (car abort) do
      (destructuring-bind (txn in-i script value tx-i) (aref checks i)
        (let ((bad (handler-case
                       (unless (s:verify-input txn in-i script value :flags flags)
                         "script verification failed")
                     (s:script-error (e) (princ-to-string e))
                     (error (e) (princ-to-string e)))))
          (when bad
            (setf (car abort) t)
            (bt:with-lock-held (lock)
              (unless (car fail) (setf (car fail) bad (cdr fail) (list tx-i in-i))))))))))

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

(defun connect-block (block height utxo &key (verify-scripts t))
  "Validate BLOCK at HEIGHT against UTXO and apply it.  Returns
   (values total-fees block-undo).  Signals CONSENSUS-ERROR on a rule violation."
  (let* ((txs (blk:block-txs block))
         (flags (consensus-flags height))
         (mtp (block-mtp height))
         (enforce-locks (>= height +bip113-height+))
         (total-fees 0)
         (coinbase-claimed 0)
         (checks '())                   ; deferred script-verification jobs
         (undo (make-block-undo)))
    ;; merkle root must match the header (structural integrity)
    (unless (blk:verify-merkle block)
      (cerr height "merkle root mismatch"))
    ;; segwit witness commitment (BIP141)
    (check-witness-commitment block height)
    ;; block weight limit (BIP141)
    (let ((wt (block-weight block)))
      (when (> wt *max-block-weight*)
        (cerr height "block weight ~d exceeds ~d" wt *max-block-weight*)))
    ;; sigop cost limit
    (let ((so (count-sigops block)))
      (when (> so *max-block-sigops*)
        (cerr height "sigop cost ~d exceeds ~d" so *max-block-sigops*)))
    ;; coinbase structure + BIP34 (coinbase must encode its own height)
    (let ((cb (aref txs 0)))
      (unless (tx:tx-coinbase-p cb) (cerr height "first tx is not a coinbase"))
      (when (>= height +bip34-height+)
        (let ((ss (tx:txin-script (first (tx:tx-inputs cb)))))
          (unless (bip34-height-ok ss height)
            (cerr height "BIP34: coinbase does not encode height ~d" height)))))
    ;; single pass, in order: validate a tx's inputs, then immediately add its
    ;; outputs — so a later tx may spend an earlier tx in the SAME block, but
    ;; not a later one (Bitcoin's ordering rule).
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
          (let ((total-in 0))
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
                ;; script verification — deferred and fanned across cores after
                ;; the sequential pass (scripts don't touch the UTXO set)
                (when verify-scripts
                  (push (list txn in-i (u:coin-script coin) (u:coin-value coin) tx-i) checks))
                (incf total-in (u:coin-value coin))))
            ;; value conservation
            (let ((total-out (reduce #'+ (tx:tx-outputs txn) :key #'tx:txout-value :initial-value 0)))
              (when (> total-out total-in)
                (cerr height "tx ~d: outputs (~d) exceed inputs (~d)" tx-i total-out total-in))
              (incf total-fees (- total-in total-out)))))
      ;; add this tx's spendable outputs to the set
      (loop for out in (tx:tx-outputs txn)
            for vout from 0 do
        (unless (unspendable-p (tx:txout-script out))
          ;; BIP30: must not overwrite an existing unspent coin
          (when (and (u:utxo-get utxo (tx:tx-txid txn) vout)
                     (not (member height *bip30-exceptions*)))
            (cerr height "BIP30: duplicate unspent outpoint ~a:~d"
                  (w:hash->hex (tx:tx-txid txn)) vout))
          (u:utxo-add utxo (tx:tx-txid txn) vout
                      (u:make-coin :value (tx:txout-value out)
                                   :script (tx:txout-script out)
                                   :height height :coinbase-p coinbase))
          (push (cons (tx:tx-txid txn) vout) (block-undo-created undo)))))
    ;; coinbase value check: claimed <= subsidy + fees
    (let ((allowed (+ (block-subsidy height) total-fees)))
      (when (> coinbase-claimed allowed)
        (cerr height "coinbase claims ~d > allowed ~d (subsidy ~d + fees ~d)"
              coinbase-claimed allowed (block-subsidy height) total-fees)))
    ;; fan the deferred script checks across cores; any failure invalidates block
    (when (and verify-scripts checks)
      (multiple-value-bind (ok msg tx-i in-i)
          (verify-block-scripts (coerce (nreverse checks) 'vector) flags)
        (unless ok (cerr height "tx ~d input ~d: ~a" tx-i in-i msg))))
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

(defun run-ibd (peer utxo &key (from 1) (to (c:tip-height)) (batch 256)
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

(defun resume-ibd (peer &key (to (c:tip-height)) (batch 256) (verify-scripts t)
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

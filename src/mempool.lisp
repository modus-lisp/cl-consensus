;;;; shared/bitcoind/mempool.lisp
;;;;
;;;; Phase 6 — the mempool: accept unconfirmed transactions, validating each
;;;; against the UTXO set (and against earlier unconfirmed txs it may spend),
;;;; rejecting double-spends and value creation, and tracking fee/vsize.
;;;;
;;;; A tx is admissible iff every input spends a coin that exists in the UTXO
;;;; set or is created by an already-accepted mempool tx, no input conflicts
;;;; with another mempool tx, all scripts verify (full soft-fork rules), and
;;;; outputs don't exceed inputs.  Verified by replaying real block N+1 txs
;;;; against a UTXO set built to height N.


(defpackage #:cl-consensus.mempool
  (:use #:cl)
  (:nicknames #:btc-mempool)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script) (#:u #:cl-consensus.utxo)
                    (#:v #:cl-consensus.validate))
  (:export
   #:mempool #:make-mempool #:mempool-size #:mempool-bytes
   #:entry #:entry-tx #:entry-fee #:entry-vsize #:entry-time #:entry-feerate
   #:accept-tx #:mempool-get #:mempool-txids #:mempool-conflicts-p
   #:rejected #:rejected-reason))

(in-package #:cl-consensus.mempool)

(defstruct (mempool (:constructor %make-mempool))
  (entries (make-hash-table :test 'equal))   ; txid hex -> entry
  (spent (make-hash-table :test 'equal))     ; "txid:idx" -> spending txid hex
  (bytes 0))

(defun make-mempool () (%make-mempool))

(defstruct entry tx fee vsize time)

(defun entry-feerate (e) (/ (entry-fee e) (max 1 (entry-vsize e)))) ; sat/vB

(defun mempool-size (mp) (hash-table-count (mempool-entries mp)))
(defun mempool-get (mp txid-hex) (gethash txid-hex (mempool-entries mp)))
(defun mempool-txids (mp)
  (loop for k being the hash-keys of (mempool-entries mp) collect k))

(define-condition rejected (error)
  ((reason :initarg :reason :reader rejected-reason))
  (:report (lambda (c st) (format st "tx rejected: ~a" (rejected-reason c)))))

(defun rej (fmt &rest args) (error 'rejected :reason (apply #'format nil fmt args)))

(defun outpoint-key (hash idx) (format nil "~a:~d" (w:hash->hex hash) idx))

(defun mempool-conflicts-p (mp txn)
  "T if any of TXN's inputs is already spent by a mempool tx."
  (some (lambda (in) (gethash (outpoint-key (tx:txin-prev-hash in) (tx:txin-prev-index in))
                              (mempool-spent mp)))
        (tx:tx-inputs txn)))

(defun lookup-coin (utxo mp hash idx)
  "Resolve an outpoint to (values amount script coinbase-p height) from the UTXO
   set, or from an unconfirmed parent already in the mempool."
  (let ((coin (and utxo (u:utxo-get utxo hash idx))))
    (if coin
        (values (u:coin-value coin) (u:coin-script coin)
                (u:coin-coinbase-p coin) (u:coin-height coin))
        (let ((parent (gethash (w:hash->hex hash) (mempool-entries mp))))
          (when parent
            (let ((out (nth idx (tx:tx-outputs (entry-tx parent)))))
              (when out (values (tx:txout-value out) (tx:txout-script out) nil -1))))))))

(defun accept-tx (txn utxo mp &key (height most-positive-fixnum) (time 0) check-only)
  "Validate TXN and add it to mempool MP (UTXO = confirmed coin set).  Returns
   the ENTRY on success; signals REJECTED otherwise.  HEIGHT selects soft-fork
   rules (default: all active, i.e. tip).  With CHECK-ONLY, validate but do not
   mutate the mempool (testmempoolaccept)."
  (when (tx:tx-coinbase-p txn) (rej "coinbase not allowed in mempool"))
  (unless (tx:tx-txid txn) (tx:finalize-tx txn))   ; hand-built tx: compute ids/sizes
  (let ((txid-hex (tx:txid-hex txn)))
    (when (gethash txid-hex (mempool-entries mp)) (rej "already in mempool"))
    (when (mempool-conflicts-p mp txn) (rej "conflicts with mempool tx (double-spend)"))
    ;; resolve every prevout (UTXO or unconfirmed parent) into a prevouts vector
    (let* ((ins (tx:tx-inputs txn))
           (prevouts (make-array (length ins)))
           (total-in 0))
      (loop for in in ins for i from 0 do
        (multiple-value-bind (amount script cb h) (lookup-coin utxo mp (tx:txin-prev-hash in) (tx:txin-prev-index in))
          (unless amount
            (rej "missing input ~a:~d" (w:hash->hex (tx:txin-prev-hash in)) (tx:txin-prev-index in)))
          (when (and cb (>= h 0) (< (- height h) v:*coinbase-maturity*))
            (rej "premature coinbase spend"))
          (setf (aref prevouts i) (cons amount script))
          (incf total-in amount)))
      ;; scripts
      (loop for in in ins for i from 0 do
        (handler-case
            (unless (s:verify-input txn i (cdr (aref prevouts i)) (car (aref prevouts i))
                                    :prevouts prevouts)
              (rej "input ~d script verification failed" i))
          (s:script-error (e) (rej "input ~d: ~a" i e))))
      ;; value conservation / fee
      (let* ((total-out (reduce #'+ (tx:tx-outputs txn) :key #'tx:txout-value :initial-value 0))
             (fee (- total-in total-out)))
        (when (< fee 0) (rej "outputs (~d) exceed inputs (~d)" total-out total-in))
        (let ((e (make-entry :tx txn :fee fee :vsize (tx:tx-vsize txn) :time time)))
          (unless check-only
            (setf (gethash txid-hex (mempool-entries mp)) e)
            (dolist (in ins)
              (setf (gethash (outpoint-key (tx:txin-prev-hash in) (tx:txin-prev-index in))
                             (mempool-spent mp))
                    txid-hex))
            (incf (mempool-bytes mp) (tx:tx-total-size txn)))
          e)))))

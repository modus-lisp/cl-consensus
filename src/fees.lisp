;;;; fees.lisp — mempool-based fee estimation.
;;;;
;;;; A self-contained estimator that needs no historical prevout values: it reads
;;;; the CURRENT mempool, ranks the unconfirmed txs by feerate (sat/vB), and walks
;;;; them from richest to poorest accumulating virtual size.  A tx paying feerate F
;;;; expects confirmation within N blocks if the backlog of txs paying >= F fits in
;;;; N blocks of space (~1e6 vbytes each).  So the feerate at which the cumulative
;;;; vsize first crosses TARGET * one-block-vbytes is the estimate for TARGET blocks.
;;;;
;;;; When the backlog is thinner than TARGET blocks (the common case, and always so
;;;; on an empty mempool) there is no congestion to price in and the estimator
;;;; returns NIL — callers fall back to the relay floor.

(defpackage #:cl-consensus.fees
  (:use #:cl)
  (:local-nicknames (#:mp #:cl-consensus.mempool))
  (:export #:*min-relay-feerate* #:*block-vbytes* #:*max-conf-target*
           #:estimate-feerate))

(in-package #:cl-consensus.fees)

(defparameter *min-relay-feerate* 1
  "Relay-floor feerate in sat/vB used when the mempool implies no congestion.")
(defparameter *block-vbytes* 1000000
  "Approximate virtual bytes (weight/4) a single block can hold.")
(defparameter *max-conf-target* 1008
  "Clamp for conf_target (blocks) — one week at 10-minute spacing, as in Core.")

(defun %rows (mempool)
  "List of (feerate-sat/vB . vsize) for every tx in MEMPOOL, feerate as a double."
  (loop for txid in (mp:mempool-txids mempool)
        for e = (mp:mempool-get mempool txid)
        when e
          collect (cons (coerce (mp:entry-feerate e) 'double-float)
                        (max 1 (mp:entry-vsize e)))))

(defun estimate-feerate (mempool target)
  "Feerate (sat/vB, double) needed to confirm within TARGET blocks given the current
   MEMPOOL backlog, or NIL when the backlog is smaller than TARGET blocks of space
   (no congestion to price in)."
  (let* ((rows (sort (%rows mempool) #'> :key #'car))
         (threshold (* (max 1 target) *block-vbytes*))
         (acc 0))
    (dolist (row rows nil)
      (incf acc (cdr row))
      (when (>= acc threshold)
        (return (car row))))))

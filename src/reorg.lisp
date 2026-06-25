;;;; reorg.lisp — tip reorg / best-chain activation.
;;;;
;;;; The chain layer (chain.lisp) records competing-fork headers in *by-hash* with
;;;; correct cumulative chainwork, and the validate layer has the UTXO primitives
;;;; to move a block on or off the set (connect-block returns a block-undo;
;;;; disconnect-block reverses it).  What was missing is the ORCHESTRATION: when a
;;;; competing branch outweighs the chain the UTXO is committed on, roll the UTXO
;;;; back to the common ancestor and roll the heavier branch forward — producing
;;;; exactly the UTXO the winning chain would have built.
;;;;
;;;; Undo for the disconnect side comes from an UNDO-STORE (a tiny protocol) so the
;;;; orchestration is testable with an in-RAM store and runs live with a persistent
;;;; (pagetree-backed) one.  A reorg deeper than MAX-DEPTH, or one missing undo for
;;;; a height it must roll back, HALTS with a condition rather than corrupting the
;;;; set (deep reorgs are catastrophic — manual / full-resync fallback).

(defpackage #:cl-consensus.reorg
  (:use #:cl)
  (:nicknames #:btc-reorg)
  (:local-nicknames (#:c #:cl-consensus.chain) (#:v #:cl-consensus.validate)
                    (#:blk #:cl-consensus.block) (#:u #:cl-consensus.utxo)
                    (#:ptu #:cl-consensus.utxo-pagetree) (#:pt #:pagetree)
                    (#:w #:cl-consensus.wire))
  (:export #:activate-best-chain #:reorg-error #:deep-reorg-halt #:reorg-depth
           ;; undo-store protocol + impls
           #:undo-get #:undo-put #:undo-del #:undo-prune
           #:mem-undo-store #:make-mem-undo-store
           #:pt-undo-store #:open-pt-undo-store #:close-pt-undo-store #:undo-commit
           #:serialize-undo #:deserialize-undo))
(in-package #:cl-consensus.reorg)

;;; ----------------------------------------------------------------------------
;;; Conditions
;;; ----------------------------------------------------------------------------

(define-condition reorg-error (error)
  ((reason :initarg :reason :reader reorg-reason))
  (:report (lambda (cnd s) (format s "reorg error: ~a" (reorg-reason cnd)))))

(define-condition deep-reorg-halt (reorg-error)
  ((depth :initarg :depth :reader reorg-depth))
  (:report (lambda (cnd s) (format s "deep-reorg halt: ~a" (reorg-reason cnd)))))

;;; ----------------------------------------------------------------------------
;;; Undo-store protocol — per-height block-undo, keyed by height.
;;; ----------------------------------------------------------------------------

(defgeneric undo-get (store height)
  (:documentation "The BLOCK-UNDO recorded for HEIGHT, or NIL."))
(defgeneric undo-put (store height undo)
  (:documentation "Record BLOCK-UNDO for HEIGHT."))
(defgeneric undo-del (store height)
  (:documentation "Forget the undo for HEIGHT."))
(defgeneric undo-prune (store below)
  (:documentation "Forget all undo for heights < BELOW (bound the window)."))

;;; In-RAM impl (tests, and a building block for a long-lived follow daemon).
(defstruct (mem-undo-store (:constructor make-mem-undo-store))
  (tab (make-hash-table)))
(defmethod undo-get ((s mem-undo-store) height) (gethash height (mem-undo-store-tab s)))
(defmethod undo-put ((s mem-undo-store) height undo) (setf (gethash height (mem-undo-store-tab s)) undo))
(defmethod undo-del ((s mem-undo-store) height) (remhash height (mem-undo-store-tab s)))
(defmethod undo-prune ((s mem-undo-store) below)
  (let ((tab (mem-undo-store-tab s)) (dead '()))
    (maphash (lambda (h u) (declare (ignore u)) (when (< h below) (push h dead))) tab)
    (dolist (h dead) (remhash h tab))))

;;; ----------------------------------------------------------------------------
;;; block-undo (de)serialization + a PERSISTENT (pagetree-backed) undo-store.
;;;
;;; The undo lives in its OWN small pagetree store (keyed by big-endian u32 height),
;;; separate from the live UTXO store — so the reorg machinery never touches the
;;; UTXO flush path, and a slightly-stale undo (committed a checkpoint behind the
;;; UTXO) just makes a reorg fail SAFE (REORG-ERROR -> halt), never corrupts.  Undo
;;; for the last K blocks is what a realistic reorg needs; deeper is guarded by
;;; MAX-DEPTH regardless.
;;; ----------------------------------------------------------------------------

(defun serialize-undo (created spent)
  "Serialize a block-undo's CREATED (list of (txid . index)) and SPENT (list of
   (txid index coin)) into a byte vector.  Coins use the compact pagetree codec."
  (let ((wr (w:make-writer)))
    (w:w-varint wr (length created))
    (dolist (cr created) (w:w-bytes wr (car cr)) (w:w-u32 wr (cdr cr)))
    (w:w-varint wr (length spent))
    (dolist (sp spent)
      (destructuring-bind (txid index coin) sp
        (w:w-bytes wr txid) (w:w-u32 wr index)
        (let ((cb (ptu:encode-coin (u:coin-value coin) (u:coin-height coin)
                                   (u:coin-coinbase-p coin) (u:coin-script coin))))
          (w:w-varint wr (length cb)) (w:w-bytes wr cb))))
    (w:writer-bytes wr)))

(defun deserialize-undo (bytes)
  "Inverse of SERIALIZE-UNDO.  Returns (values created spent)."
  (let* ((r (w:make-reader bytes))
         (nc (w:r-varint r))
         (created (loop repeat nc collect (cons (w:r-bytes r 32) (w:r-u32 r))))
         (ns (w:r-varint r))
         (spent (loop repeat ns collect
                      (let ((txid (w:r-bytes r 32)) (index (w:r-u32 r)))
                        (multiple-value-bind (v h cb s) (ptu:decode-coin (w:r-bytes r (w:r-varint r)))
                          (list txid index (u:make-coin :value v :height h :coinbase-p cb :script s)))))))
    (values created spent)))

(defun %ukey (height)
  "4-byte big-endian height key (heights sort/scan in order)."
  (let ((k (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 k) (setf (aref k i) (logand (ash height (* -8 (- 3 i))) #xff)))))

(defstruct (pt-undo-store (:constructor %make-pt-undo-store))
  store
  (buf (make-hash-table)))           ; height -> serialized-bytes | :deleted (uncommitted)

(defun open-pt-undo-store (path &key cache-bytes)
  "Open/create the undo store at PATH (NIL => in-RAM mem store, for tests)."
  (%make-pt-undo-store :store (pt:open-store path :cache-bytes cache-bytes :create t)))
(defun close-pt-undo-store (s) (pt:close-store (pt-undo-store-store s)))

(defun %undo->block-undo (bytes)
  (multiple-value-bind (cr sp) (deserialize-undo bytes)
    (v:make-block-undo :created cr :spent sp)))

(defmethod undo-get ((s pt-undo-store) height)
  (let ((v (gethash height (pt-undo-store-buf s))))
    (cond ((eq v :deleted) nil)
          (v (%undo->block-undo v))
          (t (let ((bytes (pt:with-read-txn (txn (pt-undo-store-store s))
                            (pt:tget txn (%ukey height)))))
               (when bytes (%undo->block-undo bytes)))))))
(defmethod undo-put ((s pt-undo-store) height undo)
  (setf (gethash height (pt-undo-store-buf s))
        (serialize-undo (v:block-undo-created undo) (v:block-undo-spent undo))))
(defmethod undo-del ((s pt-undo-store) height)
  (setf (gethash height (pt-undo-store-buf s)) :deleted))
(defmethod undo-prune ((s pt-undo-store) below)
  (declare (ignore below)) nil)       ; kept simple in 1b; bounded pruning is Phase 4

(defun undo-commit (s)
  "Persist buffered puts/deletes into the undo store as ONE crash-safe write txn."
  (when (plusp (hash-table-count (pt-undo-store-buf s)))
    (pt:with-write-txn (txn (pt-undo-store-store s))
      (maphash (lambda (h v)
                 (if (eq v :deleted)
                     (pt:tdel txn (%ukey h))
                     (pt:tput txn (%ukey h) v)))
               (pt-undo-store-buf s)))
    (clrhash (pt-undo-store-buf s))))

;;; ----------------------------------------------------------------------------
;;; activate-best-chain
;;; ----------------------------------------------------------------------------

(defun activate-best-chain (utxo committed-height undo-store fetch-block
                            &key (max-depth 144) (verify-scripts t))
  "Reorg UTXO (committed at COMMITTED-HEIGHT on the active chain) to the heaviest
   known branch if it differs.  FETCH-BLOCK is a function of (header) -> parsed
   block for downloading the winning branch's blocks by hash.  UNDO-STORE supplies
   the per-height BLOCK-UNDO for the disconnect side.

   Returns (values new-height reorged-p depth):
     no reorg needed       -> (values committed-height nil 0)
     reorged to a branch    -> (values best-height t depth)
   Signals DEEP-REORG-HALT if the reorg is deeper than MAX-DEPTH, or REORG-ERROR if
   undo for a height it must disconnect is missing (never mutates the set partially
   past the point of no safe return — the disconnect/connect run after the guards).
   Does NOT commit; the caller flushes the UTXO at the returned height."
  (let ((connected (c:header-at-height committed-height))
        (best (c:best-header)))
    (unless connected
      (error 'reorg-error :reason (format nil "no active header at committed height ~d"
                                          committed-height)))
    ;; Fast path: the best header already sits on the active chain at or above the
    ;; committed height (normal linear growth) — no reorg; the caller's IBD connects
    ;; any not-yet-connected blocks forward.
    (when (or (eq best connected)
              (and (c:active-header-p best) (>= (c:header-height best) committed-height)))
      (return-from activate-best-chain (values committed-height nil 0)))
    (let* ((fork (c:fork-point connected best))
           (fork-h (c:header-height fork))
           (depth (- committed-height fork-h)))
      (when (> depth max-depth)
        (error 'deep-reorg-halt :depth depth
               :reason (format nil "reorg depth ~d > max-depth ~d at height ~d (halting)"
                               depth max-depth committed-height)))
      ;; Pre-check: every undo we need to roll back must be present BEFORE we touch
      ;; the set, so a missing-undo failure leaves the UTXO untouched.
      (loop for h from committed-height downto (1+ fork-h)
            unless (undo-get undo-store h)
              do (error 'reorg-error
                        :reason (format nil "missing undo for height ~d (cannot roll back to fork ~d)"
                                        h fork-h)))
      ;; 1. disconnect the orphaned blocks, committed-height down to fork+1
      ;;    (uses only the undo — no chain state).
      (loop for h from committed-height downto (1+ fork-h)
            do (v:disconnect-block (undo-get undo-store h) utxo)
               (undo-del undo-store h))
      ;; 2. make the heavier branch the active chain BEFORE connecting its blocks:
      ;;    connect-block consults the active header at each height (MTP / locktime),
      ;;    so the branch must be on *by-height* first.
      (let ((branch (loop with h = best
                          until (eq h fork)
                          collect h into hs
                          do (setf h (c:get-header (c:header-prev h)))
                          finally (return (nreverse hs)))))   ; ascending fork+1..best
        (c:activate-headers! branch)
        ;; 3. connect the branch forward, capturing per-block undo.
        (dolist (hdr branch)
          (let* ((height (c:header-height hdr))
                 (block (funcall fetch-block hdr)))
            (unless block
              (error 'reorg-error :reason (format nil "could not fetch branch block ~a at height ~d"
                                                  (c:header-hash-hex hdr) height)))
            (multiple-value-bind (fees undo) (v:connect-block block height utxo
                                                              :verify-scripts verify-scripts)
              (declare (ignore fees))
              (undo-put undo-store height undo))))
        (undo-prune undo-store (- (c:header-height best) max-depth))
        (values (c:header-height best) t depth)))))

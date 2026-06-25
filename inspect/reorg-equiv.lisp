;;;; inspect/reorg-equiv.lisp
;;;;
;;;; Consensus gate for TIP REORG / best-chain activation: activate-best-chain MUST
;;;; produce exactly the UTXO set the winning branch would have built from the fork.
;;;;
;;;; Builds a synthetic two-branch fork, fully offline (no peer, no mining):
;;;;   - low heights => BIP34 / segwit / taproot inactive (no height-encode / witness
;;;;     commitment checks);
;;;;   - *coinbase-maturity* bound to 0 => coinbase spendable immediately, so each
;;;;     block carries a real spend (exercises disconnect's restore-spent side);
;;;;   - headers added with :validate nil (skip PoW/retarget/MTP) but chainwork is
;;;;     still computed from nBits, so a branch with MORE blocks outweighs;
;;;;   - connect-block :verify-scripts nil (this gate proves UTXO-SET equivalence,
;;;;     not script validity — that has its own oracle).
;;;;
;;;; Asserts: (1) reorg A->B yields the SAME utxo-digest/count/total as a fresh
;;;; connect of branch B from the fork, and (2) a B->A reorg-back round-trip restores
;;;; branch A's set (disconnect-block is exactly reversible).
;;;;
;;;;   sbcl --load inspect/reorg-equiv.lisp --eval '(reorg-equiv:run)'
(require :asdf)
(require :sb-posix)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/cl-consensus/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :reorg-equiv
  (:use :cl)
  (:local-nicknames (:c :cl-consensus.chain) (:v :cl-consensus.validate)
                    (:blk :cl-consensus.block) (:tx :cl-consensus.tx)
                    (:u :cl-consensus.utxo) (:w :cl-consensus.wire)
                    (:r :cl-consensus.reorg))
  (:export #:run))
(in-package :reorg-equiv)

(defparameter *bits* #x1d00ffff)            ; mainnet min-difficulty nBits (any fixed value)
(defparameter *zero32* (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(defun dummy-spk (tag) (make-array 4 :element-type '(unsigned-byte 8) :initial-contents (list 118 tag 136 172)))

(defun make-coinbase (height tag)
  "A coinbase tx paying the block subsidy.  TAG distinguishes competing branches:
   it varies the coinbase (=> different txid => different merkle => different block
   hash), so branch A and branch B at the same height are genuinely different blocks."
  (tx:finalize-tx
   (tx:make-tx :version 1 :locktime 0 :segwit-p nil :witnesses nil
               :inputs (list (tx:make-txin :prev-hash *zero32* :prev-index #xffffffff
                                           :script (make-array 4 :element-type '(unsigned-byte 8)
                                                                 :initial-contents (list (logand height 255)
                                                                                         (logand tag 255) 2 3))
                                           :sequence #xffffffff))
               :outputs (list (tx:make-txout :value (v:block-subsidy height)
                                             :script (dummy-spk (logand tag 255)))))))

(defun make-spend (prev-txid prev-index value tag)
  "A fee-free tx spending (PREV-TXID, PREV-INDEX) of VALUE to one output of VALUE."
  (tx:finalize-tx
   (tx:make-tx :version 1 :locktime 0 :segwit-p nil :witnesses nil
               :inputs (list (tx:make-txin :prev-hash prev-txid :prev-index prev-index
                                           :script #() :sequence #xffffffff))
               :outputs (list (tx:make-txout :value value :script (dummy-spk tag))))))

(defun make-block (prev-header height txs)
  "Assemble a block + header (correct merkle, prev linkage) and ADD the header to
   the chain (validate nil).  Returns the block*."
  (let* ((txv (coerce txs 'vector))
         (merkle (blk:compute-merkle-root (map 'list #'tx:tx-txid txv)))
         (wr (w:make-writer)))
    (w:w-u32 wr 1)                                  ; version
    (w:w-hash wr (c:header-hash prev-header))       ; prev
    (w:w-hash wr merkle)                            ; merkle
    (w:w-u32 wr (+ 1000000 height))                ; time (monotone; MTP skipped)
    (w:w-u32 wr *bits*)
    (w:w-u32 wr 0)                                  ; nonce (PoW skipped)
    (let ((hdr (c:parse-header (w:make-reader (w:writer-bytes wr)))))
      (c:add-header hdr :validate nil)              ; registers in *by-hash*, sets height+chainwork
      (blk::%make-block :header hdr :txs txv))))

;;; A linear chain segment: returns (values blocks-vector last-header). Each block
;;; (height>=lo+1) spends the PREVIOUS block's coinbase output (matured via the
;;; *coinbase-maturity* 0 binding), so every block exercises a spend.
(defun build-segment (start-header start-height count tag)
  (let ((blocks '()) (prev start-header) (prev-cb-txid nil))
    (dotimes (i count)
      (let* ((height (+ start-height i 1))
             (cb (make-coinbase height tag))
             (txs (if prev-cb-txid
                      (list cb (make-spend prev-cb-txid 0 (v:block-subsidy (1- height)) (logand (+ tag i) 255)))
                      (list cb)))
             (b (make-block prev height txs)))
        (push b blocks)
        (setf prev (blk:block-header b) prev-cb-txid (tx:tx-txid cb))))
    (values (nreverse blocks) prev)))

(defun connect-all (utxo blocks undo-store)
  "Connect BLOCKS in order into UTXO, recording each block's undo in UNDO-STORE."
  (dolist (b blocks)
    (let ((h (c:header-height (blk:block-header b))))
      (multiple-value-bind (fees undo) (v:connect-block b h utxo :verify-scripts nil)
        (declare (ignore fees))
        (when undo-store (r:undo-put undo-store h undo))))))

(defun snap (utxo) (list (u:utxo-digest utxo) (u:utxo-count utxo) (u:utxo-set-total-value utxo)))
(defun snap= (a b) (and (equalp (first a) (first b)) (= (second a) (second b)) (= (third a) (third b))))

(defun index-blocks (&rest block-lists)
  (let ((tab (make-hash-table :test 'equal)))
    (dolist (bl block-lists tab)
      (dolist (b bl) (setf (gethash (c:header-hash-hex (blk:block-header b)) tab) b)))))

(defun run ()
  (let ((v:*coinbase-maturity* 0) (ok t)
        common last3 a-blocks a5-header b-blocks b-tip a-ext a-ext-tip)
    (c:init-chain)
    ;; common 1..3 (tag 10); branch A 4..5 (tag 20); branch B 4'..6' (tag 40 => 3 blks
    ;; past the fork, heavier than A's 2).  best-header sees only what's been built so
    ;; far, so the A-extension is built ONLY AFTER the A->B reorg.
    (multiple-value-setq (common last3) (build-segment (c:tip) 0 3 10))
    (multiple-value-setq (a-blocks) (build-segment last3 3 2 20))
    (setf a5-header (blk:block-header (car (last a-blocks))))
    (multiple-value-setq (b-blocks b-tip) (build-segment last3 3 3 40))
    ;; NOTE: connect-block consults the ACTIVE header at each height, so a reference
    ;; for a branch is built only AFTER that branch has been activated (by the reorg).
    (let ((fetch-b (let ((tab (index-blocks common b-blocks))) (lambda (h) (gethash (c:header-hash-hex h) tab))))
          (set (u:open-pagetree-utxo nil)) (undo (r:make-mem-undo-store)))
      ;; --- connect common + A (@5, A is active), then reorg A->B ---
      (connect-all set (append common a-blocks) undo)
      (multiple-value-bind (nh reorged depth) (r:activate-best-chain set 5 undo fetch-b :verify-scripts nil)
        (format t "~&[reorg] A@5 -> B: new-height ~d reorged ~a depth ~d~%" nh reorged depth)
        (unless (and reorged (= nh (c:header-height b-tip)) (= depth 2))
          (setf ok nil) (format t "  *** wrong A->B reorg result~%"))
        ;; B is active now -> a fresh connect of common+B is the reference
        (let ((ref-b (u:open-pagetree-utxo nil)))
          (connect-all ref-b (append common b-blocks) nil)
          (unless (snap= (snap set) (snap ref-b))
            (setf ok nil) (format t "  *** reorged set != fresh winning branch B~%"))
          (format t "  reorg A->B == fresh B: ~a (count ~d, digest-eq ~a)~%"
                  (snap= (snap set) (snap ref-b)) (second (snap set))
                  (equalp (first (snap set)) (first (snap ref-b))))))
      ;; --- build the A-extension (6..8, tag 60) so A@8 outweighs B@6, reorg back ---
      (multiple-value-setq (a-ext a-ext-tip) (build-segment a5-header 5 3 60))
      (let ((fetch-a (let ((tab (index-blocks common a-blocks a-ext))) (lambda (h) (gethash (c:header-hash-hex h) tab)))))
        (multiple-value-bind (nh2 reorged2 depth2)
            (r:activate-best-chain set (c:header-height b-tip) undo fetch-a :verify-scripts nil)
          (format t "[reorg] B@~d -> A: new-height ~d reorged ~a depth ~d~%"
                  (c:header-height b-tip) nh2 reorged2 depth2)
          (unless (and reorged2 (= nh2 (c:header-height a-ext-tip)))
            (setf ok nil) (format t "  *** wrong B->A reorg-back result~%"))
          ;; A+ext is active now -> reference is a fresh connect of common+A+a-ext
          (let ((ref-a (u:open-pagetree-utxo nil)))
            (connect-all ref-a (append common a-blocks a-ext) nil)
            (unless (snap= (snap set) (snap ref-a))
              (setf ok nil) (format t "  *** reorg-back set != fresh A+ext~%"))
            (format t "  reorg B->A == fresh A+ext: ~a (count ~d, digest-eq ~a)~%"
                    (snap= (snap set) (snap ref-a)) (second (snap set))
                    (equalp (first (snap set)) (first (snap ref-a))))))))
    (format t "~&reorg-equiv: ~a~%"
            (if ok "ALL EQUIVALENT — reorg == fresh winning branch (both directions)" "FAILED"))
    ok))

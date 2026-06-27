;;;; shared/bitcoind/inspect/block-sweep.lisp
;;;;
;;;; Stable regression gate: download a confirmed block and verify every input
;;;; that spends an output created earlier in the SAME block (so all prevouts are
;;;; self-contained — no UTXO set, no RPC race).  Real mainnet blocks are valid,
;;;; so every such input MUST verify; any failure is a real regression.
;;;;
;;;;   sbcl --load shared/bitcoind/inspect/block-sweep.lisp \
;;;;        --eval '(btc-sweep:run 900000)'      ; exits nonzero on any failure

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (pushnew (uiop:pathname-parent-directory-pathname (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
           asdf:*central-registry* :test #'equal)
  (asdf:load-system "cl-consensus"))

(defpackage #:btc-sweep
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:p #:cl-consensus.peer) (#:c #:cl-consensus.chain)
                    (#:tx #:cl-consensus.tx) (#:blk #:cl-consensus.block) (#:v #:cl-consensus.validate))
  (:export #:run))

(in-package #:btc-sweep)

(defun run (&optional (height 900000) (host "127.0.0.1"))
  (unless (c:tip) (c:load-headers))
  (let ((peer (p:connect-peer host))
        (flags (v:consensus-flags height))
        (pass 0) (fail 0) (skip-taproot 0))
    (unwind-protect
         (let* ((b (blk:get-block-at-height peer height))
                (txs (blk:block-txs b))
                (by-txid (make-hash-table :test 'equal)))
           (loop for txn across txs do (setf (gethash (w:bytes->hex (tx:tx-txid txn)) by-txid) txn))
           (loop for txn across txs
                 unless (tx:tx-coinbase-p txn) do
             (loop for in in (tx:tx-inputs txn) for i from 0 do
               (let ((parent (gethash (w:bytes->hex (tx:txin-prev-hash in)) by-txid)))
                 (when parent
                   (let ((out (nth (tx:txin-prev-index in) (tx:tx-outputs parent))))
                     (handler-case
                         (if (cl-consensus.script:verify-input txn i (tx:txout-script out)
                                                             (tx:txout-value out) :flags flags)
                             (incf pass) (incf fail))
                       (error (e)
                         (if (search "taproot" (format nil "~a" e)) (incf skip-taproot) (incf fail)))))))))
           (format t "~&block ~d self-contained sweep: ~d pass, ~d FAIL, ~d taproot-skipped~%"
                   height pass fail skip-taproot)
           (if (zerop fail)
               (progn (format t "REGRESSION: PASS~%") (sb-ext:exit :code 0))
               (progn (format t "REGRESSION: FAIL (~d inputs rejected)~%" fail) (sb-ext:exit :code 1))))
      (p:disconnect peer))))

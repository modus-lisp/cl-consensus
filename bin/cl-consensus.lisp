;;;; bin/cl-consensus.lisp — run the node.
;;;;
;;;; This is THE node: a single-writer daemon that validates each block to the tip
;;;; (reorg-aware) while serving headers/blocks + relaying to inbound peers, with a
;;;; bitcoind-compatible JSON-RPC API (:8432) + a control socket (:4008).
;;;;
;;;;   sbcl --dynamic-space-size 81920 --load bin/cl-consensus.lisp
;;;;
;;;; It needs a peer to sync from (a local bitcoind on 127.0.0.1 by default — set
;;;; CL_CONSENSUS_PEER to point elsewhere) and writes its chainstate under
;;;; ~/.cl-consensus/ (set BITCOIND_DATADIR for headers; pass paths to serve-node for
;;;; the rest).  A mainnet UTXO is large, so run with a big --dynamic-space-size.
;;;;
;;;; (For an RPC server over a static chainstate without full validation, call
;;;;  cl-consensus.node:start instead — see src/node.lisp.)

(require :asdf)
(pushnew (uiop:pathname-parent-directory-pathname
          (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
         asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(in-package #:cl-consensus.node)

(let ((peer (or (sb-ext:posix-getenv "CL_CONSENSUS_PEER") "127.0.0.1")))
  (format t "~&[cl-consensus] full node starting — syncing from peer ~a~%~
             [cl-consensus]   (set CL_CONSENSUS_PEER to change; chainstate under ~~/.cl-consensus/)~%"
          peer)
  ;; serve-node blocks forever (accept + read + follow loops); Ctrl-C unwinds it,
  ;; saving the mempool and closing the undo store.
  (serve-node :peer-host peer))

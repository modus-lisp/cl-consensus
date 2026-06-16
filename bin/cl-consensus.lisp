;;;; bin/cl-consensus.lisp — run the node daemon.
;;;;
;;;;   sbcl --load bin/cl-consensus.lisp
;;;;
;;;; Loads the cl-consensus system, attaches a UTXO chainstate checkpoint if one
;;;; exists, and starts the JSON-RPC server (:8432) + control socket (:4008).

(require :asdf)
(pushnew (uiop:pathname-parent-directory-pathname
          (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
         asdf:*central-registry* :test #'equal)
(asdf:load-system "cl-consensus")

(in-package #:cl-consensus.node)

;; attach a UTXO chainstate checkpoint if one was built
(let ((cs (cl-consensus.validate:chainstate-path)))
  (when (probe-file cs)
    (multiple-value-bind (set height) (cl-consensus.utxo:load-utxo cs)
      (when set
        (setf *utxo* set)
        (format t "~&[cl-consensus] attached UTXO chainstate at height ~d (~d coins)~%"
                height (cl-consensus.utxo:utxo-count set))))))

(start)

(handler-case
    (loop (sleep 3600))
  (#+sbcl sb-sys:interactive-interrupt #-sbcl error ()
    (stop)
    (format t "~&[cl-consensus] stopped.~%")))

;;;; shared/bitcoind/inspect/oracle.lisp
;;;;
;;;; Persistent inspector: cross-check our node's state against the real mainnet
;;;; a local bitcoind via its JSON-RPC (the ground-truth oracle).
;;;;
;;;;   sbcl --load shared/bitcoind/inspect/oracle.lisp
;;;;   (in-package :btc-oracle) (check-headers) (check-tip)
;;;;
;;;; Auth uses the node's cookie file (BITCOIN_COOKIE, default ~/.bitcoin/.cookie).

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (pushnew (uiop:pathname-parent-directory-pathname (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
           asdf:*central-registry* :test #'equal)
  (ql:quickload '(:dexador :com.inuoe.jzon) :silent t)
  (asdf:load-system "cl-consensus"))

(defpackage #:btc-oracle
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:c #:cl-consensus.chain)
                    (#:jzon #:com.inuoe.jzon))
  (:export #:rpc #:check-headers #:check-tip #:*rpc-url* #:*cookie-file*))

(in-package #:btc-oracle)

;; Point these at your own Bitcoin Core node (env overrides for convenience).
(defparameter *rpc-url*
  (or (sb-ext:posix-getenv "BITCOIN_RPC_URL") "http://127.0.0.1:8332/"))
(defparameter *cookie-file*
  (or (sb-ext:posix-getenv "BITCOIN_COOKIE")
      (namestring (merge-pathnames ".bitcoin/.cookie" (user-homedir-pathname)))))

(defun cookie-auth ()
  (let ((s (with-open-file (f *cookie-file*)
             (read-line f))))
    (let ((colon (position #\: s)))
      (cons (subseq s 0 colon) (subseq s (1+ colon))))))

(defun rpc (method &rest params)
  "Call a bitcoind JSON-RPC METHOD; return the parsed \"result\"."
  (let* ((body (jzon:stringify
                (alexandria:plist-hash-table
                 (list "jsonrpc" "1.0" "id" "o" "method" method
                       "params" (coerce params 'vector))
                 :test 'equal)))
         (resp (dex:post *rpc-url* :content body
                         :basic-auth (cookie-auth)
                         :headers '(("content-type" . "text/plain"))))
         (parsed (jzon:parse resp)))
    (gethash "result" parsed)))

(defun check-headers (&optional (heights '(0 1 100000 210000 420000 630000 840000 909000)))
  "Compare our synced header-chain hashes to Core's getblockhash at HEIGHTS."
  (unless (c:tip) (c:load-headers))
  (let ((ok 0) (bad 0))
    (dolist (h heights)
      (let* ((ours (let ((hd (c:header-at-height h))) (and hd (c:header-hash-hex hd))))
             (theirs (rpc "getblockhash" h))
             (match (and ours (string= ours theirs))))
        (if match (incf ok) (incf bad))
        (format t "~&height ~8d : ~a~%   ours   ~a~%   core   ~a~%"
                h (if match "MATCH" "MISMATCH") ours theirs)))
    (format t "~%~d/~d heights match Bitcoin Core~%" ok (+ ok bad))))

(defun check-tip ()
  "Show Core's tip vs ours."
  (unless (c:tip) (c:load-headers))
  (let ((info (rpc "getblockchaininfo")))
    (format t "~&Core tip   : height ~d  ~a~%"
            (gethash "blocks" info) (gethash "bestblockhash" info))
    (format t "Our tip    : height ~d  ~a~%" (c:tip-height) (c:header-hash-hex (c:tip)))
    (format t "Core ahead by ~d blocks (sync more headers to catch up)~%"
            (- (gethash "blocks" info) (c:tip-height)))))

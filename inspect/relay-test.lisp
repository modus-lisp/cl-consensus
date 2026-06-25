;;;; inspect/relay-test.lisp
;;;;
;;;; Gate for block relay (Phase 3a): stand up the inbound listener, loopback-connect
;;;; (so our client is the daemon's inbound peer), and exercise both announcement
;;;; paths:
;;;;   - inv path:     announce-block -> client gets 'inv' -> getdata -> exact block
;;;;   - headers path: client sends 'sendheaders' -> announce-block -> client gets the
;;;;                   announced header via a 'headers' message (BIP130)
;;;; Fully offline (127.0.0.1).
;;;;
;;;;   sbcl --load inspect/relay-test.lisp --eval '(relay-test:run)'
(require :asdf)
(require :sb-posix)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/cl-consensus/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :relay-test
  (:use :cl)
  (:local-nicknames (:c :cl-consensus.chain) (:p :cl-consensus.peer)
                    (:w :cl-consensus.wire) (:s :cl-consensus.serve)
                    (:bs :cl-consensus.blockstore) (:blk :cl-consensus.block)
                    (:bt :bordeaux-threads))
  (:export #:run))
(in-package :relay-test)

(defun make-hdr (prev height)
  (let ((wr (w:make-writer)))
    (w:w-u32 wr 1) (w:w-hash wr (c:header-hash prev))
    (w:w-hash wr (make-array 32 :element-type '(unsigned-byte 8) :initial-element (logand height 255)))
    (w:w-u32 wr (+ 1500000000 height)) (w:w-u32 wr #x1d00ffff) (w:w-u32 wr height)
    (let ((h (c:parse-header (w:make-reader (w:writer-bytes wr)))))
      (c:add-header h :validate nil) h)))

(defun fake-raw-block (hdr)
  (concatenate '(simple-array (unsigned-byte 8) (*)) (c:serialize-header hdr) #(0)))

(defun run (&key (port 18555) (n 5))
  (let ((ok t) (path "/tmp/relay-test-blocks.dat"))
    (c:init-chain)
    (let ((prev (c:tip))) (dotimes (i n) (setf prev (make-hdr prev (1+ i)))))
    (ignore-errors (delete-file path))
    (setf s:*block-store* (bs:open-block-store path))
    (loop for ht from 1 to n do (bs:store-block s:*block-store* (fake-raw-block (c:header-at-height ht))))
    (s:start-listener :port port :host "127.0.0.1" :max-peers 8)
    (sleep 1)
    (let ((out (p:connect-peer "127.0.0.1" :port port :start-height 0 :timeout 5)))
      ;; wait for the daemon-side inbound peer to register
      (loop repeat 50 until s:*inbound-peers* do (sleep 0.1))
      (unless s:*inbound-peers* (setf ok nil) (format t "  *** no inbound peer registered~%"))
      (let* ((target (c:header-at-height n)) (hash (c:header-hash target)) (raw (fake-raw-block target)))
        ;; ---- INV PATH ----
        (let ((got-inv nil) (got-blk nil) (idone nil) (bdone nil))
          (p:on out "inv" (lambda (pr payload) (declare (ignore pr)) (setf got-inv (s:parse-getdata payload) idone t)))
          (p:on out "block" (lambda (pr payload) (declare (ignore pr))
                              (when (and (>= (length payload) 80) (equalp (w:hash256 (subseq payload 0 80)) hash))
                                (setf got-blk payload bdone t))))
          (s:announce-block target)
          (loop repeat 50 until idone do (sleep 0.1))
          (cond
            ((not idone) (setf ok nil) (format t "  *** no inv received~%"))
            ((not (and (= (length got-inv) 1) (equalp (cdr (first got-inv)) hash)
                       (= (car (first got-inv)) blk:+msg-block+)))
             (setf ok nil) (format t "  *** inv entry wrong: ~a~%" got-inv))
            (t (format t "[relay-test] inv announce: OK~%")))
          ;; client follows up with getdata; serve-getdata must return exact bytes
          (p:send out "getdata" (cl-consensus.block::build-getdata-payload blk:+msg-witness-block+ hash))
          (loop repeat 50 until bdone do (sleep 0.1))
          (cond
            ((not bdone) (setf ok nil) (format t "  *** no block after getdata~%"))
            ((not (equalp got-blk raw)) (setf ok nil) (format t "  *** relayed block bytes mismatch~%"))
            (t (format t "[relay-test] inv -> getdata -> exact block: OK~%"))))
        ;; ---- HEADERS PATH (BIP130) ----
        (let ((got-hdrs nil) (hdone nil))
          (p:send out "sendheaders" #())
          ;; wait until the daemon-side inbound peer records the preference
          (loop repeat 50 until (and s:*inbound-peers* (p:peer-prefers-headers (first s:*inbound-peers*)))
                do (sleep 0.1))
          (unless (and s:*inbound-peers* (p:peer-prefers-headers (first s:*inbound-peers*)))
            (setf ok nil) (format t "  *** inbound peer did not record sendheaders~%"))
          (p:on out "headers" (lambda (pr payload) (declare (ignore pr))
                                (setf got-hdrs (cl-consensus.chain::parse-headers-message payload) hdone t)))
          (s:announce-block target)
          (loop repeat 50 until hdone do (sleep 0.1))
          (cond
            ((not hdone) (setf ok nil) (format t "  *** no headers announcement received~%"))
            ((not (and (= (length got-hdrs) 1) (equalp (c:header-hash (first got-hdrs)) hash)))
             (setf ok nil) (format t "  *** headers announcement wrong~%"))
            (t (format t "[relay-test] sendheaders -> headers announce: OK~%")))))
      (ignore-errors (p:disconnect out)))
    (ignore-errors (bs:close-block-store s:*block-store*))
    (setf s:*block-store* nil)
    (ignore-errors (delete-file path))
    (format t "~&relay-test: ~a~%" (if ok "OK — inv + getdata + BIP130 headers announce" "FAILED"))
    ok))

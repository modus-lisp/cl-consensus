;;;; inspect/serve-test.lisp
;;;;
;;;; Gate for the network-citizen serving layer: stand up the inbound listener, then
;;;; LOOPBACK-connect to it with our own connect-peer (so the inbound accept-peer
;;;; handshake runs against a real outbound handshake), send a getheaders with a
;;;; genesis-only locator, and assert a valid 'headers' response comes back matching
;;;; our chain.  Fully offline (127.0.0.1).
;;;;
;;;;   sbcl --load inspect/serve-test.lisp --eval '(serve-test:run)'
(require :asdf)
(require :sb-posix)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/cl-consensus/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :serve-test
  (:use :cl)
  (:local-nicknames (:c :cl-consensus.chain) (:p :cl-consensus.peer)
                    (:w :cl-consensus.wire) (:s :cl-consensus.serve)
                    (:bs :cl-consensus.blockstore) (:blk :cl-consensus.block)
                    (:bt :bordeaux-threads))
  (:export #:run))
(in-package :serve-test)

(defun fake-raw-block (hdr)
  "A raw block for synthetic HDR: its 80-byte serialized header + an empty tx-count.
   The block hash is taken over the 80-byte header, so it matches HDR's hash."
  (let ((hb (c:serialize-header hdr)))
    (concatenate '(simple-array (unsigned-byte 8) (*)) hb #(0))))

(defun make-hdr (prev-header height)
  "A synthetic header building on PREV-HEADER (PoW/difficulty skipped via validate nil;
   chainwork still computed from nBits)."
  (let ((wr (w:make-writer)))
    (w:w-u32 wr 1)                                  ; version
    (w:w-hash wr (c:header-hash prev-header))       ; prev
    (w:w-hash wr (make-array 32 :element-type '(unsigned-byte 8) :initial-element (logand height 255))) ; merkle (any)
    (w:w-u32 wr (+ 1500000000 height))             ; time
    (w:w-u32 wr #x1d00ffff)                         ; bits
    (w:w-u32 wr height)                             ; nonce (any)
    (let ((h (c:parse-header (w:make-reader (w:writer-bytes wr)))))
      (c:add-header h :validate nil)
      h)))

(defun run (&key (port 18444) (n 5))
  (let ((ok t) (got nil) (done nil))
    (c:init-chain)
    ;; build a small active chain: genesis + N synthetic headers
    (let ((prev (c:tip)))
      (dotimes (i n) (setf prev (make-hdr prev (1+ i)))))
    (format t "~&[serve-test] built chain to height ~d~%" (c:tip-height))
    ;; stand up the listener, give it a moment to bind
    (s:start-listener :port port :host "127.0.0.1" :max-peers 8)
    (sleep 1)
    ;; loopback-connect (our connect-peer drives the inbound accept-peer handshake)
    (let ((out (p:connect-peer "127.0.0.1" :port port :start-height 0 :timeout 5)))
      (format t "[serve-test] loopback handshake OK; peer ~a services ~a~%"
              (p:peer-addr out) (p:peer-services out))
      ;; capture the served 'headers' response
      (p:on out "headers" (lambda (pr payload) (declare (ignore pr)) (setf got payload done t)))
      ;; ask for everything after genesis (locator = [genesis hash])
      (p:send out "getheaders"
              (cl-consensus.chain::build-getheaders-payload (list (c:header-hash c:*genesis*))))
      ;; wait for the response
      (loop repeat 50 until done do (sleep 0.1))
      (cond
        ((not done) (setf ok nil) (format t "  *** no headers response~%"))
        (t (let ((hs (cl-consensus.chain::parse-headers-message got)))
             (format t "[serve-test] received ~d headers~%" (length hs))
             (unless (= (length hs) n) (setf ok nil) (format t "  *** expected ~d headers, got ~d~%" n (length hs)))
             ;; each received header must match our active chain by hash, in order
             (loop for hdr in hs for ht from 1 do
               (unless (equalp (c:header-hash hdr) (c:header-hash (c:header-at-height ht)))
                 (setf ok nil) (format t "  *** header at height ~d mismatch~%" ht)))
             (format t "[serve-test] all ~d served headers match our chain: ~a~%" n ok))))
      ;; ---- getdata(block) round-trip ----
      (let* ((path "/tmp/serve-test-blocks.dat")
             (target (c:header-at-height 3))
             (raw (fake-raw-block target))
             (gotblk nil) (bdone nil))
        (ignore-errors (delete-file path))
        (setf s:*block-store* (bs:open-block-store path))
        ;; store all n synthetic blocks; we'll request height 3
        (loop for ht from 1 to n do (bs:store-block s:*block-store* (fake-raw-block (c:header-at-height ht))))
        (p:on out "block" (lambda (pr payload) (declare (ignore pr)) (setf gotblk payload bdone t)))
        (p:send out "getdata"
                (cl-consensus.block::build-getdata-payload blk:+msg-witness-block+ (c:header-hash target)))
        (loop repeat 50 until bdone do (sleep 0.1))
        (cond
          ((not bdone) (setf ok nil) (format t "  *** no block response to getdata~%"))
          ((not (equalp gotblk raw)) (setf ok nil) (format t "  *** served block bytes mismatch~%"))
          (t (format t "[serve-test] getdata(block) round-trip exact bytes: OK~%")))
        ;; getdata for an unknown block -> notfound
        (let ((nf nil) (nfdone nil)
              (unknown (make-array 32 :element-type '(unsigned-byte 8) :initial-element 99)))
          (p:on out "notfound" (lambda (pr payload) (declare (ignore pr)) (setf nf payload nfdone t)))
          (p:send out "getdata"
                  (cl-consensus.block::build-getdata-payload blk:+msg-witness-block+ unknown))
          (loop repeat 50 until nfdone do (sleep 0.1))
          (if (and nfdone nf) (format t "[serve-test] unknown getdata -> notfound: OK~%")
              (progn (setf ok nil) (format t "  *** expected notfound for unknown block~%"))))
        (ignore-errors (bs:close-block-store s:*block-store*))
        (setf s:*block-store* nil)
        (ignore-errors (delete-file path)))
      (ignore-errors (p:disconnect out)))
    (format t "~&serve-test: ~a~%" (if ok "OK — inbound handshake + getheaders + getdata served correctly" "FAILED"))
    ok))

;;;; serve.lisp — make the node a network CITIZEN: accept inbound P2P connections
;;;; and SERVE headers (Phase 1; blocks in Phase 2) instead of only leeching.
;;;;
;;;; The P2P plumbing already exists (peer.lisp: send/on/read-loop/accept-peer; the
;;;; control-loop in node.lisp is the listener template).  This adds: the getheaders
;;;; responder, an inbound listener with a peer cap, and a long-lived serve-daemon
;;;; that follows the header tip (to serve fresh headers) and listens for inbound
;;;; peers.  It needs only the header chain — no UTXO — so it runs independently
;;;; alongside the keep-current (UTXO) writer.

(defpackage #:cl-consensus.serve
  (:use #:cl)
  (:nicknames #:btc-serve)
  (:local-nicknames (#:c #:cl-consensus.chain) (#:p #:cl-consensus.peer)
                    (#:w #:cl-consensus.wire) (#:blk #:cl-consensus.block)
                    (#:bs #:cl-consensus.blockstore)
                    (#:bt #:bordeaux-threads))
  (:export #:parse-getheaders #:build-headers-message #:serve-getheaders
           #:parse-getdata #:serve-getdata #:*block-store*
           #:install-serving-handlers #:start-listener #:serve-daemon
           #:*inbound-peers*))
(in-package #:cl-consensus.serve)

;;; ----------------------------------------------------------------------------
;;; getheaders -> headers
;;; ----------------------------------------------------------------------------

(defun parse-getheaders (payload)
  "Parse a getheaders/getblocks payload -> (values version locator hash-stop).
   LOCATOR is a list of 32-byte block hashes (newest first)."
  (let* ((r (w:make-reader payload))
         (version (w:r-u32 r))
         (count (w:r-varint r))
         (locator (loop repeat count collect (w:r-hash r)))
         (hash-stop (w:r-hash r)))
    (values version locator hash-stop)))

(defun build-headers-message (headers)
  "Serialize a 'headers' message payload: varint(count) + [80-byte header || 0x00]*
   (the trailing 0 is the always-empty tx-count of a header announcement)."
  (let ((wr (w:make-writer)))
    (w:w-varint wr (length headers))
    (dolist (h headers)
      (w:w-bytes wr (c:serialize-header h))
      (w:w-varint wr 0))
    (w:writer-bytes wr)))

(defparameter *max-headers* 2000)        ; protocol cap per headers message

(defun serve-getheaders (peer payload)
  "Answer a peer's getheaders: find the first locator hash on OUR active chain (the
   fork point), then send up to *max-headers* of our headers starting just after it.
   An empty response (count 0) tells the peer it is caught up."
  (multiple-value-bind (version locator hash-stop) (parse-getheaders payload)
    (declare (ignore version hash-stop))
    (let ((start 0))                     ; default: serve from genesis+1 (no match)
      (dolist (h locator)
        (let ((hdr (c:get-header h)))
          (when (and hdr (c:active-header-p hdr))
            (setf start (c:header-height hdr))
            (return))))
      (let* ((from (1+ start))
             (to (min (c:tip-height) (+ from (1- *max-headers*))))
             (headers (when (<= from to)
                        (loop for ht from from to to collect (c:header-at-height ht)))))
        (p:send peer "headers" (build-headers-message headers))
        (p:peer-log peer "served ~d headers from ~d" (length headers) from)))))

;;; ----------------------------------------------------------------------------
;;; getdata -> block (serve raw blocks we have stored)
;;; ----------------------------------------------------------------------------

(defvar *block-store* nil
  "The open BLOCK-STORE the serving daemon reads to answer getdata for blocks.
   NIL means we have no block storage -> every block getdata is answered notfound.")

(defun parse-getdata (payload)
  "Parse a getdata/inv/notfound payload -> a list of (type . hash) inventory
   entries (TYPE a u32, HASH 32 bytes)."
  (let* ((r (w:make-reader payload))
         (count (w:r-varint r)))
    (loop repeat count
          collect (cons (w:r-u32 r) (w:r-hash r)))))

(defun %block-getdata-p (type)
  "True for MSG_BLOCK / MSG_WITNESS_BLOCK (we ignore the witness flag and serve the
   bytes we stored, which include witnesses)."
  (= (logand type #x3fffffff) blk:+msg-block+))

(defun build-notfound-message (entries)
  "Serialize a 'notfound' payload from a list of (type . hash) inventory entries."
  (let ((wr (w:make-writer)))
    (w:w-varint wr (length entries))
    (dolist (e entries)
      (w:w-u32 wr (car e))
      (w:w-hash wr (cdr e)))
    (w:writer-bytes wr)))

(defun serve-getdata (peer payload)
  "Answer a peer's getdata for blocks: for each MSG_BLOCK/MSG_WITNESS_BLOCK entry we
   have stored, send the raw 'block' bytes; collect the misses and reply 'notfound'.
   Non-block inventory types (tx) are left to other handlers / ignored here."
  (let ((entries (parse-getdata payload))
        (misses '()) (served 0))
    (dolist (e entries)
      (let ((type (car e)) (hash (cdr e)))
        (cond
          ((not (%block-getdata-p type)) nil)   ; not a block request; ignore here
          (t
           (let ((raw (and *block-store*
                           (bs:get-block-bytes *block-store* (w:hash->hex hash)))))
             (if raw
                 (progn (p:send peer "block" raw) (incf served))
                 (push e misses)))))))
    (when misses
      (p:send peer "notfound" (build-notfound-message (nreverse misses))))
    (p:peer-log peer "served ~d block(s), ~d notfound" served (length misses))))

(defun install-serving-handlers (peer)
  "Register the read-only serving responders on PEER: getheaders and getdata."
  (p:on peer "getheaders" #'serve-getheaders)
  (p:on peer "getdata" #'serve-getdata))

;;; ----------------------------------------------------------------------------
;;; Inbound listener
;;; ----------------------------------------------------------------------------

(defvar *inbound-peers* '() "Live accepted inbound peers (capped).")
(defvar *inbound-lock* (bt:make-lock "serve-inbound"))
(defvar *listener-thread* nil)

(defun %reap-inbound ()
  (bt:with-lock-held (*inbound-lock*)
    (setf *inbound-peers* (remove-if-not #'p:peer-alive-p *inbound-peers*))
    (length *inbound-peers*)))

(defun start-listener (&key (port (w:net-port w:*network*)) (host "0.0.0.0") (max-peers 64))
  "Accept inbound P2P connections in a background thread: handshake each (advertising
   NODE_NETWORK|WITNESS), install serving handlers, track it (up to MAX-PEERS).  Each
   connection is handshaked + served in its own thread, and per-connection errors are
   isolated so one bad peer can't take down the listener.  Returns the listener thread."
  (setf *listener-thread*
    (bt:make-thread
     (lambda ()
       (handler-case
           (let ((sock (usocket:socket-listen host port :reuse-address t
                                              :element-type '(unsigned-byte 8))))
             (format t "~&[serve] listening for inbound peers on ~a:~d~%" host port) (force-output)
             (loop
               (handler-case
                   (let ((conn (usocket:socket-accept sock :element-type '(unsigned-byte 8))))
                     (cond
                       ((>= (%reap-inbound) max-peers)
                        (ignore-errors (usocket:socket-close conn)))      ; at cap: drop
                       (t
                        (bt:make-thread
                         (lambda ()
                           (handler-case
                               (let ((pr (p:accept-peer conn)))
                                 (install-serving-handlers pr)
                                 (bt:with-lock-held (*inbound-lock*) (push pr *inbound-peers*))
                                 (format t "~&[serve] inbound peer up: ~a ~a (height ~a)~%"
                                         (p:peer-addr pr) (p:peer-subver pr) (p:peer-height pr))
                                 (force-output))
                             (serious-condition (e)
                               (format t "~&[serve] inbound handshake failed: ~a~%" e) (force-output)
                               (ignore-errors (usocket:socket-close conn)))))
                         :name "btc-accept"))))
                 (serious-condition (e)
                   (format t "~&[serve] accept error: ~a~%" e) (force-output)))))
         (serious-condition (e)
           (format t "~&[serve] listener died: ~a~%" e) (force-output))))
     :name "btc-listener")))

;;; ----------------------------------------------------------------------------
;;; The serving daemon
;;; ----------------------------------------------------------------------------

(defun %follow-headers (out)
  "Install live header-following handlers on the OUTBOUND peer so the chain stays
   current (we serve the freshest headers)."
  (p:on out "headers"
        (lambda (pr payload)
          (dolist (h (c::parse-headers-message payload))
            (handler-case (c:add-header h) (serious-condition () nil)))
          (p:send pr "getheaders" (c::build-getheaders-payload (c:build-locator)))))
  (p:on out "inv"
        (lambda (pr payload)
          (declare (ignore payload))
          (p:send pr "getheaders" (c::build-getheaders-payload (c:build-locator))))))

(defparameter *recent-blocks* 288
  "How many of the most-recent blocks to keep stored & serveable (NODE_NETWORK_LIMITED
   keeps the last 288).  The serving daemon backfills this rolling window.")

(defun %backfill-recent (out &key (recent *recent-blocks*) (max-per-pass 64))
  "Fetch & store any block in the rolling [tip-RECENT .. tip] window that we don't
   already have, from the OUTBOUND peer OUT.  Bounded to MAX-PER-PASS fetches per call
   so a fresh start doesn't stall the loop.  Per-block error isolation."
  (when *block-store*
    (let* ((tip (c:tip-height))
           (from (max 1 (- tip recent)))
           (fetched 0))
      (loop for ht from from to tip
            while (< fetched max-per-pass) do
        (let ((hdr (c:header-at-height ht)))
          (when hdr
            (let ((hx (c:header-hash-hex hdr)))
              (unless (bs:block-store-has-p *block-store* hx)
                (handler-case
                    (let ((raw (blk:get-block-raw out (c:header-hash hdr) :timeout 30)))
                      (bs:store-block *block-store* raw)
                      (incf fetched))
                  (serious-condition (e)
                    (format t "~&[serve] block ~d fetch failed: ~a~%" ht e) (force-output))))))))
      fetched)))

(defun serve-daemon (&key (listen-port (w:net-port w:*network*))
                          (peer-host "epyc-docker.lan") (max-peers 64)
                          (block-store-path "/mnt/lisp/ptchain/blocks.dat")
                          (recent-blocks *recent-blocks*))
  "Long-lived network-citizen daemon: follow the header tip from an OUTBOUND peer,
   keep a rolling window of the most-recent blocks stored, and SERVE inbound
   getheaders + getdata(block).  Header-chain + a recent-blocks store (no UTXO) — runs
   alongside the keep-current UTXO writer.  Blocks forever (accept + read loops run in
   threads)."
  (c:init-chain) (c:load-headers)
  (when block-store-path
    (setf *block-store* (bs:open-block-store block-store-path))
    (format t "~&[serve] block store ~a: ~d blocks~%"
            block-store-path (bs:block-store-count *block-store*)) (force-output))
  (let ((out (p:connect-peer peer-host :start-height (c:tip-height))))
    (handler-case (c:sync-headers out) (serious-condition () nil))
    (ignore-errors (p:send out "sendheaders" #()))
    (%follow-headers out)
    (format t "~&[serve] following headers via ~a; tip ~d~%" peer-host (c:tip-height)) (force-output)
    (start-listener :port listen-port :max-peers max-peers)
    (loop
      (handler-case (%backfill-recent out :recent recent-blocks)
        (serious-condition (e) (format t "~&[serve] backfill error: ~a~%" e) (force-output)))
      (sleep 60)
      (format t "~&[serve] tip ~d, ~d inbound peers, ~d blocks stored~%"
              (c:tip-height) (%reap-inbound)
              (if *block-store* (bs:block-store-count *block-store*) 0))
      (force-output))))

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
                    (#:bs #:cl-consensus.blockstore) (#:mp #:cl-consensus.mempool)
                    (#:tx #:cl-consensus.tx) (#:u #:cl-consensus.utxo)
                    (#:bt #:bordeaux-threads))
  (:export #:parse-getheaders #:build-headers-message #:serve-getheaders
           #:parse-getdata #:serve-getdata #:*block-store*
           #:build-inv-message #:announce-block #:*max-relay-advance*
           #:announce-tx #:handle-inbound-tx #:*mempool* #:*utxo* #:*orphans*
           #:*tx-relay-enabled* #:add-orphan #:orphans-spending
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

(defconstant +msg-tx+ 1)
(defconstant +msg-witness-tx+ #x40000001)

(defun %tx-getdata-p (type) (= (logand type #x3fffffff) +msg-tx+))

(defun serve-getdata (peer payload)
  "Answer a peer's getdata: MSG_BLOCK/MSG_WITNESS_BLOCK from the block store (raw
   'block'), MSG_TX/MSG_WITNESS_TX from the mempool ('tx'); collect the misses and reply
   'notfound'."
  (let ((entries (parse-getdata payload))
        (misses '()) (blocks 0) (txs 0))
    (dolist (e entries)
      (let ((type (car e)) (hash (cdr e)))
        (cond
          ((%block-getdata-p type)
           (let ((raw (and *block-store* (bs:get-block-bytes *block-store* (w:hash->hex hash)))))
             (if raw (progn (p:send peer "block" raw) (incf blocks)) (push e misses))))
          ((%tx-getdata-p type)
           (let ((ent (and *mempool*
                           (bt:with-lock-held (*relay-lock*)
                             (mp:mempool-get *mempool* (w:hash->hex hash))))))
             (if ent
                 (progn (p:send peer "tx" (tx:serialize-tx (mp:entry-tx ent) :witness t)) (incf txs))
                 (push e misses))))
          (t nil))))                              ; unknown inv type: ignore
    (when misses
      (p:send peer "notfound" (build-notfound-message (nreverse misses))))
    (p:peer-log peer "served ~d block(s) ~d tx(s), ~d notfound" blocks txs (length misses))))

;;; ----------------------------------------------------------------------------
;;; Tx relay — accept inbound txs into the mempool, announce + serve them (Phase 3b)
;;; ----------------------------------------------------------------------------

(defvar *mempool* nil "The shared mempool tx relay accepts into (nil = no tx relay).")
(defvar *utxo* nil "Confirmed coin set used to validate inbound txs (nil = none).")
(defvar *relay-lock* (bt:make-lock "tx-relay")
  "Guards *mempool* + *orphans*: inbound peers run on separate read-loop threads.")
(defparameter *tx-relay-enabled* nil
  "Only accept/serve txs when a mempool + UTXO are wired (else every real tx is a
   missing-inputs orphan).  serve-daemon sets this when it has a UTXO.")

;; Orphan pool: txs whose inputs aren't all known yet (out-of-order relay arrival).
(defstruct orphan-pool (txs (make-hash-table :test 'equal)) (max 100))
(defvar *orphans* (make-orphan-pool))

(defun %unix-now () (- (get-universal-time) 2208988800))
(defun %accept-height () (1+ (c:tip-height)))
(defun %accept-mtp () (handler-case (c:median-time-past (c:tip)) (serious-condition () 0)))

(defun add-orphan (txn)
  "Park TXN in the orphan pool, evicting an arbitrary orphan if at capacity."
  (let ((tbl (orphan-pool-txs *orphans*)))
    (when (>= (hash-table-count tbl) (orphan-pool-max *orphans*))
      (let ((victim (block pick (maphash (lambda (k v) (declare (ignore v)) (return-from pick k)) tbl))))
        (when victim (remhash victim tbl))))
    (setf (gethash (tx:txid-hex txn) tbl) txn)))

(defun orphans-spending (parent-txid-hex)
  "Orphan txns that spend an output of PARENT-TXID-HEX (candidates to retry now that the
   parent is in the mempool)."
  (loop for txn being the hash-values of (orphan-pool-txs *orphans*)
        when (some (lambda (in) (string= (w:hash->hex (tx:txin-prev-hash in)) parent-txid-hex))
                   (tx:tx-inputs txn))
        collect txn))

(defun announce-tx (txid-hex &optional source-peer)
  "inv(MSG_TX) TXID-HEX to every live inbound peer except SOURCE-PEER (don't echo it
   back to the peer that sent it).  Per-peer error isolation."
  (let ((peers (bt:with-lock-held (*inbound-lock*) (copy-list *inbound-peers*)))
        (hash (w:hex->hash txid-hex)))
    (dolist (pr peers)
      (when (and (p:peer-alive-p pr) (not (eq pr source-peer)))
        (handler-case (p:send pr "inv" (build-inv-message (list (cons +msg-tx+ hash))))
          (serious-condition () nil))))))

(defun request-parents (peer txn)
  "Ask PEER for any of TXN's parents we don't yet have (getdata MSG_WITNESS_TX).  Best
   effort — the parent arrives later as its own 'tx' message (no blocking wait here)."
  (dolist (in (tx:tx-inputs txn))
    (let* ((ph (tx:txin-prev-hash in)) (phx (w:hash->hex ph)))
      (unless (or (and *utxo* (u:utxo-get *utxo* ph (tx:txin-prev-index in)))
                  (mp:mempool-get *mempool* phx))
        (handler-case
            (p:send peer "getdata" (build-inv-message (list (cons +msg-witness-tx+ ph))))
          (serious-condition () nil))))))

(defun %try-accept (txn source-peer)
  "Accept TXN into the mempool (caller holds *relay-lock*).  On success announce it and
   recursively retry any orphans that were waiting on it; on missing-inputs park it as an
   orphan and request its parents; other rejects drop it.  Returns T if accepted."
  (let ((txid-hex (tx:txid-hex txn)))
    (handler-case
        (progn
          (mp:accept-tx txn *utxo* *mempool*
                        :height (%accept-height) :mtp (%accept-mtp) :time (%unix-now))
          (announce-tx txid-hex source-peer)
          ;; this tx may unblock parked orphans
          (dolist (orphan (orphans-spending txid-hex))
            (remhash (tx:txid-hex orphan) (orphan-pool-txs *orphans*))
            (%try-accept orphan source-peer))
          t)
      (mp:rejected (e)
        (when (search "missing-inputs" (mp:rejected-reason e))
          (add-orphan txn)
          (when source-peer (request-parents source-peer txn)))
        nil))))

(defun handle-inbound-tx (peer payload)
  "Dispatch handler for an inbound 'tx': parse, validate, and relay.  Runs on the peer's
   read-loop thread but never blocks on a reply (accept is CPU-only; announce/getdata are
   non-blocking sends), so it can't deadlock the read-loop."
  (when *tx-relay-enabled*
    (handler-case
        (let ((txn (tx:parse-tx (w:make-reader payload))))
          (tx:finalize-tx txn)
          (bt:with-lock-held (*relay-lock*)
            (unless (mp:mempool-get *mempool* (tx:txid-hex txn))
              (%try-accept txn peer))))
      (serious-condition (e)
        (format t "~&[serve] inbound tx error: ~a~%" e) (force-output)))))

(defun install-serving-handlers (peer)
  "Register the read-only serving responders on PEER: getheaders, getdata, and (when tx
   relay is enabled) inbound tx."
  (p:on peer "getheaders" #'serve-getheaders)
  (p:on peer "getdata" #'serve-getdata)
  (p:on peer "tx" #'handle-inbound-tx))

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

;;; ----------------------------------------------------------------------------
;;; Block relay — announce new blocks to inbound peers (Phase 3a)
;;; ----------------------------------------------------------------------------

(defparameter *max-relay-advance* 8
  "Only RELAY a tip advance of at most this many blocks.  A bigger jump is catch-up
   (e.g. the initial header sync), not live propagation — those blocks are covered by
   the recent-window backfill, not the per-block relay path.")

(defun build-inv-message (entries)
  "Serialize an 'inv' payload from a list of (type . hash) inventory entries (same
   wire layout as getdata)."
  (let ((wr (w:make-writer)))
    (w:w-varint wr (length entries))
    (dolist (e entries) (w:w-u32 wr (car e)) (w:w-hash wr (cdr e)))
    (w:writer-bytes wr)))

(defun announce-block (header)
  "Announce HEADER to every live inbound peer: a BIP130 'headers' announcement to
   peers that sent sendheaders, an 'inv' (MSG_BLOCK) to the rest.  Per-peer error
   isolation; the peer follows up with getdata, which serve-getdata answers from the
   block store."
  (let ((peers (bt:with-lock-held (*inbound-lock*) (copy-list *inbound-peers*)))
        (hash (c:header-hash header)))
    (dolist (pr peers)
      (when (p:peer-alive-p pr)
        (handler-case
            (if (p:peer-prefers-headers pr)
                (p:send pr "headers" (build-headers-message (list header)))
                (p:send pr "inv" (build-inv-message (list (cons blk:+msg-block+ hash)))))
          (serious-condition (e)
            (format t "~&[serve] announce to ~a failed: ~a~%" (p:peer-addr pr) e) (force-output)))))))

(defun %announce-new (last-announced)
  "MAIN-THREAD relay step.  Announce blocks newly available above LAST-ANNOUNCED, in
   order, returning the new high-water mark.  Only blocks we actually have STORED are
   announced (so the peer's getdata is answerable); a contiguous run stops at the first
   not-yet-stored height and retries next tick.  A large gap (> *max-relay-advance*) is
   catch-up, not live propagation: jump the mark to tip WITHOUT announcing (those blocks
   are covered by the recent-window backfill).

   This runs on the daemon's main loop, NEVER inside the read-loop dispatch handler — a
   synchronous getdata there would deadlock the very thread that must deliver the reply."
  (let ((tip (c:tip-height)))
    (when (> (- tip last-announced) *max-relay-advance*)
      (return-from %announce-new tip))            ; catch-up: skip relay
    (loop for ht from (1+ last-announced) to tip do
      (let ((hdr (c:header-at-height ht)))
        (if (and hdr *block-store*
                 (bs:block-store-has-p *block-store* (c:header-hash-hex hdr)))
            (progn
              (announce-block hdr)
              (format t "~&[serve] relayed block ~d ~a to ~d peer(s)~%"
                      ht (c:header-hash-hex hdr) (length *inbound-peers*)) (force-output)
              (setf last-announced ht))
            (return))))                            ; not stored yet -> retry next tick
    last-announced))

(defun %follow-headers (out)
  "Keep the chain current from the OUTBOUND peer: on any headers/inv, add and
   re-request.  Block FETCH + relay happen on the main daemon loop (see %announce-new) —
   we deliberately do NO synchronous getdata here, since this runs on the read-loop
   thread and blocking it would deadlock against the reply it must itself read."
  (p:on out "headers"
        (lambda (pr payload)
          (let ((before (c:tip-height)))
            (dolist (h (c::parse-headers-message payload))
              (handler-case (c:add-header h) (serious-condition () nil)))
            (when (> (c:tip-height) before)
              (p:send pr "getheaders" (c::build-getheaders-payload (c:build-locator)))))))
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
    ;; main loop: store the recent window + relay newly-stored blocks.  Both block
    ;; fetches (getdata) happen HERE, serialized on this thread, so they never deadlock
    ;; the read-loop and never race each other for the single 'block' handler slot.
    ;; last-announced starts at the boot tip so the backfilled window isn't re-announced.
    (let ((last-announced (c:tip-height)) (ticks 0))
      (loop
        (handler-case (%backfill-recent out :recent recent-blocks)
          (serious-condition (e) (format t "~&[serve] backfill error: ~a~%" e) (force-output)))
        (handler-case (setf last-announced (%announce-new last-announced))
          (serious-condition (e) (format t "~&[serve] announce error: ~a~%" e) (force-output)))
        (when (>= (incf ticks) 12)                 ; status every ~60s (12 * 5s)
          (setf ticks 0)
          (format t "~&[serve] tip ~d, ~d inbound peers, ~d blocks stored~%"
                  (c:tip-height) (%reap-inbound)
                  (if *block-store* (bs:block-store-count *block-store*) 0))
          (force-output))
        (sleep 5)))))

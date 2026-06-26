;;;; shared/bitcoind/node.lisp
;;;;
;;;; Phase 6 — the node daemon: ties the layers together and exposes a
;;;; bitcoind-compatible JSON-RPC surface over HTTP, plus a mempool and a
;;;; control socket for hot-reload (repo convention).
;;;;
;;;; The RPC method shapes mirror Bitcoin Core so existing tooling / bitcoin-cli
;;;; style calls work.  Chain-backed read methods are live; mempool methods come
;;;; online when a UTXO set is attached.


(defpackage #:cl-consensus.node
  (:use #:cl)
  (:nicknames #:btc-node)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:p #:cl-consensus.peer)
                    (#:c #:cl-consensus.chain) (#:tx #:cl-consensus.tx)
                    (#:blk #:cl-consensus.block) (#:u #:cl-consensus.utxo)
                    (#:v #:cl-consensus.validate) (#:mp #:cl-consensus.mempool)
                    (#:s #:cl-consensus.serve) (#:r #:cl-consensus.reorg)
                    (#:bs #:cl-consensus.blockstore)
                    (#:ht #:hunchentoot)
                    (#:jzon #:com.inuoe.jzon) (#:bt #:bordeaux-threads))
  (:export #:start #:stop #:reload! #:*rpc-port* #:*control-port* #:rpc-call
           #:serve-node #:*utxo* #:*mempool*))

(in-package #:cl-consensus.node)

(defparameter *rpc-port* 8432)          ; our JSON-RPC (avoid Core's 8332)
(defparameter *control-port* 4008)
(defvar *acceptor* nil)
(defvar *control-thread* nil)
(defvar *utxo* nil "Attached UTXO set, if validation state is loaded.")
(defvar *mempool* (mp:make-mempool))
(defvar *start-time* 0)

;;; ----------------------------------------------------------------------------
;;; JSON helpers
;;; ----------------------------------------------------------------------------

(defun obj (&rest kv)
  "Build a string-keyed hash table (renders as a JSON object) from a plist."
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k val) on kv by #'cddr do (setf (gethash k h) val))
    h))

(defun difficulty (bits)
  (coerce (/ (c:compact->target #x1d00ffff) (c:compact->target bits)) 'double-float))

(defun bits-hex (bits) (format nil "~(~8,'0x~)" bits))

;;; ----------------------------------------------------------------------------
;;; RPC methods — bitcoind-compatible shapes
;;; ----------------------------------------------------------------------------

(defun m-getblockcount (&rest _) (declare (ignore _)) (c:tip-height))
(defun m-getbestblockhash (&rest _) (declare (ignore _)) (c:header-hash-hex (c:tip)))
(defun m-getdifficulty (&rest _) (declare (ignore _)) (difficulty (c:header-bits (c:tip))))
(defun m-uptime (&rest _) (declare (ignore _)) (- (get-universal-time) *start-time*))

(defun m-getblockhash (height &rest _)
  (declare (ignore _))
  (let ((h (c:header-at-height (truncate height))))
    (unless h (error "block height out of range"))
    (c:header-hash-hex h)))

(defun header->json (h)
  (let* ((height (c:header-height h))
         (next (c:header-at-height (1+ height))))
    (obj "hash" (c:header-hash-hex h)
         "height" height
         "version" (c:header-version h)
         "versionHex" (format nil "~(~8,'0x~)" (logand (c:header-version h) #xffffffff))
         "merkleroot" (w:hash->hex (c:header-merkle h))
         "time" (c:header-time h)
         "mediantime" (c:median-time-past h)
         "nonce" (c:header-nonce h)
         "bits" (bits-hex (c:header-bits h))
         "difficulty" (difficulty (c:header-bits h))
         "chainwork" (format nil "~(~64,'0x~)" (c:header-chainwork h))
         "previousblockhash" (if (zerop height) 'null (w:hash->hex (c:header-prev h)))
         "nextblockhash" (if next (c:header-hash-hex next) 'null))))

(defun m-getblockheader (hash &optional (verbose t) &rest _)
  (declare (ignore _))
  (let ((h (c:get-header hash)))
    (unless h (error "block not found"))
    (if verbose (header->json h) (w:bytes->hex (c:serialize-header h)))))

(defun m-getblockchaininfo (&rest _)
  (declare (ignore _))
  (let ((tip (c:tip)))
    (obj "chain" (string-downcase (symbol-name (w:net-name w:*network*)))
         "blocks" (c:tip-height)
         "headers" (c:tip-height)
         "bestblockhash" (c:header-hash-hex tip)
         "bits" (bits-hex (c:header-bits tip))
         "difficulty" (difficulty (c:header-bits tip))
         "time" (c:header-time tip)
         "mediantime" (c:median-time-past tip)
         "chainwork" (format nil "~(~64,'0x~)" (c:header-chainwork tip))
         "initialblockdownload" nil
         "verificationprogress" 1.0d0
         "utxo_set_loaded" (if *utxo* t nil)
         "utxo_count" (if *utxo* (u:utxo-count *utxo*) 0))))

(defun m-getmempoolinfo (&rest _)
  (declare (ignore _))
  (obj "loaded" t
       "size" (mp:mempool-size *mempool*)
       "bytes" (mp:mempool-bytes *mempool*)
       "usage" (mp:mempool-bytes *mempool*)))

(defun m-getrawmempool (&rest _)
  (declare (ignore _))
  (coerce (mp:mempool-txids *mempool*) 'vector))

(defun parse-tx-hex (hexstring)
  (tx:parse-tx (w:make-reader (w:hex->bytes hexstring))))

(defun m-sendrawtransaction (hexstring &rest _)
  "Validate a raw tx against the UTXO set + mempool and accept it; return txid."
  (declare (ignore _))
  (unless *utxo* (error "no UTXO set loaded (cannot validate)"))
  (let ((txn (parse-tx-hex hexstring)))
    (handler-case
        (progn (mp:accept-tx txn *utxo* *mempool*
                             :height (1+ (c:tip-height)) :mtp (c:median-time-past (c:tip)))
               (tx:txid-hex txn))
      (mp:rejected (e) (error "~a" (mp:rejected-reason e))))))

(defun m-testmempoolaccept (rawtxs &rest _)
  "Dry-run mempool acceptance for an array of raw tx hexes."
  (declare (ignore _))
  (unless *utxo* (error "no UTXO set loaded"))
  (map 'vector
       (lambda (hx)
         (let ((txn (parse-tx-hex hx)))
           (handler-case
               (let ((e (mp:accept-tx txn *utxo* *mempool*
                                      :height (1+ (c:tip-height)) :mtp (c:median-time-past (c:tip))
                                      :check-only t)))
                 (obj "txid" (tx:txid-hex txn) "allowed" t
                      "vsize" (mp:entry-vsize e) "fees" (obj "base" (/ (mp:entry-fee e) 1d8))))
             (mp:rejected (er)
               (obj "txid" (tx:txid-hex txn) "allowed" nil
                    "reject-reason" (mp:rejected-reason er))))))
       rawtxs))

(defun m-gettxout (txid vout &rest _)
  "Look up an unspent output in the attached UTXO set (null if spent/absent)."
  (declare (ignore _))
  (unless *utxo* (error "no UTXO set loaded"))
  (let ((coin (u:utxo-get *utxo* (w:hex->hash txid) (truncate vout))))
    (if (null coin) 'null
        (obj "bestblock" (c:header-hash-hex (c:tip))
             "value" (/ (u:coin-value coin) 1d8)
             "scriptPubKey" (obj "hex" (w:bytes->hex (u:coin-script coin)))
             "coinbase" (if (u:coin-coinbase-p coin) t nil)
             "height" (u:coin-height coin)))))

(defun m-help (&rest _)
  (declare (ignore _))
  (format nil "methods: ~{~a~^, ~}"
          (sort (loop for k being the hash-keys of *methods* collect k) #'string<)))

(defvar *methods* (make-hash-table :test 'equal))

(defun register-methods ()
  (clrhash *methods*)
  (dolist (m '(("getblockcount" m-getblockcount)
               ("getbestblockhash" m-getbestblockhash)
               ("getdifficulty" m-getdifficulty)
               ("getblockhash" m-getblockhash)
               ("getblockheader" m-getblockheader)
               ("getblockchaininfo" m-getblockchaininfo)
               ("getmempoolinfo" m-getmempoolinfo)
               ("getrawmempool" m-getrawmempool)
               ("sendrawtransaction" m-sendrawtransaction)
               ("testmempoolaccept" m-testmempoolaccept)
               ("gettxout" m-gettxout)
               ("uptime" m-uptime)
               ("help" m-help)))
    (setf (gethash (first m) *methods*) (symbol-function (second m)))))

;;; ----------------------------------------------------------------------------
;;; JSON-RPC dispatch over HTTP
;;; ----------------------------------------------------------------------------

(defun rpc-call (method params)
  "Dispatch one JSON-RPC call; returns (values result error)."
  (let ((fn (gethash method *methods*)))
    (if (null fn)
        (values nil (obj "code" -32601 "message" (format nil "Method not found: ~a" method)))
        (handler-case
            (values (apply fn (coerce params 'list)) nil)
          (error (e) (values nil (obj "code" -1 "message" (format nil "~a" e))))))))

(defun handle-one (req)
  (let ((id (gethash "id" req))
        (method (gethash "method" req))
        (params (or (gethash "params" req) #())))
    (multiple-value-bind (result err) (rpc-call method params)
      (obj "result" (if err 'null result) "error" (or err 'null) "id" (or id 'null)))))

(defun rpc-handler ()
  (setf (ht:content-type*) "application/json")
  (let* ((raw (ht:raw-post-data :force-text t))
         (parsed (handler-case (jzon:parse raw) (error () nil))))
    (jzon:stringify
     (cond
       ((null parsed) (obj "result" 'null
                           "error" (obj "code" -32700 "message" "Parse error") "id" 'null))
       ((vectorp parsed) (map 'vector #'handle-one parsed))   ; batch
       (t (handle-one parsed))))))

;;; ----------------------------------------------------------------------------
;;; Live chain-follow — keep a peer, extend the header chain as blocks arrive
;;; ----------------------------------------------------------------------------

(defvar *peer* nil)

(defun install-live-handlers (peer)
  "After initial sync, track the tip: the peer announces new blocks via headers
   (BIP130 sendheaders) or inv; either way we extend the chain."
  (p:on peer "headers"
        (lambda (pr payload)
          (dolist (h (c::parse-headers-message payload))
            (handler-case (c:add-header h)
              (c::header-rejected () nil)))   ; unknown-parent / already-known are fine
          ;; if a batch arrived we may be behind; ask for more
          (p:send pr "getheaders" (c::build-getheaders-payload (c:build-locator)))))
  (p:on peer "inv"
        (lambda (pr payload)
          ;; any inv (block or tx) — nudge a header request to stay current
          (declare (ignore payload))
          (p:send pr "getheaders" (c::build-getheaders-payload (c:build-locator))))))

(defun start-follow (&optional (host "epyc-docker.lan"))
  "Connect a peer, sync headers to the tip, then follow new blocks live."
  (setf *peer* (p:connect-peer host :start-height (c:tip-height)))
  (c:sync-headers *peer*)               ; catch up to the peer's tip
  (p:send *peer* "sendheaders" #())     ; ask to be pushed future headers
  (install-live-handlers *peer*)
  (format t "~&[bitcoind] following chain via ~a; tip ~d~%" host (c:tip-height))
  *peer*)

;;; ----------------------------------------------------------------------------
;;; Consolidated node: validate to tip (single UTXO writer) + serve + relay
;;; ----------------------------------------------------------------------------

(defun %confirm-into-mempool (block)
  "Drop confirmed + now-conflicting txs from the live mempool when BLOCK connects."
  (when s:*mempool*
    (bt:with-lock-held (s:*relay-lock*)
      (mp:mempool-on-block s:*mempool* (coerce (blk:block-txs block) 'list)))))

(defun %connect-new-blocks (peers utxo undo committed)
  "Fetch + connect every block from COMMITTED+1 to the header tip into UTXO, recording
   undo, storing the raw bytes, dropping confirmed mempool txs, and announcing each to
   inbound peers.  Returns the new committed height.  Synchronous per block — ample at
   the ~1-block/10-min tip-following rate, and far simpler than the async IBD pipeline."
  (let ((target (c:tip-height)))
    (loop for h from (1+ committed) to target do
      (let* ((hdr (c:header-at-height h))
             (raw (blk:get-block-raw (first peers) (c:header-hash hdr)))
             (b (blk:parse-block raw)))
        (multiple-value-bind (fees undo-rec) (v:connect-block b h utxo)
          (declare (ignore fees))
          (r:undo-put undo h undo-rec))
        (when s:*block-store* (bs:store-block s:*block-store* raw))
        (%confirm-into-mempool b)
        (s:announce-block hdr)
        (setf committed h)
        (format t "~&[node] connected + served block ~d~%" h) (force-output)))
    committed))

(defun validating-follow-loop (peers utxo undo start-height &key (poll 30))
  "Long-lived: keep the UTXO at the header tip (reorg-aware), serving + relaying as we
   go.  This thread is the SINGLE writer of the UTXO store."
  (let ((committed start-height))
    (loop
      (handler-case
          (progn
            (handler-case (c:sync-headers (first peers) :max-batches 50) (serious-condition () nil))
            (setf u:*utxo-flush-method* :incremental)
            ;; reorg: roll the UTXO onto the heaviest branch before extending it
            (multiple-value-bind (h2 reorged depth)
                (r:activate-best-chain utxo committed undo
                                       (lambda (hdr) (blk:get-block (first peers) (c:header-hash hdr))))
              (when reorged
                (format t "~&[node] *** REORG depth ~d: ~d -> ~d ***~%" depth committed h2) (force-output)
                (u:flush-utxo utxo h2) (c:save-headers) (r:undo-commit undo)
                (setf committed h2)))
            ;; extend forward
            (when (> (c:tip-height) committed)
              (setf committed (%connect-new-blocks peers utxo undo committed))
              (u:flush-utxo utxo committed) (c:save-headers) (r:undo-commit undo)
              (when (> committed 288) (r:undo-prune undo (- committed 288)))))
        (r:deep-reorg-halt (e)
          (format t "~&[node] HALT (deep reorg): ~a~%" e) (force-output) (return))
        (r:reorg-error (e)
          (format t "~&[node] HALT (reorg-error): ~a~%" e) (force-output) (return))
        (serious-condition (e)
          (format t "~&[node] follow error: ~a~%" e) (force-output)))
      (sleep poll))))

(defun serve-node (&key (store "/mnt/lisp/ptchain/live.pt")
                        (block-store "/mnt/lisp/ptchain/blocks.dat")
                        (peer-host "epyc-docker.lan") (conns 2) (cache-gb 24)
                        (listen-port (w:net-port w:*network*)) (rpc-port *rpc-port*)
                        (max-peers 64) (poll 30))
  "THE consolidated node: own the pagetree UTXO (single writer), validate new blocks to
   the tip (reorg-aware), and SERVE headers/blocks + RELAY txs to inbound peers with a
   tip-current UTXO + mempool, plus JSON-RPC + the control socket.  Replaces the
   keep-current poll AND the header-only serve-daemon.  Blocks forever."
  (setf *rpc-port* rpc-port *start-time* (get-universal-time))
  (c:init-chain) (c:load-headers)
  (let* ((peers (loop repeat conns collect (p:connect-peer peer-host :start-height (c:tip-height))))
         (undo (r:open-pt-undo-store (concatenate 'string store ".undo"))))
    (handler-case (c:sync-headers (first peers) :max-batches 50) (serious-condition () nil))
    (multiple-value-bind (utxo height)
        (u:open-utxo-backend store :backend :pagetree :cache-bytes (* cache-gb 1024 1024 1024))
      (setf *utxo* utxo
            s:*block-store* (bs:open-block-store block-store)
            s:*utxo* utxo s:*mempool* *mempool* s:*tx-relay-enabled* t)
      (format t "~&[node] UTXO resume height ~d (~d coins); block store ~d blocks~%"
              height (u:utxo-count utxo) (bs:block-store-count s:*block-store*)) (force-output)
      (register-methods)
      (setf *acceptor* (make-instance 'ht:easy-acceptor :port rpc-port :address "0.0.0.0"))
      (setf (ht:acceptor-message-log-destination *acceptor*) nil
            (ht:acceptor-access-log-destination *acceptor*) nil)
      (ht:define-easy-handler (rpc :uri "/") () (rpc-handler))
      (ht:start *acceptor*)
      (unless *control-thread*
        (setf *control-thread* (bt:make-thread #'control-loop :name "btc-node control")))
      (s:start-listener :port listen-port :max-peers max-peers)
      (format t "~&[node] serve-node up: RPC :~d control :~d P2P :~d  follow ~a  tip ~d~%"
              rpc-port *control-port* listen-port peer-host (c:tip-height)) (force-output)
      (unwind-protect (validating-follow-loop peers utxo undo height :poll poll)
        (r:close-pt-undo-store undo)))))

;;; ----------------------------------------------------------------------------
;;; Control socket (hot reload), start/stop
;;; ----------------------------------------------------------------------------

(defun reload! ()
  "Hot-reload the system (ASDF recompiles only changed files) and re-register
   RPC methods.  `echo '(reload!)' | nc 127.0.0.1 4008`."
  (asdf:load-system "cl-consensus")
  (register-methods)
  :reloaded)

(defun control-loop ()
  "Bare-TCP control socket (repo convention): read forms, eval in this package,
   write the printed result.  `echo '(reload!)' | nc 127.0.0.1 4008`."
  (handler-case
      (let ((sock (usocket:socket-listen "127.0.0.1" *control-port* :reuse-address t)))
        (loop
          (handler-case
              (let* ((conn (usocket:socket-accept sock)) (s (usocket:socket-stream conn)))
                (unwind-protect
                     (let ((*package* (find-package '#:cl-consensus.node)))
                       (loop for form = (read s nil :eof) until (eq form :eof) do
                         (let ((rr (handler-case (format nil "~s" (eval form))
                                     (serious-condition (e) (format nil "ERR: ~a" e)))))
                           (write-string rr s) (terpri s) (force-output s))))
                  (ignore-errors (usocket:socket-close conn))))
            (serious-condition () nil))))
    (serious-condition () nil)))

(defun start (&key (rpc-port *rpc-port*) (load-chain t) (utxo nil) (follow nil))
  "Start the node: load headers, register RPC methods, start the JSON-RPC HTTP
   server and the control socket.  UTXO optionally attaches a chainstate;
   FOLLOW connects a peer and tracks the chain tip live."
  (setf *rpc-port* rpc-port *start-time* (get-universal-time))
  (when load-chain (unless (c:tip) (c:load-headers)))
  (when utxo (setf *utxo* utxo))
  (register-methods)
  (when follow
    (bt:make-thread (lambda () (ignore-errors (start-follow))) :name "btc-node follow"))
  (setf *acceptor* (make-instance 'ht:easy-acceptor :port rpc-port :address "0.0.0.0"))
  (setf (ht:acceptor-message-log-destination *acceptor*) nil
        (ht:acceptor-access-log-destination *acceptor*) nil)
  (ht:define-easy-handler (rpc :uri "/") () (rpc-handler))
  (ht:start *acceptor*)
  (unless *control-thread*
    (setf *control-thread* (bt:make-thread #'control-loop :name "btc-node control")))
  (format t "~&[bitcoind] RPC on :~d  control on :~d  tip ~d~%"
          rpc-port *control-port* (c:tip-height))
  t)

(defun stop ()
  (when *acceptor* (ht:stop *acceptor*) (setf *acceptor* nil))
  t)

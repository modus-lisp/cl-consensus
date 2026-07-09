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
                    (#:enc #:cl-consensus.encoding) (#:fee #:cl-consensus.fees)
                    (#:d #:cl-consensus.discovery) (#:am #:cl-consensus.addrman)
                    (#:onion #:cl-consensus.onion)
                    (#:ht #:hunchentoot)
                    (#:jzon #:com.inuoe.jzon) (#:bt #:bordeaux-threads))
  (:export #:start #:stop #:reload! #:*rpc-port* #:*control-port* #:rpc-call
           #:serve-node #:*utxo* #:*mempool* #:*onion-service-hook* #:live-peers))

(in-package #:cl-consensus.node)

(defparameter *rpc-port* 8432)          ; our JSON-RPC (avoid Core's 8332)
(defparameter *control-port* 4008)
(defvar *acceptor* nil)
(defvar *control-thread* nil)
(defvar *utxo* nil "Attached UTXO set, if validation state is loaded.")
(defvar *mempool* (mp:make-mempool))
(defvar *mempool-path* nil "If set, persist/restore the mempool here across restarts.")
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

;;; ----------------------------------------------------------------------------
;;; Fee estimation (mempool-based) — see src/fees.lisp
;;; ----------------------------------------------------------------------------

(defun sat/vb->btc/kvb (sat/vb)
  "Convert a feerate in sat/vB to Core's BTC per 1000 vBytes."
  (/ (* sat/vb 1000) 1d8))

(defun m-estimatesmartfee (conf-target &optional estimate-mode &rest _)
  "Mempool-based smart fee estimate, Core-shaped: {feerate: BTC/kvB, blocks: N}.
   Falls back to the relay floor (1 sat/vB) with an `errors` note when the current
   mempool backlog is too thin to imply congestion (e.g. an empty mempool)."
  (declare (ignore estimate-mode _))
  (let* ((target (min fee:*max-conf-target* (max 1 (truncate conf-target))))
         (sat/vb (fee:estimate-feerate *mempool* target)))
    (if sat/vb
        (obj "feerate" (sat/vb->btc/kvb sat/vb) "blocks" target)
        (obj "feerate" (sat/vb->btc/kvb fee:*min-relay-feerate*) "blocks" target
             "errors" (vector "Insufficient data or no feerate estimate available; using relay floor")))))

(defun m-estimaterawfee (conf-target &optional threshold &rest _)
  "Lightweight raw estimator: the mempool feerate for CONF-TARGET blocks, reported
   both in BTC/kvB and sat/vB (NIL feerate when the backlog can't price it)."
  (declare (ignore threshold _))
  (let* ((target (min fee:*max-conf-target* (max 1 (truncate conf-target))))
         (sat/vb (fee:estimate-feerate *mempool* target)))
    (obj "blocks" target
         "feerate" (if sat/vb (sat/vb->btc/kvb sat/vb) 'null)
         "feerate_sat_vb" (if sat/vb sat/vb 'null))))

;;; ----------------------------------------------------------------------------
;;; Block / transaction decoding for verbose RPC
;;; ----------------------------------------------------------------------------

(defun varint-size (n)
  "Wire byte-length of a CompactSize encoding of N."
  (cond ((< n #xfd) 1) ((<= n #xffff) 3) ((<= n #xffffffff) 5) (t 9)))

(defun vin->json (in witness coinbasep)
  (let ((o (if coinbasep
               (obj "coinbase" (w:bytes->hex (tx:txin-script in))
                    "sequence" (tx:txin-sequence in))
               (obj "txid" (w:hash->hex (tx:txin-prev-hash in))
                    "vout" (tx:txin-prev-index in)
                    "scriptSig" (obj "hex" (w:bytes->hex (tx:txin-script in)))
                    "sequence" (tx:txin-sequence in)))))
    (when witness
      (setf (gethash "txinwitness" o)
            (map 'vector #'w:bytes->hex witness)))
    o))

(defun vout->json (out n)
  (obj "value" (/ (tx:txout-value out) 1d8)
       "n" n
       "scriptPubKey" (obj "hex" (w:bytes->hex (tx:txout-script out)))))

(defun tx->json (txn &optional include-hex)
  "Decode TXN into a Core-shaped object (decoderawtransaction style)."
  (let* ((cb (tx:tx-coinbase-p txn))
         (wits (tx:tx-witnesses txn))
         (o (obj "txid" (tx:txid-hex txn)
                 "hash" (tx:wtxid-hex txn)
                 "version" (tx:tx-version txn)
                 "size" (tx:tx-total-size txn)
                 "vsize" (tx:tx-vsize txn)
                 "weight" (tx:tx-weight txn)
                 "locktime" (tx:tx-locktime txn)
                 "vin" (coerce (loop for in in (tx:tx-inputs txn) for i from 0
                                     collect (vin->json in (nth i wits) cb))
                               'vector)
                 "vout" (coerce (loop for out in (tx:tx-outputs txn) for n from 0
                                      collect (vout->json out n))
                                'vector))))
    (when include-hex
      (setf (gethash "hex" o) (w:bytes->hex (tx:serialize-tx txn :witness t))))
    o))

(defun load-block-from-store (blockhash)
  "Parse the block for BLOCKHASH (display hex) out of the archived block store.
   Returns (values block raw-bytes); errors if unavailable."
  (unless s:*block-store* (error "no block store loaded"))
  (let ((raw (bs:get-block-bytes s:*block-store* blockhash)))
    (unless raw (error "Block not found"))
    (values (blk:parse-block raw) raw)))

(defun block->json (b raw verbosity)
  ;; Prefer the canonical chain header (carries height/chainwork/nextblockhash);
  ;; the header parsed off the wire has none of those.
  (let* ((chain-h (or (c:get-header (blk:block-hash-hex b)) (blk:block-header b)))
         (txs (blk:block-txs b))
         (ntx (length txs))
         (stripped (+ 80 (varint-size ntx)
                      (reduce #'+ txs :key #'tx:tx-base-size :initial-value 0)))
         (size (length raw))
         (o (header->json chain-h)))
    (setf (gethash "size" o) size
          (gethash "strippedsize" o) stripped
          (gethash "weight" o) (+ (* 3 stripped) size)
          (gethash "nTx" o) ntx
          (gethash "tx" o)
          (if (>= verbosity 2)
              (map 'vector (lambda (txn) (tx->json txn nil)) txs)
              (map 'vector #'tx:txid-hex txs)))
    o))

(defun m-getblock (blockhash &optional (verbosity 1) &rest _)
  "getblock: verbosity 0 = raw hex; 1 = header + tx hashes; 2 = header + decoded txs.
   Served from the full archived block store."
  (declare (ignore _))
  (let ((v (cond ((numberp verbosity) (truncate verbosity))
                 ((null verbosity) 0)
                 (t 1))))
    (multiple-value-bind (b raw) (load-block-from-store blockhash)
      (if (<= v 0)
          (w:bytes->hex raw)
          (block->json b raw v)))))

(defun m-getrawtransaction (txid &optional verbose blockhash &rest _)
  "With BLOCKHASH, pull the tx out of that block in the store (no txindex needed).
   Otherwise look in the mempool; error like Core if absent.  VERBOSE (bool or int)
   selects the decoded-object form over the raw hex."
  (declare (ignore _))
  (let ((verb (if (integerp verbose) (plusp verbose) (and verbose t))))
    (multiple-value-bind (txn where)
        (if blockhash
            (let ((b (load-block-from-store blockhash)))
              (let ((found (find txid (blk:block-txs b)
                                 :key #'tx:txid-hex :test #'string=)))
                (unless found (error "No such transaction found in the provided block"))
                (values found blockhash)))
            (let ((e (mp:mempool-get *mempool* txid)))
              (unless e
                (error "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries."))
              (values (mp:entry-tx e) nil)))
      (if verb
          (let ((o (tx->json txn t)))
            (when where (setf (gethash "blockhash" o) where))
            o)
          (w:bytes->hex (tx:serialize-tx txn :witness t))))))

;;; ----------------------------------------------------------------------------
;;; Peers / network
;;; ----------------------------------------------------------------------------

(defun inbound-peers-snapshot ()
  (bt:with-lock-held (s::*inbound-lock*)
    (remove-if-not #'p:peer-alive-p (copy-list s:*inbound-peers*))))

(defun peer->json (pr id inbound)
  (obj "id" id
       "addr" (p:peer-addr pr)
       "services" (format nil "~16,'0x" (or (p:peer-services pr) 0))
       "subver" (or (p:peer-subver pr) "")
       "version" (or (p:peer-version pr) 0)
       "startingheight" (or (p:peer-height pr) 0)
       "synced_headers" (c:tip-height)
       "inbound" (if inbound t nil)
       "conntime" (or (p:peer-connected-at pr) 0)))

(defun connected-peers ()
  "All peers we can enumerate: the primary follow peer (start-follow path, if any),
   the discovered outbound pool, and the inbound serve peers.  Each element is
   (peer . inbound-p)."
  (let ((out '()))
    (when (and *peer* (p:peer-alive-p *peer*)) (push (cons *peer* nil) out))
    (dolist (pr (extra-peers)) (push (cons pr nil) out))
    (dolist (pr (inbound-peers-snapshot)) (push (cons pr t) out))
    (nreverse out)))

(defun m-getpeerinfo (&rest _)
  (declare (ignore _))
  (let ((id -1))
    (coerce (mapcar (lambda (cell) (peer->json (car cell) (incf id) (cdr cell)))
                    (connected-peers))
            'vector)))

(defun m-getconnectioncount (&rest _)
  (declare (ignore _))
  (length (connected-peers)))

(defun m-getnetworkinfo (&rest _)
  (declare (ignore _))
  (obj "version" 10100
       "subversion" p:*default-user-agent*
       "protocolversion" p:*protocol-version*
       "localservices" "0000000000000000"
       "localservicesnames" #()
       "localrelay" t
       "timeoffset" 0
       "networkactive" t
       "connections" (length (connected-peers))
       "networks" (vector (obj "name" "ipv4" "limited" nil "reachable" t
                               "proxy" "" "proxy_randomize_credentials" nil)
                          (obj "name" "ipv6" "limited" nil "reachable" t
                               "proxy" "" "proxy_randomize_credentials" nil))
       "relayfee" (sat/vb->btc/kvb fee:*min-relay-feerate*)
       "incrementalfee" (sat/vb->btc/kvb 1)
       "localaddresses" #()
       "warnings" ""))

(defun m-getchaintips (&rest _)
  (declare (ignore _))
  (let ((tip (c:tip)))
    (vector (obj "height" (c:tip-height)
                 "hash" (c:header-hash-hex tip)
                 "branchlen" 0
                 "status" "active"))))

(defun m-getnodeaddresses (&optional (count 1) &rest _)
  "Sample reachable node addresses from the discovered outbound pool.  COUNT <= 0
   returns all known.  Empty array when no peers are reachable."
  (declare (ignore _))
  (let* ((peers (extra-peers))
         (n (if (and (numberp count) (plusp count)) (truncate count) (length peers))))
    (coerce (loop for pr in peers repeat n
                  collect (obj "time" (or (p:peer-connected-at pr) (get-universal-time))
                               "services" (or (p:peer-services pr) 0)
                               "address" (p:peer-host pr)
                               "port" (p:peer-port pr)))
            'vector)))

;;; ----------------------------------------------------------------------------
;;; Mempool entry / address validation
;;; ----------------------------------------------------------------------------

(defun m-getmempoolentry (txid &rest _)
  (declare (ignore _))
  (let ((e (mp:mempool-get *mempool* txid)))
    (unless e (error "Transaction not in mempool"))
    (let ((fee-btc (/ (mp:entry-fee e) 1d8)))
      (obj "vsize" (mp:entry-vsize e)
           "weight" (tx:tx-weight (mp:entry-tx e))
           "time" (mp:entry-time e)
           "descendantcount" 1
           "ancestorcount" 1
           "fees" (obj "base" fee-btc "modified" fee-btc
                       "ancestor" fee-btc "descendant" fee-btc)
           "depends" (coerce (mp:entry-parents e) 'vector)
           "spentby" (coerce (mp:entry-children e) 'vector)
           "bip125-replaceable" (if (mp:entry-replaceable e) t nil)))))

(defun address->script (address)
  "Decode a mainnet ADDRESS to (values scriptPubKey-bytes kind-keyword).
   Signals on any invalid address (bad checksum / hrp / version)."
  (let ((lower (string-downcase address)))
    (if (and (>= (length lower) 4) (string= (subseq lower 0 3) "bc1"))
        (multiple-value-bind (witver program) (enc:segwit-decode address "bc")
          (let ((op (if (zerop witver) 0 (+ #x50 witver))))
            (values (concatenate '(vector (unsigned-byte 8))
                                 (vector op (length program)) program)
                    (cond ((and (zerop witver) (= (length program) 20)) :witness_v0_keyhash)
                          ((and (zerop witver) (= (length program) 32)) :witness_v0_scripthash)
                          ((= witver 1) :witness_v1_taproot)
                          (t :witness_unknown)))))
        (let* ((payload (enc:base58check-decode address))
               (ver (aref payload 0))
               (h (subseq payload 1)))
          (cond
            ((and (= ver #x00) (= (length h) 20))
             (values (concatenate '(vector (unsigned-byte 8))
                                  (vector #x76 #xa9 #x14) h (vector #x88 #xac))
                     :pubkeyhash))
            ((and (= ver #x05) (= (length h) 20))
             (values (concatenate '(vector (unsigned-byte 8))
                                  (vector #xa9 #x14) h (vector #x87))
                     :scripthash))
            (t (error "unknown base58 address version ~d" ver)))))))

(defun m-validateaddress (address &rest _)
  "Decode ADDRESS (mainnet bech32/bech32m or base58check) and report validity +
   the derived scriptPubKey.  isvalid is nil for anything that fails to decode."
  (declare (ignore _))
  (handler-case
      (multiple-value-bind (spk kind) (address->script address)
        (obj "isvalid" t
             "address" address
             "scriptPubKey" (w:bytes->hex spk)
             "type" (string-downcase (symbol-name kind))
             "isscript" (if (member kind '(:scripthash :witness_v0_scripthash)) t nil)
             "iswitness" (if (member kind '(:witness_v0_keyhash :witness_v0_scripthash
                                            :witness_v1_taproot :witness_unknown))
                             t nil)))
    (error () (obj "isvalid" nil))))

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
               ("estimatesmartfee" m-estimatesmartfee)
               ("estimaterawfee" m-estimaterawfee)
               ("getblock" m-getblock)
               ("getrawtransaction" m-getrawtransaction)
               ("getpeerinfo" m-getpeerinfo)
               ("getconnectioncount" m-getconnectioncount)
               ("getnetworkinfo" m-getnetworkinfo)
               ("getchaintips" m-getchaintips)
               ("getmempoolentry" m-getmempoolentry)
               ("getnodeaddresses" m-getnodeaddresses)
               ("validateaddress" m-validateaddress)
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

(defun start-follow (&optional (host "127.0.0.1"))
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

(defun %connect-new-blocks (peer utxo undo committed)
  "Fetch + connect every block from COMMITTED+1 to the header tip into UTXO, recording
   undo, storing the raw bytes, dropping confirmed mempool txs, and announcing each to
   inbound peers.  Returns the new committed height.  Synchronous per block — ample at
   the ~1-block/10-min tip-following rate, and far simpler than the async IBD pipeline."
  (let ((target (c:tip-height)))
    (loop for h from (1+ committed) to target do
      (let* ((hdr (c:header-at-height h))
             (raw (blk:get-block-raw peer (c:header-hash hdr)))
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

;;; ----------------------------------------------------------------------------
;;; Peer manager: keep a pool of diverse outbound peers alive alongside the
;;; primary (local) follow peer — bootstrapped from the primary's getaddr + DNS
;;; seeds, dialed in parallel (most gossiped addresses are dead).  Gives the node
;;; peer diversity + a failover source if the primary dies.
;;; ----------------------------------------------------------------------------

(defvar *extra-peers* '()  "Discovered outbound peers (besides the primary follow peer).")
(defvar *extra-peers-lock* (bt:make-lock "extra-peers"))
(defvar *peer-manager-thread* nil)

(defun extra-peers ()
  "Snapshot of the currently-live discovered peers (prunes dead ones)."
  (bt:with-lock-held (*extra-peers-lock*)
    (setf *extra-peers* (remove-if-not #'p:peer-alive-p *extra-peers*))
    (copy-list *extra-peers*)))

(defun live-peers ()
  "All currently-live peers: the primary follow peer, discovered outbound peers, and
   accepted inbound peers.  Used to gossip our own address (self-advertisement)."
  (remove-duplicates
   (remove-if-not #'p:peer-alive-p
                  (append (when *peer* (list *peer*))
                          (extra-peers)
                          (copy-list s:*inbound-peers*)))))   ; snapshot; a transient race is harmless

(defvar *tor-dir-path* nil
  "File to persist the Tor v3 .onion peer directory to (NIL = don't persist).")

(defvar *onion-target* 2
  "How many live .onion peers to keep in the pool (0 disables onion dialing).  Only
   attempted when cl-tor-transport is loaded (P:TOR-AVAILABLE-P), so the core node
   runs unchanged without the (optional) onion-service client.")

(defvar *onion-service-hook* nil
  "When set (by loading cl-consensus/tor), a function called by SERVE-NODE to publish
   our OWN v3 onion service and accept inbound Tor peers.  Called as
   (funcall hook :key-path P :start-height H :max-peers N) -> .onion address.")

(defun %onion-peer-p (pr) (onion:onion-valid-p (p:peer-host pr)))

(defun %dial-onion-peers (want)
  "Best-effort: dial up to WANT .onion peers from the directory that aren't already
   live in the pool.  Onion dials are slow (descriptor fetch + introduce + rendezvous)
   and flaky, so this is sequential with a generous per-dial timeout, and never signals.
   CONNECT-PEER routes .onion hosts through cl-transport's :tor backend automatically."
  (let* ((live (mapcar #'p:peer-host (remove-if-not #'%onion-peer-p (extra-peers))))
         (cands (remove-if (lambda (op) (member (car op) live :test #'string=))
                           (onion:tordir-list)))
         (got '()))
    (dolist (op cands got)
      (when (>= (length got) want) (return got))
      (let ((pr (ignore-errors
                  (p:connect-peer (car op) :port (cdr op)
                                  :start-height (c:tip-height) :timeout 120))))
        (when pr
          (format t "~&[onion] connected ~a:~d~%" (car op) (cdr op)) (force-output)
          (push pr got))))))

(defun peer-manager-loop (bootstrap &key (target 8) (poll 60))
  "Maintain TARGET live discovered peers in *EXTRA-PEERS*, collect Tor v3 .onion
   addresses gossiped by peers into the persistent tor directory, and — when the
   onion-service client is loaded (cl-tor-transport) — keep *ONION-TARGET* live
   .onion peers dialed from it through cl-transport's :tor backend.  Bootstraps from
   BOOTSTRAP's getaddr + DNS, tops up in parallel each POLL seconds, and asks each
   new peer for addresses.  Best-effort: never signals."
  (handler-case
      (let ((onion-sink (lambda (op) (onion:tordir-add (car op) (cdr op)))))
        ;; restore the onion directory from disk
        (when *tor-dir-path*
          (ignore-errors
            (let ((n (onion:load-tor-directory *tor-dir-path*)))
              (when (plusp n) (format t "~&[onion] restored ~d .onion peers~%" n) (force-output)))))
        ;; one-time addrman seeding + onion collection from the local peer
        (when (and bootstrap (p:peer-alive-p bootstrap))
          (ignore-errors
            (p:enable-discovery bootstrap
              (lambda (hp) (am:addrman-add am:*addrman* (car hp) (cdr hp)))
              onion-sink)
            (sleep 3)))
        (ignore-errors (d:seed-from-dns am:*addrman*))
        (loop
          (handler-case
              (let* ((have (length (extra-peers)))
                     (need (- target have)))
                (when (> need 0)
                  (let ((got (d:connect-n-parallel need :start-height (c:tip-height)
                                                   :min-height (max 0 (- (c:tip-height) 6)))))
                    (when got
                      ;; ask each new peer for addresses — public peers are where the
                      ;; .onion gossip comes from (the local follow peer usually has none)
                      (dolist (pr got)
                        (ignore-errors
                          (p:enable-discovery pr
                            (lambda (hp) (am:addrman-add am:*addrman* (car hp) (cdr hp)))
                            onion-sink)))
                      (bt:with-lock-held (*extra-peers-lock*)
                        (setf *extra-peers* (append *extra-peers* got)))
                      (format t "~&[peers] +~d discovered (pool now ~d/~d); onion dir ~d~%"
                              (length got) (length (extra-peers)) target (onion:tordir-count))
                      (force-output))))
                ;; dial .onion peers from the directory (needs cl-tor-transport's :tor backend)
                (when (and (plusp *onion-target*) (p:tor-available-p))
                  (let ((oneed (- *onion-target* (count-if #'%onion-peer-p (extra-peers)))))
                    (when (> oneed 0)
                      (let ((og (%dial-onion-peers oneed)))
                        (when og
                          (bt:with-lock-held (*extra-peers-lock*)
                            (setf *extra-peers* (append *extra-peers* og)))
                          (format t "~&[onion] +~d .onion peer(s) in pool (dir ~d)~%"
                                  (length og) (onion:tordir-count)) (force-output)))))))
            (serious-condition (e)
              (format t "~&[peers] manager tick error: ~a~%" e) (force-output)))
          ;; persist the onion directory each tick
          (when *tor-dir-path*
            (ignore-errors (onion:save-tor-directory *tor-dir-path*)))
          (sleep poll)))
    (serious-condition () nil)))

;;; ----------------------------------------------------------------------------
;;; Archival backfill: download every historical block into the block store so the
;;; node can SERVE any block, not just the rolling recent window.  Idempotent and
;;; resumable — STORE-BLOCK skips blocks already present and gaps are retried over
;;; multiple passes, so a re-run (or a restart) only fetches what's missing.  Uses
;;; its OWN dedicated peers: GET-BLOCK-RAW installs one "block" handler per peer, so
;;; archive fetches must not share the follow loop's / manager's connections.
;;; ----------------------------------------------------------------------------

(defvar *archive-thread* nil)
(defvar *archive-stop* nil)
(defvar *archive-status* (list :running nil :stored 0 :bytes 0 :height 0 :missing 0))

(defun archive-status () (copy-list *archive-status*))
(defun stop-archive () (setf *archive-stop* t) :stopping)

(defun %missing-heights (from to store)
  "Ascending list of heights in [FROM,TO] whose block isn't in STORE yet."
  (let ((out '()))
    (loop for h from to downto from
          for hdr = (c:header-at-height h)
          when (and hdr (not (bs:block-store-has-p store (c:header-hash-hex hdr))))
            do (push h out))
    out))

(defun %archive-fetch (peer h store verify)
  "Fetch block at height H from PEER and store it; return bytes stored, or NIL if
   already present.  GET-BLOCK-RAW verifies the header hash; VERIFY adds a merkle
   check that the tx body actually matches that trusted header."
  (let* ((hdr (c:header-at-height h))
         (hash (and hdr (c:header-hash hdr))))
    (when (and hash (not (bs:block-store-has-p store (c:header-hash-hex hdr))))
      (let ((raw (blk:get-block-raw peer hash :timeout 40 :witness t)))
        (when (and verify (not (blk:verify-merkle (blk:parse-block raw))))
          (error "archive: merkle mismatch at height ~d" h))
        (bs:store-block store raw)
        (length raw)))))

(defun archive-blocks (&key (from 1) (to (c:tip-height)) (verify t) (peers 16)
                            (archive-host (or (sb-ext:posix-getenv "SERVE_PEER") "epyc-docker.lan"))
                            (max-passes 100) (log-every 5000))
  "Backfill raw blocks [FROM,TO] into the block store, fetching in parallel over PEERS
   dedicated connections to ARCHIVE-HOST — an archival node that can serve any block.
   Defaults to the local Core (SERVE_PEER), so history streams off our own full node
   at LAN speed instead of hammering public volunteers.  Resumable/idempotent: only
   missing blocks are fetched, gaps are retried across passes, and a height skipped on
   a peer error is picked up next pass.  Honors (STOP-ARCHIVE)."
  (let ((store s:*block-store*) (t0 (get-internal-real-time))
        (stored 0) (bytes 0))
    (unless store (error "archive: no block store open"))
    (setf *archive-stop* nil
          *archive-status* (list :running t :stored 0 :bytes 0 :height from :missing 0))
    (flet ((dial () (ignore-errors
                      (p:connect-peer archive-host :start-height (c:tip-height) :timeout 15))))
      (unwind-protect
          (loop for pass from 1 to max-passes
                for missing = (%missing-heights from to store)
                while (and missing (not *archive-stop*)) do
            (setf (getf *archive-status* :missing) (length missing))
            (format t "~&[archive] pass ~d: ~d blocks to fetch in ~d..~d (from ~a)~%"
                    pass (length missing) from to archive-host) (force-output)
            (let ((apeers (remove nil (loop repeat peers collect (dial)))))
              (unless apeers
                (format t "~&[archive] cannot reach ~a; stopping (resume when it's back)~%"
                        archive-host) (force-output)
                (return))
              (unwind-protect
                  (let* ((vec (coerce missing 'vector)) (n (length vec))
                         (idx 0) (lock (bt:make-lock)))
                    (labels ((next-i ()
                               (bt:with-lock-held (lock)
                                 (if (or *archive-stop* (>= idx n)) nil (prog1 idx (incf idx))))))
                      (let ((threads
                              (mapcar
                               (lambda (peer0)
                                 (bt:make-thread
                                  (lambda ()
                                    (let ((peer peer0))
                                      (loop for i = (next-i) while i
                                            for h = (aref vec i) do
                                        (handler-case
                                            (let ((b (%archive-fetch peer h store verify)))
                                              (when b
                                                (bt:with-lock-held (lock)
                                                  (incf stored) (incf bytes b)
                                                  (setf (getf *archive-status* :stored) stored
                                                        (getf *archive-status* :bytes) bytes
                                                        (getf *archive-status* :height) h)
                                                  (when (zerop (mod stored log-every))
                                                    (let ((s (max 1d0 (/ (- (get-internal-real-time) t0)
                                                                         internal-time-units-per-second))))
                                                      (format t "~&[archive] ~d blocks, ~,2f GB, ~,1f blk/s, last h~d~%"
                                                              stored (/ bytes 1d9) (/ stored s) h)
                                                      (force-output))))))
                                          (serious-condition ()
                                            ;; peer stalled/died: redial; skipped height
                                            ;; is refetched next pass.
                                            (unless (p:peer-alive-p peer)
                                              (setf peer (or (dial) peer))))))))
                                  :name "btc-archive"))
                               apeers)))
                        (dolist (th threads) (ignore-errors (bt:join-thread th))))))
                (dolist (pr apeers) (ignore-errors (p:disconnect pr)))))))
      (setf (getf *archive-status* :running) nil))
    (format t "~&[archive] finished this run: ~d blocks (~,2f GB); ~d still missing~%"
            stored (/ bytes 1d9) (length (%missing-heights from to store))) (force-output)
    stored))

(defun start-archive (&rest args)
  "Start ARCHIVE-BLOCKS in a background thread (ARGS pass through).  Returns
   :ALREADY-RUNNING if an archive is already in progress."
  (when (and *archive-thread* (bt:thread-alive-p *archive-thread*))
    (return-from start-archive :already-running))
  (setf *archive-thread*
        (bt:make-thread (lambda () (ignore-errors (apply #'archive-blocks args)))
                        :name "btc-archive-driver"))
  :started)

(defun %reconnect-peer (old peer-host)
  "Drop OLD (if any) and dial a fresh follow connection to PEER-HOST at the current
   tip.  Returns the new peer, or NIL if the redial failed (the caller keeps the old
   handle and retries next tick)."
  (when old (ignore-errors (p:disconnect old)))
  (handler-case
      (let ((np (p:connect-peer peer-host :start-height (c:tip-height))))
        (format t "~&[node] reconnected peer ~a (height ~a)~%"
                (p:peer-addr np) (p:peer-height np)) (force-output)
        np)
    (serious-condition (e)
      (format t "~&[node] peer redial to ~a failed: ~a~%" peer-host e) (force-output)
      nil)))

(defun %ensure-peers (peers peer-host)
  "Replace any peer whose read loop has died with a fresh dial to PEER-HOST.  A failed
   redial keeps the old (dead) entry so the next tick retries."
  (if peer-host
      (loop for p in peers
            collect (if (p:peer-alive-p p) p (or (%reconnect-peer p peer-host) p)))
      peers))

(defun validating-follow-loop (peers utxo undo start-height &key (poll 30) peer-host
                                                                 (stall-ticks 2))
  "Long-lived: keep the UTXO at the header tip (reorg-aware), serving + relaying as we
   go.  This thread is the SINGLE writer of the UTXO store.  Self-heals a wedged
   upstream: header sync is time-bounded, dead connections are redialled, and a peer
   that goes silent (TCP-alive but not advancing the tip) is dropped after STALL-TICKS
   idle ticks.  If the primary follow peer(s) all die it FAILS OVER to a discovered
   peer from the manager pool — so the node can't freeze behind one bad connection."
  (let ((committed start-height)
        (peers (copy-list peers))
        (stalls 0))
    (loop
      (handler-case
          (progn
            ;; drop-and-redial any primary peer whose read loop has already died
            (setf peers (%ensure-peers peers peer-host))
            ;; pick the follow peer for this tick: a live primary if any, else a
            ;; discovered pool peer (failover when the local upstream is down).
            (let ((fp (or (find-if #'p:peer-alive-p peers) (first (extra-peers)))))
              (unless fp                       ; nothing live anywhere — force a redial
                (setf peers (%ensure-peers peers peer-host)
                      fp (find-if #'p:peer-alive-p peers)))
              (when fp
                ;; headers-first, but time-bounded so a silent peer can't hang the loop
                (multiple-value-bind (added timed-out)
                    (handler-case (c:sync-headers fp :max-batches 50)
                      (serious-condition (e)
                        (format t "~&[node] header sync error: ~a~%" e) (force-output)
                        (values 0 t)))
                  (declare (ignore added))
                  ;; a peer that keeps timing out is wedged (TCP-alive, not replying):
                  ;; drop it after STALL-TICKS idle ticks so the next tick fails over.
                  (if timed-out
                      (when (>= (incf stalls) stall-ticks)
                        (format t "~&[node] follow peer ~a stalled at tip ~d — dropping~%"
                                (p:peer-addr fp) (c:tip-height)) (force-output)
                        (ignore-errors (p:disconnect fp))
                        (setf peers (%ensure-peers peers peer-host) stalls 0))
                      (setf stalls 0)))
                (setf u:*utxo-flush-method* :incremental)
                ;; reorg: roll the UTXO onto the heaviest branch before extending it
                (multiple-value-bind (h2 reorged depth)
                    (r:activate-best-chain utxo committed undo
                                           (lambda (hdr) (blk:get-block fp (c:header-hash hdr))))
                  (when reorged
                    (format t "~&[node] *** REORG depth ~d: ~d -> ~d ***~%" depth committed h2) (force-output)
                    (u:flush-utxo utxo h2) (c:save-headers) (r:undo-commit undo)
                    (setf committed h2)))
                ;; extend forward
                (when (> (c:tip-height) committed)
                  (setf committed (%connect-new-blocks fp utxo undo committed))
                  (u:flush-utxo utxo committed) (c:save-headers) (r:undo-commit undo)
                  (when (> committed 288) (r:undo-prune undo (- committed 288)))))))
        (r:deep-reorg-halt (e)
          (format t "~&[node] HALT (deep reorg): ~a~%" e) (force-output) (return))
        (r:reorg-error (e)
          (format t "~&[node] HALT (reorg-error): ~a~%" e) (force-output) (return))
        (serious-condition (e)
          (format t "~&[node] follow error: ~a~%" e) (force-output)))
      ;; persist the mempool each tick so a crash/respawn keeps the unconfirmed set
      (when *mempool-path*
        (handler-case (mp:save-mempool *mempool* *mempool-path*) (serious-condition () nil)))
      (sleep poll))))

(defun serve-node (&key (store (namestring (merge-pathnames ".cl-consensus/live.pt"
                                                            (user-homedir-pathname))))
                        (block-store (namestring (merge-pathnames ".cl-consensus/blocks.dat"
                                                                  (user-homedir-pathname))))
                        (peer-host "127.0.0.1") (conns 2) (cache-gb 24)
                        (onion-service nil)
                        (listen-port (w:net-port w:*network*)) (rpc-port *rpc-port*)
                        (max-peers 64) (poll 30) (discover 8)
                        (archive nil) (archive-peers 16)
                        (mempool-path (namestring (merge-pathnames ".cl-consensus/mempool.dat"
                                                                   (user-homedir-pathname)))))
  "THE consolidated node: own the pagetree UTXO (single writer), validate new blocks to
   the tip (reorg-aware), and SERVE headers/blocks + RELAY txs to inbound peers with a
   tip-current UTXO + mempool, plus JSON-RPC + the control socket.  Replaces the
   keep-current poll AND the header-only serve-daemon.  Blocks forever."
  (setf *rpc-port* rpc-port *start-time* (get-universal-time))
  (ensure-directories-exist store)              ; create the data dir for a fresh node
  (c:init-chain) (c:load-headers)
  (let* ((peers (loop repeat conns collect (p:connect-peer peer-host :start-height (c:tip-height))))
         (undo (r:open-pt-undo-store (concatenate 'string store ".undo"))))
    (handler-case (c:sync-headers (first peers) :max-batches 50) (serious-condition () nil))
    (multiple-value-bind (utxo height)
        (u:open-utxo-backend store :backend :pagetree :cache-bytes (* cache-gb 1024 1024 1024))
      (setf *utxo* utxo
            s:*block-store* (bs:open-block-store block-store)
            s:*utxo* utxo s:*mempool* *mempool* s:*tx-relay-enabled* t
            *tor-dir-path* (merge-pathnames "onion-peers.dat" (pathname block-store)))
      (format t "~&[node] UTXO resume height ~d (~d coins); block store ~d blocks~%"
              height (u:utxo-count utxo) (bs:block-store-count s:*block-store*)) (force-output)
      ;; restore the mempool (re-validated against the just-loaded UTXO)
      (setf *mempool-path* mempool-path)
      (when mempool-path
        (handler-case
            (let ((n (mp:load-mempool *mempool* utxo mempool-path
                                      :height (1+ (c:tip-height)) :mtp (c:median-time-past (c:tip)))))
              (format t "~&[node] mempool restored: ~d tx~%" n) (force-output))
          (serious-condition (e) (format t "~&[node] mempool restore skipped: ~a~%" e) (force-output))))
      (register-methods)
      (setf *acceptor* (make-instance 'ht:easy-acceptor :port rpc-port :address "0.0.0.0"))
      (setf (ht:acceptor-message-log-destination *acceptor*) nil
            (ht:acceptor-access-log-destination *acceptor*) nil)
      (ht:define-easy-handler (rpc :uri "/") () (rpc-handler))
      (ht:start *acceptor*)
      (unless *control-thread*
        (setf *control-thread* (bt:make-thread #'control-loop :name "btc-node control")))
      (s:start-listener :port listen-port :max-peers max-peers)
      ;; optionally run our OWN v3 onion service (inbound over Tor).  Needs the provider
      ;; (cl-consensus/tor sets *onion-service-hook*; cl-tor-transport registers :tor).
      (when (and onion-service *onion-service-hook* (p:tor-available-p))
        (ignore-errors
          (let ((addr (funcall *onion-service-hook*
                               :key-path (namestring (merge-pathnames "onion-service-key.dat"
                                                                      (pathname block-store)))
                               :port listen-port
                               :start-height (c:tip-height) :max-peers max-peers)))
            (format t "~&[node] onion service enabled: ~a~%" addr) (force-output))))
      ;; keep a pool of diverse outbound peers alive alongside the primary follow
      ;; peer (peer diversity + failover); bootstraps from the primary's getaddr.
      (when (and (plusp discover) (first peers))
        (setf *peer-manager-thread*
              (bt:make-thread (lambda () (peer-manager-loop (first peers) :target discover))
                              :name "btc-peer-manager")))
      ;; archival backfill of all historical blocks (resumable — skips what's stored)
      (when archive
        (format t "~&[node] starting archival backfill (~d peers, verify)~%" archive-peers) (force-output)
        (start-archive :from 1 :to (c:tip-height) :peers archive-peers :verify t))
      (format t "~&[node] serve-node up: RPC :~d control :~d P2P :~d  follow ~a  discover ~d  archive ~a  tip ~d~%"
              rpc-port *control-port* listen-port peer-host discover archive (c:tip-height)) (force-output)
      (unwind-protect (validating-follow-loop peers utxo undo height :poll poll
                                                                     :peer-host peer-host)
        (when *mempool-path* (ignore-errors (mp:save-mempool *mempool* *mempool-path*)))
        (r:close-pt-undo-store undo)))))

;;; ----------------------------------------------------------------------------
;;; Control socket (hot reload), start/stop
;;; ----------------------------------------------------------------------------

(defun %cl-consensus-source-files ()
  "The cl-consensus system's OWN .lisp source components, in load order."
  (labels ((walk (c)
             (cond ((typep c 'asdf:cl-source-file) (list c))
                   ((typep c 'asdf:module) (mapcan #'walk (asdf:component-children c)))
                   (t nil))))
    (walk (asdf:find-system "cl-consensus"))))

(defun %fasl-for (src)
  "Output-translated fasl path (in the ASDF cache) for source file SRC."
  (asdf:apply-output-translations (compile-file-pathname src)))

(defun reload! ()
  "Hot-reload ONLY cl-consensus's own changed source files (recompile source-newer-
   than-fasl, then load) and re-register RPC methods.  Deliberately does NOT go through
   ASDF:LOAD-SYSTEM: that reloads the whole dependency graph, and some deps (notably
   secp256k1-fast) define SBCL VOPs that CANNOT be reloaded into a live image — doing
   so aborts mid-load and corrupts the crypto.  Scoping to our own files makes this
   safe for fast in-process iteration.  `echo '(reload!)' | nc 127.0.0.1 4008`."
  ;; pick up .asd component changes (e.g. a new file) without touching loaded code
  (ignore-errors
    (asdf:load-asd (asdf:system-source-file (asdf:find-system "cl-consensus"))))
  (let ((reloaded '()))
    (dolist (c (%cl-consensus-source-files))
      (let* ((src (asdf:component-pathname c)) (fasl (%fasl-for src)))
        (when (or (not (probe-file fasl))
                  (> (file-write-date src) (file-write-date fasl)))
          (handler-bind ((warning #'muffle-warning))
            (ensure-directories-exist fasl)
            (compile-file src :output-file fasl)
            (load fasl))
          (push (pathname-name src) reloaded))))
    (register-methods)
    (list :reloaded (nreverse reloaded))))

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

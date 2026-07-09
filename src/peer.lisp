;;;; shared/bitcoind/peer.lisp
;;;;
;;;; Phase 1 — a single P2P peer connection: TCP, the version/verack handshake,
;;;; ping/pong keepalive, and a message read loop that dispatches to handlers.
;;;;
;;;; A PEER owns one socket and one reader thread.  Higher layers register
;;;; handlers on message commands ("headers", "block", "inv", ...) and send
;;;; requests via SEND.  The handshake is synchronous; everything after is the
;;;; async read loop.


(defpackage #:cl-consensus.peer
  (:use #:cl)
  (:nicknames #:btc-peer)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:bt #:bordeaux-threads) (#:tr #:cl-transport)
                    (#:onion #:cl-consensus.onion))
  (:export
   #:peer #:peer-addr #:peer-version #:peer-subver #:peer-height
   #:peer-services #:peer-alive-p #:peer-connected-at #:peer-prefers-headers
   #:connect-peer #:start-read-loop #:run-read-loop #:accept-peer #:disconnect #:send #:on #:peer-log #:peer-host #:peer-port
   #:send-getaddr #:parse-addr-payload #:parse-addrv2-payload #:enable-discovery
   #:tor-available-p #:%onion-host-p
   #:*default-user-agent* #:*protocol-version* #:*peer-transport* #:peer-closer))

(in-package #:cl-consensus.peer)

(defparameter *protocol-version* 70016)
(defparameter *default-user-agent* "/cl-consensus:0.1/")
(defparameter +max-message-length+ (* 32 1024 1024)
  "Reject P2P messages larger than this before allocating the payload (DoS guard).")

(defparameter *peer-transport* :direct
  "Transport for OUTBOUND peer connections (CONNECT-PEER): :direct | :socks5 | :tor.
   :direct is plain TCP (unchanged behaviour); :tor routes through cl-transport's
   native Tor circuits (hides our IP); :socks5 through an external proxy.  Inbound
   (ACCEPT-PEER) is always direct.")

(defstruct peer
  host port socket stream
  closer                                 ; thunk that tears the connection down (transport-agnostic)
  (lock (bt:make-lock "peer-send"))
  thread
  (handlers (make-hash-table :test 'equal))   ; command string -> function (peer payload-bytes)
  (alive t)
  ;; peer-reported handshake info
  version services subver height
  (connected-at 0)
  (prefers-headers nil)   ; peer sent BIP130 "sendheaders" -> announce blocks via headers
  (verbose nil))

(defun peer-addr (p) (format nil "~a:~d" (peer-host p) (peer-port p)))
(defun peer-alive-p (p) (peer-alive p))

(defun peer-log (p fmt &rest args)
  (when (peer-verbose p)
    (format t "~&[peer ~a] ~a~%" (peer-addr p) (apply #'format nil fmt args))
    (force-output)))

;;; ----------------------------------------------------------------------------
;;; Low-level socket I/O
;;; ----------------------------------------------------------------------------

(defun read-fully (stream n)
  "Read exactly N bytes or signal end-of-file."
  (let ((buf (make-array n :element-type '(unsigned-byte 8)))
        (got 0))
    (loop while (< got n) do
      (let ((r (read-sequence buf stream :start got :end n)))
        (when (= r got) (error 'end-of-file :stream stream))
        (setf got r)))
    buf))

(defun read-message (p)
  "Read one framed message off the peer socket.  Returns (values command-string
   payload-bytes), or NIL on clean EOF.  Verifies the magic and checksum."
  (let ((stream (peer-stream p)))
    (let* ((hdr (handler-case (read-fully stream 24)
                  (end-of-file () (return-from read-message nil))))
           (r (w:make-reader hdr))
           (magic (w:r-u32 r)))
      (unless (= magic (w:net-magic w:*network*))
        (error "bad magic ~x from ~a" magic (peer-addr p)))
      (let* ((cmd-bytes (w:r-bytes r 12))
             (command (string-right-trim '(#\Nul)
                                         (map 'string #'code-char cmd-bytes)))
             (len (w:r-u32 r))
             (checksum (w:r-bytes r 4)))
        ;; Cap the payload length before allocating: an attacker-controlled u32 (up to
        ;; 4 GB) would otherwise make-array a giant buffer (DoS).  Largest legit message
        ;; is a block (~4 MB); 32 MB leaves generous headroom.
        (when (> len +max-message-length+)
          (error "oversized ~a message: ~d bytes from ~a" command len (peer-addr p)))
        (let ((payload (if (plusp len) (read-fully stream len)
                           (make-array 0 :element-type '(unsigned-byte 8)))))
          (unless (equalp checksum (w:checksum payload))
            (error "bad checksum on ~a message from ~a" command (peer-addr p)))
          (values command payload))))))

(defun send (p command payload)
  "Frame and send a message.  PAYLOAD is a byte vector (often a writer's bytes)."
  (let ((bytes (w:encode-message command payload)))
    (bt:with-lock-held ((peer-lock p))
      (write-sequence bytes (peer-stream p))
      (force-output (peer-stream p)))
    (peer-log p "-> ~a (~d bytes)" command (length payload))
    p))

;;; ----------------------------------------------------------------------------
;;; version message
;;; ----------------------------------------------------------------------------

(defun build-version-payload (&key (services (logior w:+services-witness+))
                                   (start-height 0)
                                   (user-agent *default-user-agent*)
                                   (peer-ip #(0 0 0 0)) (peer-port 0))
  (let ((wr (w:make-writer)))
    (w:w-i32 wr *protocol-version*)
    (w:w-u64 wr services)
    (w:w-i64 wr (- (get-universal-time) 2208988800)) ; CL epoch 1900 -> unix epoch
    ;; addr_recv (the peer), no time field in version
    (w:w-netaddr wr services peer-ip peer-port)
    ;; addr_from (us) — zeros are fine
    (w:w-netaddr wr services #(0 0 0 0) 0)
    (w:w-u64 wr (logand (get-internal-real-time) #xffffffffffffffff)) ; nonce
    (w:w-varstr wr user-agent)
    (w:w-i32 wr start-height)
    (w:w-bool wr nil)              ; relay=false: don't flood us with mempool txs yet
    (w:writer-bytes wr)))

(defun parse-version-payload (payload)
  "Pull the fields we care about out of a peer's version message."
  (let ((r (w:make-reader payload)))
    (let ((version (w:r-i32 r))
          (services (w:r-u64 r)))
      (w:r-i64 r)                  ; timestamp
      ;; addr_recv: services(8) ip(16) port(2)
      (w:r-bytes r 26)
      ;; addr_from
      (w:r-bytes r 26)
      (w:r-u64 r)                  ; nonce
      (let ((subver (w:r-varstr r))
            (height (w:r-i32 r)))
        (values version services subver height)))))

;;; ----------------------------------------------------------------------------
;;; handler registry + read loop
;;; ----------------------------------------------------------------------------

(defun on (p command fn)
  "Register FN (peer payload-bytes) as the handler for COMMAND."
  (setf (gethash command (peer-handlers p)) fn)
  p)

(defun dispatch (p command payload)
  (let ((fn (gethash command (peer-handlers p))))
    (when fn
      (handler-case (funcall fn p payload)
        (serious-condition (c)
          (format t "~&[peer ~a] handler ~a error: ~a~%" (peer-addr p) command c)
          (force-output))))))

(defun handle-builtin (p command payload)
  "Protocol housekeeping common to every node: pings and sendheaders/feefilter
   noise.  Returns T if fully handled here."
  (cond
    ((string= command "ping")
     (send p "pong" payload) t)          ; echo the nonce
    ((string= command "sendheaders")
     (setf (peer-prefers-headers p) t) t) ; BIP130: announce new blocks via headers
    ((member command '("alert" "feefilter" "sendcmpct" "wtxidrelay")
             :test #'string=)
     t)                                   ; ignore for now
    ;; NOTE: "addr"/"addrv2"/"getheaders"/"getdata" are intentionally NOT swallowed
    ;; here — they dispatch to a registered handler (peer discovery; serving headers/
    ;; blocks).  With no handler installed DISPATCH simply no-ops, so this stays safe
    ;; by default (a pure leech ignores them; the serving daemon installs handlers).
    (t nil)))

(defun read-loop (p)
  (handler-case
      (loop while (peer-alive p) do
        ;; An idle read past the socket timeout must NOT kill the loop: during
        ;; IBD the consumer can pause requesting (backpressure) for a while, so a
        ;; P2P read loop blocks indefinitely for the next message and just retries
        ;; on a timeout.  (The stream's input timeout is also cleared at connect.)
        (block one
          (handler-case
              (multiple-value-bind (command payload) (read-message p)
                (unless command (return))    ; clean EOF
                (peer-log p "<- ~a (~d bytes)" command (length payload))
                (unless (handle-builtin p command payload)
                  (dispatch p command payload)))
            (#+sbcl sb-sys:io-timeout #-sbcl error () (return-from one))
            #+sbcl (sb-sys:deadline-timeout () (return-from one)))))
    (serious-condition (c)
      (when (peer-alive p)
        (format t "~&[peer ~a] read loop ended: ~a~%" (peer-addr p) c)
        (force-output))))
  (setf (peer-alive p) nil))

;;; ----------------------------------------------------------------------------
;;; connect + handshake
;;; ----------------------------------------------------------------------------

(defun start-read-loop (p)
  "Clear the connect-time input timeout and spawn P's async read loop; return P.
   Call this from a LONG-LIVED thread: in SBCL a read loop spawned inside an
   ephemeral worker thread dies when that worker exits, so a parallel dialer must
   dial with :DEFER-LOOP and hand the peers here from its (long-lived) collector."
  ;; usocket set an INPUT timeout on the stream (from the connect :timeout); clear it
  ;; so the steady-state read loop blocks indefinitely for the next message instead of
  ;; dying on an idle gap (e.g. while IBD is backpressured).
  #+sbcl (ignore-errors (setf (sb-impl::fd-stream-timeout (peer-stream p)) nil))
  (setf (peer-thread p)
        (bt:make-thread (lambda () (read-loop p))
                        :name (format nil "btc-peer ~a" (peer-addr p))))
  p)

(defun run-read-loop (p)
  "Clear the input timeout and run P's read loop IN THE CURRENT THREAD (blocks until
   the peer closes).  Parallel dialers use this so the dialing thread BECOMES the
   peer's long-lived owner: a socket opened in a thread that then exits is torn down
   with it, so the connecting thread must live as long as the connection."
  #+sbcl (ignore-errors (setf (sb-impl::fd-stream-timeout (peer-stream p)) nil))
  (setf (peer-thread p) (bt:current-thread))
  (read-loop p))

(defun %prefix-p (prefix s)
  (and (stringp s) (>= (length s) (length prefix))
       (string= prefix s :end2 (length prefix))))

(defun %suffix-p (suffix s)
  (and (stringp s) (>= (length s) (length suffix))
       (string= suffix s :start2 (- (length s) (length suffix)))))

(defun %private-host-p (host)
  "True for loopback / RFC1918 / .lan / .local hosts — not reachable via a Tor exit,
   so they always dial :DIRECT even when *PEER-TRANSPORT* is :TOR/:SOCKS5."
  (and (stringp host)
       (or (string= host "localhost")
           (%suffix-p ".lan" host) (%suffix-p ".local" host)
           (%prefix-p "10." host) (%prefix-p "127." host) (%prefix-p "192.168." host)
           (loop for b from 16 to 31 thereis (%prefix-p (format nil "172.~d." b) host)))))

(defun %onion-host-p (host)
  "True for a v3 .onion address — only reachable end-to-end via the onion-service
   client, so these ALWAYS dial :TOR regardless of *PEER-TRANSPORT*."
  (onion:onion-valid-p host))

(defun tor-available-p ()
  "T if a :tor backend is registered with cl-transport — i.e. cl-tor-transport is
   loaded.  Callers gate .onion dialing on this so the core node stays usable
   without the (optional) onion-service client."
  (tr:transport-available-p :tor))

(defun connect-peer (host &key (port (w:net-port w:*network*))
                               (start-height 0) (verbose nil)
                               (timeout 15) (defer-loop nil)
                               (transport *peer-transport*))
  "Open a connection to HOST:PORT over TRANSPORT (default *PEER-TRANSPORT*) and
   complete the version/verack handshake.  Returns a live PEER with its read loop
   running, or signals on failure.  With :DEFER-LOOP the handshake completes but the
   async read loop is NOT started — the caller must call START-READ-LOOP from a
   long-lived thread (see its docstring)."
  (cond ((%onion-host-p host) (setf transport :tor))        ; .onion requires the onion client
        ((and (not (eq transport :direct)) (%private-host-p host))
         (setf transport :direct)))       ; LAN/loopback peers can't route through Tor
  (multiple-value-bind (stream closer)
      (tr:dial host port :transport transport :timeout timeout)
    (let ((p (make-peer :host host :port port :stream stream :closer closer
                        :verbose verbose
                        :connected-at (get-universal-time)))
          (ok nil))
      (unwind-protect
           (progn
             ;; --- handshake (synchronous, TIME-BOUNDED) ---
             ;; A :tor gray-stream read has no socket input-timeout (unlike a usocket
             ;; stream), so bound the whole handshake here — otherwise a peer that
             ;; opens the stream but never sends `version` parks this call forever,
             ;; which on a :tor failover dial could wedge the UTXO-writer follow loop.
             (sb-ext:with-timeout timeout
               (send p "version" (build-version-payload :start-height start-height))
               (let ((got-version nil) (got-verack nil))
                 (loop until (and got-version got-verack) do
                   (multiple-value-bind (command payload) (read-message p)
                     (unless command (error "peer ~a closed during handshake" (peer-addr p)))
                     (peer-log p "<- ~a (~d bytes)" command (length payload))
                     (cond
                       ((string= command "version")
                        (multiple-value-bind (v s sv h) (parse-version-payload payload)
                          (setf (peer-version p) v (peer-services p) s
                                (peer-subver p) sv (peer-height p) h)
                          (setf got-version t)
                          ;; BIP155: signal we understand addrv2 (must precede verack) so
                          ;; the peer gossips Tor v3 / other addrs; then ack.
                          (send p "sendaddrv2" #())
                          (send p "verack" #())))
                       ((string= command "verack") (setf got-verack t))
                       ((string= command "wtxidrelay") nil)
                       ((string= command "sendaddrv2") nil)
                       (t nil))))))
             (setf ok t))
        ;; on handshake failure/timeout, tear the connection down (don't leak a Tor
        ;; circuit or socket); the condition then propagates to the caller.
        (unless ok (ignore-errors (funcall closer))))
      ;; --- go async (unless the caller defers the loop to its own thread) ---
      (if defer-loop p (start-read-loop p)))))

(defun %inbound-addr (socket)
  "Best-effort dotted IP of an accepted SOCKET's remote end (for logging)."
  (handler-case
      (let ((a (usocket:get-peer-address socket)))
        (if (vectorp a) (format nil "~{~a~^.~}" (coerce a 'list)) (format nil "~a" a)))
    (serious-condition () "inbound")))

(defun accept-peer (socket &key (services (logior w:+services-network+ w:+services-witness+))
                                (start-height 0) (verbose nil))
  "Wrap an ACCEPTED inbound TCP SOCKET as a live peer: complete the version/verack
   handshake in INBOUND order (read THEIR version first, then send ours advertising
   SERVICES + verack), clear the read timeout, and spawn the read loop.  Returns the
   live peer, or signals on a bad/!aborted handshake (caller closes the socket)."
  (let* ((stream (usocket:socket-stream socket))
         (p (make-peer :host (%inbound-addr socket)
                       :port (handler-case (usocket:get-peer-port socket) (serious-condition () 0))
                       :socket socket :stream stream :verbose verbose
                       :connected-at (get-universal-time))))
    (let ((got-version nil) (got-verack nil))
      (loop until (and got-version got-verack) do
        (multiple-value-bind (command payload) (read-message p)
          (unless command (error "inbound peer ~a closed during handshake" (peer-addr p)))
          (peer-log p "<- ~a (~d bytes)" command (length payload))
          (cond
            ((string= command "version")
             (multiple-value-bind (v s sv h) (parse-version-payload payload)
               (setf (peer-version p) v (peer-services p) s
                     (peer-subver p) sv (peer-height p) h))
             (setf got-version t)
             ;; respond with OUR version (advertising SERVICES) then verack.
             (send p "version" (build-version-payload :services services :start-height start-height))
             (send p "verack" #()))
            ((string= command "verack") (setf got-verack t))
            (t nil)))))                  ; ignore wtxidrelay/sendaddrv2/etc. during handshake
    #+sbcl (ignore-errors (setf (sb-impl::fd-stream-timeout (peer-stream p)) nil))
    (setf (peer-thread p)
          (bt:make-thread (lambda () (read-loop p))
                          :name (format nil "btc-inbound ~a" (peer-addr p))))
    p))

(defun disconnect (p)
  (setf (peer-alive p) nil)
  ;; tear down via the transport closer (outbound: direct/socks5/tor), else the raw
  ;; socket (inbound peers from ACCEPT-PEER have no closer).
  (if (peer-closer p)
      (ignore-errors (funcall (peer-closer p)))
      (ignore-errors (usocket:socket-close (peer-socket p))))
  ;; The read-loop may be parked in a blocking read with the idle timeout cleared
  ;; (see CONNECT-PEER); closing the socket from another thread does not reliably
  ;; unblock that read, so join with a bounded timeout and move on rather than
  ;; hang forever.  A leftover thread dies when its read finally errors / at exit.
  (when (and (peer-thread p) (bt:thread-alive-p (peer-thread p))
             (not (eq (peer-thread p) (bt:current-thread))))
    (ignore-errors (sb-thread:join-thread (peer-thread p) :timeout 3 :default nil)))
  p)

;;; ----------------------------------------------------------------------------
;;; Peer discovery: ask a peer for its known addresses (getaddr -> addr/addrv2).
;;; ----------------------------------------------------------------------------

(defun send-getaddr (p) (send p "getaddr" #()))

(defun parse-addr-payload (payload)
  "addr message: varint count + entries[time u32, services u64, ip16, port u16BE].
   Returns a list of (host . port) for the IPv4 entries (others skipped)."
  (let ((r (w:make-reader payload)) (out '()))
    (let ((n (w:r-varint r)))
      (dotimes (i n)
        (let ((a (w:r-netaddr r :with-time t))) (when a (push a out)))))
    out))

(defun parse-addrv2-payload (payload)
  "addrv2 (BIP155): varint count + entries[time u32, services varint, netID u8,
   addrlen varint, addr, port u16BE].  Returns (host . port) for IPv4 (netID 1)."
  (let ((r (w:make-reader payload)) (out '()))
    (let ((n (w:r-varint r)))
      (dotimes (i n)
        (w:r-u32 r)                      ; time
        (w:r-varint r)                   ; services
        (let* ((netid (w:r-u8 r)) (len (w:r-varint r))
               (addr (w:r-bytes r len)) (port (w:r-port-be r)))
          (when (and (= netid 1) (= len 4))   ; IPV4
            (push (cons (format nil "~d.~d.~d.~d"
                                (aref addr 0) (aref addr 1) (aref addr 2) (aref addr 3))
                        port)
                  out)))))
    out))

(defun enable-discovery (p sink &optional onion-sink)
  "Register addr/addrv2 handlers on P that feed parsed (host . port) pairs to
   SINK (a function of one (host . port)), and send getaddr.  SINK is typically
   ADDRMAN-ADD bound to the process address pool.  With ONION-SINK, Tor v3
   (.onion-address . port) entries from addrv2 gossip are fed to it as well."
  (on p "addr"   (lambda (pr payload) (declare (ignore pr))
                   (dolist (hp (parse-addr-payload payload)) (funcall sink hp))))
  (on p "addrv2" (lambda (pr payload) (declare (ignore pr))
                   (dolist (hp (parse-addrv2-payload payload)) (funcall sink hp))
                   (when onion-sink
                     (dolist (op (onion:parse-addrv2-onions payload)) (funcall onion-sink op)))))
  (send-getaddr p)
  p)

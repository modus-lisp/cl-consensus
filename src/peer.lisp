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
  (:local-nicknames (#:w #:cl-consensus.wire) (#:bt #:bordeaux-threads))
  (:export
   #:peer #:peer-addr #:peer-version #:peer-subver #:peer-height
   #:peer-services #:peer-alive-p #:peer-connected-at
   #:connect-peer #:disconnect #:send #:on #:peer-log #:peer-host #:peer-port
   #:send-getaddr #:parse-addr-payload #:parse-addrv2-payload #:enable-discovery
   #:*default-user-agent* #:*protocol-version*))

(in-package #:cl-consensus.peer)

(defparameter *protocol-version* 70016)
(defparameter *default-user-agent* "/cl-consensus:0.1/")

(defstruct peer
  host port socket stream
  (lock (bt:make-lock "peer-send"))
  thread
  (handlers (make-hash-table :test 'equal))   ; command string -> function (peer payload-bytes)
  (alive t)
  ;; peer-reported handshake info
  version services subver height
  (connected-at 0)
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
             (checksum (w:r-bytes r 4))
             (payload (if (plusp len) (read-fully stream len)
                          (make-array 0 :element-type '(unsigned-byte 8)))))
        (unless (equalp checksum (w:checksum payload))
          (error "bad checksum on ~a message from ~a" command (peer-addr p)))
        (values command payload)))))

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
    ((member command '("alert" "feefilter" "sendheaders" "sendcmpct"
                       "getheaders" "wtxidrelay")
             :test #'string=)
     t)                                   ; ignore for now
    ;; NOTE: "addr"/"addrv2" are intentionally NOT swallowed here — they dispatch
    ;; to a registered handler (peer discovery, see ENABLE-DISCOVERY); with no
    ;; handler installed, DISPATCH simply no-ops, so this stays safe by default.
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

(defun connect-peer (host &key (port (w:net-port w:*network*))
                               (start-height 0) (verbose nil)
                               (timeout 15))
  "Open a TCP connection to HOST:PORT and complete the version/verack handshake.
   Returns a live PEER with its read loop running, or signals on failure."
  (let* ((sock (usocket:socket-connect host port
                                        :element-type '(unsigned-byte 8)
                                        :timeout timeout))
         (p (make-peer :host host :port port :socket sock
                       :stream (usocket:socket-stream sock)
                       :verbose verbose
                       :connected-at (get-universal-time))))
    ;; --- handshake (synchronous) ---
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
               ;; modern protocol: ack, and accept wtxid relay / sendaddrv2 noise
               (send p "verack" #())))
            ((string= command "verack") (setf got-verack t))
            ((string= command "wtxidrelay") nil)
            ((string= command "sendaddrv2") nil)
            (t nil)))))
    ;; --- go async ---
    ;; usocket set a 15s INPUT timeout on the stream (from the connect :timeout);
    ;; clear it so the steady-state read loop blocks indefinitely for the next
    ;; message instead of dying on an idle gap (e.g. while IBD is backpressured).
    #+sbcl (ignore-errors (setf (sb-impl::fd-stream-timeout (peer-stream p)) nil))
    (setf (peer-thread p)
          (bt:make-thread (lambda () (read-loop p))
                          :name (format nil "btc-peer ~a" (peer-addr p))))
    p))

(defun disconnect (p)
  (setf (peer-alive p) nil)
  (ignore-errors (usocket:socket-close (peer-socket p)))
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

(defun enable-discovery (p sink)
  "Register addr/addrv2 handlers on P that feed parsed (host . port) pairs to
   SINK (a function of one (host . port)), and send getaddr.  SINK is typically
   ADDRMAN-ADD bound to the process address pool."
  (on p "addr"   (lambda (pr payload) (declare (ignore pr))
                   (dolist (hp (parse-addr-payload payload)) (funcall sink hp))))
  (on p "addrv2" (lambda (pr payload) (declare (ignore pr))
                   (dolist (hp (parse-addrv2-payload payload)) (funcall sink hp))))
  (send-getaddr p)
  p)

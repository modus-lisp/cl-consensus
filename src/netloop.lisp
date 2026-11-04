;;;; src/netloop.lisp -- P2P sockets on modus: one net thread, two channels.
;;;;
;;;; SBCL runs a thread per peer, and those threads share the chain, the mempool,
;;;; the peer lists and every handler's closure variables.  modus threads share
;;;; no state: a worker may not store one of its own objects where another thread
;;;; can reach it.  So on modus the work is split the way modus's own isolated SSH
;;;; server splits it (net/isolated-cl.lisp):
;;;;
;;;;   - ONE net thread owns every socket (listeners and connections).  It never
;;;;     sees a peer, a handler or the chain; it moves BYTES.
;;;;   - The OWNER thread (the one that loaded this) owns everything else.  Peers,
;;;;     handlers and the chain all live there, and every handler runs there.
;;;;   - Two modus channels connect them: commands in (:listen :connect :send
;;;;     :close), events out (:accept :data :eof and replies).  A channel copies
;;;;     its message into the receiver's heap, so nothing is shared.
;;;;
;;;; The owner learns about network input only when it PUMPS the event channel.
;;;; Every place cl-consensus waits for the network therefore waits through
;;;; PAUSE-FOR (or WAIT-UNTIL, built on it): on SBCL it is SLEEP, on modus it pumps
;;;; for that long, running handlers as messages arrive.  A blocking read on a
;;;; connection (the outbound handshake) pumps too.
;;;;
;;;; Nothing here runs on SBCL except PAUSE-FOR and WAIT-UNTIL.
;;;;
;;;; NOT CALLED "PAUSE": modus compiles (pause ...) as its spin-wait intrinsic
;;;; whatever package the symbol is in, so a function named PAUSE is never
;;;; called there -- every wait returned 0 at once and delivered nothing.

(defpackage #:cl-consensus.netloop
  (:use #:cl)
  (:export #:pause-for #:wait-until
           #:netconn #:netconn-p #:netconn-host #:netconn-port #:netconn-eof
           #:netconn-on-data #:net-listen #:net-connect #:net-close #:conn-write
           #:conn-read #:conn-available #:conn-peek-u32 #:pump #:serve-http))
(in-package #:cl-consensus.netloop)

#-modus
(progn
  (defun pause-for (seconds)
    "Wait SECONDS.  (On modus this also delivers network input; see the file header.)"
    (sleep seconds))
  (defun wait-until (predicate &key (timeout 5) (step 0.05))
    "Call PREDICATE until it is true or TIMEOUT seconds pass; its last value."
    (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
      (loop (let ((v (funcall predicate)))
              (when (or v (> (get-internal-real-time) deadline)) (return v)))
            (pause-for step)))))

#+modus
(progn

;;; ===========================================================================
;;; The net thread.  Everything below until "THE OWNER SIDE" runs there and
;;; keeps its state in one local NSTATE: nothing it makes is stored anywhere the
;;; owner can reach.
;;; ===========================================================================

(defstruct nstate
  in out                                   ; channels: commands in, events out
  (socks (make-hash-table))                ; id -> connected socket
  (rdone (make-hash-table))                ; ids whose peer has finished SENDING (EOF read):
                                           ; no longer polled, still writable until :close
  (lsocks (make-hash-table))               ; id -> listening socket
  (next 1000000)                           ; ids for accepted connections
  (buf (make-array 65536 :element-type '(unsigned-byte 8))))

(defun %quad (host)
  (let ((parts (ignore-errors
                (loop with s = 0 for i = (position #\. host :start s)
                      collect (parse-integer host :start s :end i)
                      while i do (setf s (1+ i))))))
    (if (and (= (length parts) 4) (every (lambda (x) (and (integerp x) (<= 0 x 255))) parts))
        (coerce parts 'vector)
        (sb-bsd-sockets:host-ent-address (sb-bsd-sockets:get-host-by-name host)))))

(defun %fd-ready-p (sock)
  (let ((fd (sb-bsd-sockets:socket-file-descriptor sock)))
    (and fd (> (modus-int::%sbs-poll-in fd 0) 0))))

(defun %ns-emit (st event) (modus:channel-send (nstate-out st) event))

(defun %ns-command (st cmd)
  "Run one owner command.  Returns NIL for :QUIT, else T."
  (let ((op (first cmd)) (id (second cmd)))
    (case op
      (:listen
       (handler-case
           (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
             (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
             (sb-bsd-sockets:socket-bind s (%quad (third cmd)) (fourth cmd))
             (sb-bsd-sockets:socket-listen s 16)
             (setf (gethash id (nstate-lsocks st)) s)
             (%ns-emit st (list :listening id (nth-value 1 (sb-bsd-sockets:socket-name s)))))
         (serious-condition () (%ns-emit st (list :error id "listen failed")))))
      (:connect
       (handler-case
           (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
             (sb-bsd-sockets:socket-connect s (%quad (third cmd)) (fourth cmd))
             (setf (gethash id (nstate-socks st)) s)
             (%ns-emit st (list :connected id)))
         (serious-condition () (%ns-emit st (list :error id "connect failed")))))
      (:send
       (let ((s (gethash id (nstate-socks st))) (bytes (third cmd)))
         (when s
           (handler-case
               (let ((off 0) (n (length bytes)))
                 (loop while (< off n) do
                   (let ((k (sb-bsd-sockets:socket-send
                             s (if (zerop off) bytes (subseq bytes off)) (- n off))))
                     (when (or (null k) (<= k 0)) (error "short send"))
                     (incf off k))))
             (serious-condition ()
               (remhash id (nstate-socks st))
               (ignore-errors (sb-bsd-sockets:socket-close s))
               (%ns-emit st (list :eof id)))))))
      (:close
       (let ((s (or (gethash id (nstate-socks st)) (gethash id (nstate-lsocks st)))))
         (remhash id (nstate-socks st)) (remhash id (nstate-lsocks st)) (remhash id (nstate-rdone st))
         (when s (ignore-errors (sb-bsd-sockets:socket-close s)))))
      (:quit (return-from %ns-command nil)))
    t))

(defun %ns-poll (st)
  "Accept pending connections and read ready sockets.  T if anything happened."
  (let ((busy nil))
    (maphash (lambda (lid ls)
               (when (%fd-ready-p ls)
                 (setf busy t)
                 (handler-case
                     (let ((c (sb-bsd-sockets:socket-accept ls)))
                       (when c
                         (let ((id (incf (nstate-next st))))
                           (setf (gethash id (nstate-socks st)) c)
                           (multiple-value-bind (ip port)
                               (ignore-errors (sb-bsd-sockets:socket-peername c))
                             (%ns-emit st (list :accept lid id
                                                (if (vectorp ip) (format nil "~{~a~^.~}" (coerce ip 'list)) "inbound")
                                                (or port 0)))))))
                   (serious-condition () nil))))
             (nstate-lsocks st))
    (let ((dead '()))
      (maphash (lambda (id s)
                 (when (and (not (gethash id (nstate-rdone st))) (%fd-ready-p s))
                   (setf busy t)
                   (let ((n (handler-case
                                (nth-value 1 (sb-bsd-sockets:socket-receive s (nstate-buf st) 65536))
                              (serious-condition () 0))))
                     (if (and n (plusp n))
                         (%ns-emit st (list :data id (subseq (nstate-buf st) 0 n)))
                         (push id dead)))))
               (nstate-socks st))
      ;; The peer has finished sending.  It may still be reading -- a client that
      ;; half-closes after its request waits for the reply -- so the socket stays
      ;; open for writes until the owner closes it.
      (dolist (id dead)
        (setf (gethash id (nstate-rdone st)) t)
        (%ns-emit st (list :eof id))))
    busy))

(defun %net-thread-main (in out)
  (let ((st (make-nstate :in in :out out)))
    (%ns-emit st (list :ready 0))
    (loop
      (loop (multiple-value-bind (cmd ok) (modus:channel-try-receive in)
              (unless ok (return))
              (unless (%ns-command st cmd) (return-from %net-thread-main nil))))
      (unless (%ns-poll st)
        ;; idle: wait for a command, but not long, so sockets are polled again
        (multiple-value-bind (cmd ok) (modus:channel-receive in :timeout 0.005)
          (when (and ok (not (%ns-command st cmd)))
            (return-from %net-thread-main nil)))))))

;;; ===========================================================================
;;; THE OWNER SIDE
;;; ===========================================================================

(defvar *to-net* nil)
(defvar *from-net* nil)
(defvar *net-thread* nil)
(defvar *next-id* 0)
(defvar *conns* (make-hash-table))       ; id -> netconn
(defvar *listeners* (make-hash-table))   ; id -> function of one netconn
(defvar *replies* (make-hash-table))     ; request id -> reply event

(defstruct netconn
  id host port
  (buf (make-array 4096 :element-type '(unsigned-byte 8)))
  (start 0) (end 0)
  (eof nil)
  (on-data nil)                          ; function of the conn, run after input arrives
  (busy nil))                            ; ON-DATA is running (no re-entry)

(defun %warm ()
  "Run every socket call the net thread makes once on THIS thread first.  The
   first call of some runtime functions fills a shared cache, and a worker may not
   do that (modus refuses the store); after a call here the worker only reads it."
  (let ((l (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
        (c (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
        (buf (make-array 16 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (progn
           (setf (sb-bsd-sockets:sockopt-reuse-address l) t)
           (sb-bsd-sockets:socket-bind l (%quad "127.0.0.1") 0)
           (sb-bsd-sockets:socket-listen l 4)
           (let ((port (nth-value 1 (sb-bsd-sockets:socket-name l))))
             (sb-bsd-sockets:socket-connect c (%quad "127.0.0.1") port)
             (%fd-ready-p l)
             (let ((a (sb-bsd-sockets:socket-accept l)))
               (sb-bsd-sockets:socket-peername a)
               (sb-bsd-sockets:socket-send c buf 1)
               (loop repeat 100 until (%fd-ready-p a) do (sleep 0.001))
               (sb-bsd-sockets:socket-receive a buf 16)
               (sb-bsd-sockets:socket-close a))))
      (ignore-errors (sb-bsd-sockets:socket-close c))
      (ignore-errors (sb-bsd-sockets:socket-close l)))))

(defun %ensure-net ()
  (unless *net-thread*
    (%warm)
    (let ((in (modus:make-channel :capacity (* 8 1024 1024) :name "p2p commands"))
          (out (modus:make-channel :capacity (* 8 1024 1024) :name "p2p events")))
      (setf *to-net* in *from-net* out)
      (setf *net-thread* (sb-thread:make-thread (lambda () (%net-thread-main in out))
                                                :name "cl-consensus net"))
      (multiple-value-bind (ev ok) (modus:channel-receive out :timeout 10)
        (unless (and ok (eq (first ev) :ready))
          (error "cl-consensus: the net thread did not start"))))))

(defun %request (cmd &key (timeout 15))
  "Send CMD (its second element is a fresh request id) and pump until the reply."
  (%ensure-net)
  (let ((id (second cmd))
        (deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (modus:channel-send *to-net* cmd)
    (loop
      (multiple-value-bind (r found) (gethash id *replies*)
        (when found (remhash id *replies*) (return r)))
      (when (> (get-internal-real-time) deadline)
        (error "net thread did not answer ~a" (first cmd)))
      (pump 0.05))))

(defun %append (c bytes)
  (let* ((n (length bytes)) (buf (netconn-buf c)))
    (when (> (+ (netconn-end c) n) (length buf))
      ;; compact, and grow if still short
      (let* ((live (- (netconn-end c) (netconn-start c)))
             (nb (if (> (+ live n) (length buf))
                     (make-array (max (* 2 (length buf)) (+ live n)) :element-type '(unsigned-byte 8))
                     buf)))
        (replace nb buf :start2 (netconn-start c) :end2 (netconn-end c))
        (setf (netconn-buf c) nb (netconn-start c) 0 (netconn-end c) live buf nb)))
    (replace buf bytes :start1 (netconn-end c))
    (incf (netconn-end c) n)))

(defun %run-on-data (c)
  (let ((fn (netconn-on-data c)))
    (when (and fn (not (netconn-busy c)))
      (setf (netconn-busy c) t)
      (unwind-protect (funcall fn c) (setf (netconn-busy c) nil)))))

(defun pump (&optional (timeout 0))
  "Deliver what the net thread has sent: wait up to TIMEOUT seconds for the first
   event, then take every event already waiting.  Runs connections' ON-DATA (so
   handlers) and listeners' accept functions.  T if anything arrived."
  (when *from-net*
    (let ((touched '()) (any nil))
      (multiple-value-bind (ev ok) (modus:channel-receive *from-net* :timeout timeout)
        (loop while ok do
          (setf any t)
          (let ((c (gethash (second ev) *conns*)))
            (case (first ev)
              (:data (when c (%append c (third ev)) (pushnew c touched)))
              (:eof (when c (setf (netconn-eof c) t) (remhash (second ev) *conns*) (pushnew c touched)))
              (:accept
               (let ((nc (make-netconn :id (third ev) :host (fourth ev) :port (fifth ev)))
                     (fn (gethash (second ev) *listeners*)))
                 (setf (gethash (third ev) *conns*) nc)
                 (when fn (handler-case (funcall fn nc)
                            (serious-condition (e)
                              (format t "~&[net] accept handler error: ~a~%" e) (force-output))))))
              (t (setf (gethash (second ev) *replies*) ev))))
          (multiple-value-setq (ev ok) (modus:channel-try-receive *from-net*))))
      (dolist (c (nreverse touched)) (%run-on-data c))
      any)))

(defun pause-for (seconds)
  "Wait SECONDS, delivering network input (and running handlers) meanwhile."
  (let ((deadline (+ (get-internal-real-time) (* seconds internal-time-units-per-second))))
    (loop (let ((left (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))
            (when (<= left 0) (return))
            (if *from-net* (pump (min left 0.05)) (sleep (min left 0.05)))))))

(defun wait-until (predicate &key (timeout 5) (step 0.05))
  "Call PREDICATE until it is true or TIMEOUT seconds pass; its last value."
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (loop (let ((v (funcall predicate)))
            (when (or v (> (get-internal-real-time) deadline)) (return v)))
          (pause-for step))))

(defun net-listen (host port on-accept)
  "Listen on HOST:PORT (0 = any free port); call ON-ACCEPT with each new NETCONN.
   Returns the port actually bound."
  (let* ((id (incf *next-id*))
         (r (%request (list :listen id host port))))
    (when (eq (first r) :error) (error "listen on ~a:~d failed" host port))
    (setf (gethash id *listeners*) on-accept)
    (third r)))

(defun net-connect (host port &key (timeout 15))
  "A connected NETCONN to HOST:PORT."
  (let* ((id (incf *next-id*))
         (c (make-netconn :id id :host host :port port)))
    (setf (gethash id *conns*) c)            ; before the reply: data may follow it
    (let ((r (%request (list :connect id host port) :timeout timeout)))
      (when (eq (first r) :error)
        (remhash id *conns*)
        (error "connect to ~a:~d failed" host port)))
    c))

(defun conn-write (c bytes)
  "Send BYTES on C.  Allowed after EOF has been read: a half-closed peer may
   still be waiting for an answer.  (On a fully closed socket the send fails in
   the net thread, which reports :EOF.)"
  (modus:channel-send *to-net* (list :send (netconn-id c)
                                     (coerce bytes '(simple-array (unsigned-byte 8) (*))))))

(defun net-close (c)
  (setf (netconn-eof c) t)
  (remhash (netconn-id c) *conns*)
  (when *to-net* (modus:channel-send *to-net* (list :close (netconn-id c)))))

(defun conn-available (c) (- (netconn-end c) (netconn-start c)))

(defun conn-peek-u32 (c offset)
  "The little-endian u32 at OFFSET into C's buffered input."
  (let ((b (netconn-buf c)) (i (+ (netconn-start c) offset)))
    (logior (aref b i) (ash (aref b (+ i 1)) 8) (ash (aref b (+ i 2)) 16) (ash (aref b (+ i 3)) 24))))

(defun conn-read (c n)
  "Exactly N bytes from C, pumping until they have arrived; END-OF-FILE if the
   connection closes first."
  (loop while (< (conn-available c) n) do
    (when (netconn-eof c) (error 'end-of-file :stream nil))
    (pump 0.05))
  (let ((out (subseq (netconn-buf c) (netconn-start c) (+ (netconn-start c) n))))
    (incf (netconn-start c) n)
    (when (= (netconn-start c) (netconn-end c)) (setf (netconn-start c) 0 (netconn-end c) 0))
    out))

;;; ---------------------------------------------------------------------------
;;; A minimal HTTP/1.1 server on the same net thread, for JSON-RPC.  Hunchentoot
;;; accepts and serves on threads of its own that write the acceptor's state, which
;;; modus refuses; here the HANDLER runs on the owner thread, during PUMP, like a
;;; peer handler.  One request per connection (Connection: close), Content-Length
;;; bodies only -- what bitcoind-style RPC clients send.
;;; ---------------------------------------------------------------------------

(defun %http-head-end (c)
  "Index just past CRLFCRLF in C's buffered input, or NIL."
  (let ((b (netconn-buf c)))
    (loop for i from (netconn-start c) to (- (netconn-end c) 4)
          when (and (= (aref b i) 13) (= (aref b (+ i 1)) 10)
                    (= (aref b (+ i 2)) 13) (= (aref b (+ i 3)) 10))
            return (- (+ i 4) (netconn-start c)))))

(defun %http-content-length (head)
  (let ((k (search "content-length:" (string-downcase head))))
    (if k
        (or (parse-integer head :start (+ k 15) :junk-allowed t) 0)
        0)))

(defun %bytes->string (v) (map 'string #'code-char v))
(defun %string->bytes (s) (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))

(defun serve-http (host port handler)
  "Serve HTTP on HOST:PORT.  HANDLER: a function of the request body (a string)
   returning the response body (a string), sent as application/json.  Returns the
   port bound."
  (net-listen
   host port
   (lambda (conn)
     (setf (netconn-on-data conn)
           (lambda (c)
             (let ((hl (%http-head-end c)))
               (when hl
                 (let* ((head (%bytes->string (subseq (netconn-buf c) (netconn-start c)
                                                       (+ (netconn-start c) hl))))
                        (len (%http-content-length head)))
                   (when (>= (conn-available c) (+ hl len))
                     (conn-read c hl)
                     (let* ((body (%bytes->string (conn-read c len)))
                            (reply (handler-case (funcall handler body)
                                     (serious-condition (e)
                                       (format nil "{\"result\":null,\"error\":{\"code\":-32603,\"message\":~s},\"id\":null}"
                                               (princ-to-string e)))))
                            (out (%string->bytes reply)))
                       (conn-write c (%string->bytes
                                      (format nil "HTTP/1.1 200 OK~c~cContent-Type: application/json~c~cContent-Length: ~d~c~cConnection: close~c~c~c~c"
                                              #\Return #\Newline #\Return #\Newline (length out)
                                              #\Return #\Newline #\Return #\Newline #\Return #\Newline)))
                       (conn-write c out)
                       (net-close c)))))))))))

) ; #+modus

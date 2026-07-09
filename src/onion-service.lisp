;;;; src/onion-service.lisp — run a v3 onion SERVICE for this node (inbound over Tor).
;;;;
;;;; Part of the optional cl-consensus/tor system (needs cl-tor).  Publishes an onion
;;;; service for the node and bridges each inbound rendezvous stream into an ordinary
;;;; inbound peer: cl-tor delivers a connected circuit + stream id, we wrap it as a
;;;; binary gray stream and hand it to ACCEPT-PEER-STREAM, then install the usual
;;;; serving handlers.  The node's identity (hence its .onion address) is persisted so
;;;; it survives restarts.

(defpackage #:cl-consensus.onion-service
  (:use #:cl)
  (:local-nicknames (#:svc #:cl-tor.hsservice) (#:host #:cl-tor.hshost)
                    (#:hsdir #:cl-tor.hsdir) (#:gs #:cl-tor.gray-stream)
                    (#:p #:cl-consensus.peer) (#:s #:cl-consensus.serve)
                    (#:bt #:bordeaux-threads))
  (:export #:start-onion-service #:*onion-address* #:*onion-service-thread*))

(in-package #:cl-consensus.onion-service)

(defvar *onion-address* nil "This node's published .onion address, once the service is up.")
(defvar *onion-service-thread* nil)

(defun %load-or-create-identity (path)
  "Load the 32-byte service seed from PATH, or generate + persist a new one there."
  (if (and path (probe-file path))
      (svc:identity-from-seed
       (with-open-file (in path :element-type '(unsigned-byte 8))
         (let ((seed (make-array 32 :element-type '(unsigned-byte 8))))
           (read-sequence seed in) seed)))
      (let ((id (svc:generate-identity)))
        (when path
          (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                                    :if-exists :supersede :if-does-not-exist :create)
            (write-sequence (svc:hs-identity-seed id) out)))
        id)))

(defun %inbound-handler (start-height max-peers)
  "A RUN-SERVICE handler: turn one connected rendezvous (circ . sid) into an inbound
   peer — gray-stream wrap, INBOUND handshake, install serving handlers, track it."
  (lambda (circ sid)
    (handler-case
        (let* ((stream (gs:make-tor-stream circ sid))
               (pr (p:accept-peer-stream stream :host "onion-inbound"
                                         :closer (lambda () (ignore-errors (close stream)))
                                         :start-height start-height)))
          (if (s:register-inbound-peer pr :max-peers max-peers)
              (progn (format t "~&[onion] inbound peer up: ~a (height ~a)~%"
                             (p:peer-subver pr) (p:peer-height pr)) (force-output))
              (ignore-errors (p:disconnect pr))))             ; at cap
      (serious-condition (e)
        (format t "~&[onion] inbound handshake failed: ~a~%" e) (force-output)))))

(defun %announce-loop (onion port interval)
  "Gossip our own .onion as a BIP155 addrv2 to every live peer, so they add it to their
   address db and RELAY it — this is how the network learns to reach us.  Announces
   shortly after startup (once peers are up), then every INTERVAL seconds."
  (sleep 60)                              ; let the initial peers connect first
  (loop
    (handler-case
        (let ((peers (remove-if-not #'p:peer-wants-addrv2 (cl-consensus.node:live-peers)))
              (entries (list (p:onion-addrv2-entry onion port))))
          (dolist (pr peers) (p:announce-address pr entries))
          (when peers
            (format t "~&[onion] advertised ~a:~d to ~d peers~%" onion port (length peers))
            (force-output)))
      (serious-condition () nil))
    (sleep interval)))

(defun start-onion-service (&key key-path (start-height 0) (num-intros 3) (port 8333)
                                 (max-peers 64) (republish 5400) (announce-interval 900))
  "Publish an onion service for this node and serve inbound Tor peers into the node's
   inbound set.  KEY-PATH persists the identity (stable .onion across restarts).
   Re-publishes every REPUBLISH seconds, and self-advertises our .onion (addrv2) to
   peers every ANNOUNCE-INTERVAL seconds so the network learns to dial us.  Returns
   the .onion."
  (let* ((id (%load-or-create-identity key-path))
         (onion (hsdir:pubkey->onion (svc:hs-identity-pubkey id)))
         (handler (%inbound-handler start-height max-peers)))
    (setf *onion-address* onion)
    (format t "~&[onion] service address: ~a~%" onion) (force-output)
    (bt:make-thread (lambda () (%announce-loop onion port announce-interval))
                    :name "onion-advertise")
    (setf *onion-service-thread*
          (bt:make-thread
           (lambda ()
             (loop
               (handler-case
                   (multiple-value-bind (service accepted)
                       (host:run-service id handler :num-intros num-intros)
                     (declare (ignore service))
                     (format t "~&[onion] published descriptor to ~d HSDirs (~a)~%"
                             accepted onion) (force-output))
                 (serious-condition (e)
                   (format t "~&[onion] publish failed: ~a~%" e) (force-output)))
               (sleep republish)))
           :name "onion-service"))
    onion))

;; Register with the core node: SERVE-NODE calls this when :onion-service is on.
(setf cl-consensus.node:*onion-service-hook* #'start-onion-service)

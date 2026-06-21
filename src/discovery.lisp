;;;; src/discovery.lisp
;;;;
;;;; Peer discovery: bootstrap the address pool from DNS seeds and/or a known
;;;; peer's getaddr reply, then dial N live connections for parallel IBD download.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-bsd-sockets))             ; libc resolver (usocket's hangs here)

(defpackage #:cl-consensus.discovery
  (:use #:cl)
  (:nicknames #:btc-discovery)
  (:local-nicknames (#:p #:cl-consensus.peer) (#:am #:cl-consensus.addrman) (#:w #:cl-consensus.wire))
  (:export #:*dns-seeds* #:seed-from-dns #:try-connect #:connect-n
           #:make-peer-source #:discover-peers))

(in-package #:cl-consensus.discovery)

(defparameter *dns-seeds*
  '("seed.bitcoin.sipa.be" "dnsseed.bluematt.me" "seed.bitcoinstats.com"
    "seed.bitcoin.jonasschnelli.ch" "seed.btc.petertodd.net" "seed.bitcoin.wiz.biz"
    "dnsseed.emzy.de" "seed.bitcoin.sprovoost.nl")
  "Mainnet DNS seeds — each resolves to many full-node A records.")

(defun %resolve-a (host)
  "Resolve HOST to a list of IPv4 dotted-quad strings via the libc resolver,
   bounded by a per-host timeout so one dead seed can't stall startup."
  (handler-case
      (sb-ext:with-timeout 8
        (loop for a in (sb-bsd-sockets:host-ent-addresses (sb-bsd-sockets:get-host-by-name host))
              when (and (vectorp a) (= (length a) 4))
                collect (format nil "~d.~d.~d.~d" (aref a 0) (aref a 1) (aref a 2) (aref a 3))))
    (serious-condition () nil)))         ; NXDOMAIN / timeout / no A records

(defun seed-from-dns (&optional (am am:*addrman*) (port (w:net-port w:*network*)))
  "Resolve each DNS seed to its A records and add (ip . PORT) to AM.  Returns the
   count of newly-added addresses."
  (let ((added 0))
    (dolist (host *dns-seeds* added)
      (dolist (ip (%resolve-a host))
        (when (am:addrman-add am ip port) (incf added))))))

(defun try-connect (host port &key (start-height 0) (timeout 8) (require-network t) (min-height 0))
  "Dial one address; return a live peer, or NIL on failure / wrong services / too
   far behind.  IBD of historical blocks needs NODE_NETWORK (full, unpruned)
   peers — pruned nodes can't serve old blocks — and the peer must itself be
   synced past the heights we want (MIN-HEIGHT), else it can't serve them."
  (handler-case
      (let ((peer (p:connect-peer host :port port :start-height start-height :timeout timeout)))
        (cond
          ((and require-network (not (logtest (p:peer-services peer) w:+services-network+)))
           (p:disconnect peer) nil)       ; pruned / non-archive: can't serve history
          ((< (or (p:peer-height peer) 0) min-height)
           (p:disconnect peer) nil)       ; peer itself not synced past our target
          (t (format t "~&[discovery] +peer ~a:~d h~a ~a~%"
                     host port (p:peer-height peer) (p:peer-subver peer)) (force-output)
             peer)))
    (serious-condition () nil)))           ; unreachable / handshake failed

(defun connect-n (n &key (am am:*addrman*) (start-height 0) (timeout 8)
                         (max-attempts (* 12 n)) (require-network t) (min-height 0))
  "Dial up to N untried NODE_NETWORK addresses from AM; return the live peers.
   Bounded by MAX-ATTEMPTS so a run of pruned/dead addresses can't loop forever."
  (let ((peers '()) (attempts 0))
    (loop while (and (< (length peers) n) (< attempts max-attempts)) do
      (let ((cands (am:addrman-take am (max 1 (- n (length peers))))))
        (when (null cands) (return))
        (dolist (hp cands)
          (when (>= (length peers) n) (return))
          (incf attempts)
          (let ((peer (try-connect (car hp) (cdr hp) :start-height start-height
                                   :timeout timeout :require-network require-network
                                   :min-height min-height)))
            (when peer (push peer peers))))))
    (nreverse peers)))

(defun make-peer-source (&key (am am:*addrman*) (start-height 0) (timeout 8)
                              (require-network t) (min-height 0))
  "Return a thunk that yields ONE fresh live NODE_NETWORK peer from AM (or NIL when
   exhausted).  Passed to RUN-IBD-ASYNC so a fetcher whose peer dies can pull a
   replacement instead of aborting the whole run."
  (lambda ()
    (loop for tries from 0 below 24
          for hp = (first (am:addrman-take am 1))
          while hp
          for peer = (try-connect (car hp) (cdr hp) :start-height start-height
                                  :timeout timeout :require-network require-network
                                  :min-height min-height)
          when peer do (return peer)
          finally (return nil))))

(defun discover-peers (n &key (am am:*addrman*) (start-height 0) bootstrap)
  "Return up to N live NODE_NETWORK peer connections.  Seeds AM from DNS when
   empty, and — if a BOOTSTRAP peer is given — asks it for addresses (getaddr)
   first, so a local node can supply the network without DNS."
  (when bootstrap
    (p:enable-discovery bootstrap (lambda (hp) (am:addrman-add am (car hp) (cdr hp))))
    (sleep 3))                            ; let the addr/addrv2 reply arrive
  (when (zerop (am:addrman-size am)) (seed-from-dns am))
  (connect-n n :am am :start-height start-height))

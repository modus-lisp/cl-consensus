;;;; src/discovery.lisp
;;;;
;;;; Peer discovery: bootstrap the address pool from DNS seeds and/or a known
;;;; peer's getaddr reply, then dial N live connections for parallel IBD download.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-bsd-sockets))             ; libc resolver (usocket's hangs here)

(defpackage #:cl-consensus.discovery
  (:use #:cl)
  (:nicknames #:btc-discovery)
  (:local-nicknames (#:p #:cl-consensus.peer) (#:am #:cl-consensus.addrman) (#:w #:cl-consensus.wire)
                    (#:bt #:bordeaux-threads))
  (:export #:*dns-seeds* #:seed-from-dns #:try-connect #:connect-n
           #:make-peer-source #:discover-peers
           #:connect-parallel #:connect-n-parallel #:discover-peers-parallel))

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

(defun try-connect (host port &key (start-height 0) (timeout 8) (require-network t) (min-height 0)
                                   (defer-loop nil))
  "Dial one address; return a live peer, or NIL on failure / wrong services / too
   far behind.  IBD of historical blocks needs NODE_NETWORK (full, unpruned)
   peers — pruned nodes can't serve old blocks — and the peer must itself be
   synced past the heights we want (MIN-HEIGHT), else it can't serve them.  With
   :DEFER-LOOP the returned peer's read loop is not started (the caller must call
   P:START-READ-LOOP from a long-lived thread) — required when dialing in workers."
  (handler-case
      (let ((peer (p:connect-peer host :port port :start-height start-height :timeout timeout
                                  :defer-loop defer-loop)))
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

(defun connect-parallel (candidates &key (start-height 0) (timeout 6)
                                         (require-network t) (min-height 0))
  "Dial every (host . port) in CANDIDATES concurrently and return the live peers.
   Most gossiped addresses are dead, so serial dialing pays one TIMEOUT per dud;
   fanning out collapses the whole batch into a single timeout window."
  ;; One thread per candidate.  Each dials (:defer-loop, no child read-loop) and, on
  ;; success, BECOMES the peer's read loop — so it stays alive as long as the peer and
  ;; the socket is never orphaned.  A per-thread "dial resolved" signal (fired before
  ;; entering the read loop) lets us collect the live set without joining threads that
  ;; must keep running.
  (let* ((lock (bt:make-lock)) (live '())
         (rlock (bt:make-lock)) (remaining (length candidates))
         (all-resolved (bt:make-semaphore)))
    (when (zerop remaining) (return-from connect-parallel '()))
    ;; NB: fresh binding of HP per iteration — SBCL's DOLIST reuses one binding, so a
    ;; closure over the loop var would see only the last candidate.
    (mapc
     (lambda (hp)
       (bt:make-thread
        (lambda ()
          (let ((peer (handler-case
                          (try-connect (car hp) (cdr hp) :start-height start-height
                                       :timeout timeout :require-network require-network
                                       :min-height min-height :defer-loop t)
                        (serious-condition () nil))))
            (when peer (bt:with-lock-held (lock) (push peer live)))
            (bt:with-lock-held (rlock)
              (when (zerop (decf remaining)) (bt:signal-semaphore all-resolved)))
            (when peer (p:run-read-loop peer))))   ; thread lives on as the read loop
        :name (format nil "btc-dial ~a" (car hp))))
     candidates)
    ;; wait until every dial has resolved (bounded: one timeout window + slack)
    (bt:wait-on-semaphore all-resolved :timeout (+ timeout 5))
    (bt:with-lock-held (lock) (copy-list live))))

(defun connect-n-parallel (n &key (am am:*addrman*) (start-height 0) (timeout 6)
                                  (batch (* 4 n)) (max-rounds 4)
                                  (require-network t) (min-height 0))
  "Collect up to N live NODE_NETWORK peers, dialing addrman candidates in parallel
   batches until N are up, the pool is exhausted, or MAX-ROUNDS batches have run.
   Surplus connections beyond N are closed."
  (let ((live '()))
    (loop for round from 0 below max-rounds
          while (< (length live) n) do
      (let ((cands (am:addrman-take am batch)))
        (when (null cands) (return))
        (setf live (append live
                           (connect-parallel cands :start-height start-height :timeout timeout
                                             :require-network require-network :min-height min-height)))))
    (when (> (length live) n)
      (mapc (lambda (p) (ignore-errors (p:disconnect p))) (subseq live n))  ; drop surplus (tail)
      (setf live (subseq live 0 n)))                                        ; keep the live head
    live))

(defun discover-peers-parallel (n &key (am am:*addrman*) (start-height 0) bootstrap (min-height 0))
  "Like DISCOVER-PEERS but fans the dials out.  Seeds AM from a BOOTSTRAP peer's
   getaddr (if given) AND the DNS seeds (curated, higher hit-rate than gossip),
   then parallel-dials up to N live peers."
  (when bootstrap
    (p:enable-discovery bootstrap (lambda (hp) (am:addrman-add am (car hp) (cdr hp))))
    (sleep 3))                            ; let the addr/addrv2 reply arrive
  (seed-from-dns am)
  (connect-n-parallel n :am am :start-height start-height :min-height min-height))

(defun discover-peers (n &key (am am:*addrman*) (start-height 0) bootstrap)
  "Return up to N live NODE_NETWORK peer connections.  Seeds AM from DNS when
   empty, and — if a BOOTSTRAP peer is given — asks it for addresses (getaddr)
   first, so a local node can supply the network without DNS."
  (when bootstrap
    (p:enable-discovery bootstrap (lambda (hp) (am:addrman-add am (car hp) (cdr hp))))
    (sleep 3))                            ; let the addr/addrv2 reply arrive
  (when (zerop (am:addrman-size am)) (seed-from-dns am))
  (connect-n n :am am :start-height start-height))

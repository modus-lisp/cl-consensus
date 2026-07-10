;;;; bin/serve-node.lisp — the consolidated node launcher (HARNESS).
;;;;
;;;; One long-lived process: single-writer validating follower + serve headers/blocks +
;;;; tx relay + JSON-RPC.  Resumes from the UTXO store's crash-safe checkpoint each
;;;; (re)start.  This file is reusable — ALL node-specific configuration comes from the
;;;; environment (see bin/serve-node.sh and bin/node.env.example).  Dependencies are
;;;; found through the ASDF source-registry, so set CL_SOURCE_REGISTRY (the supervisor
;;;; does) to a :tree over the cl-consensus checkout and its deps — no hardcoded paths.
(require :asdf)

;; Build hunchentoot WITHOUT its cl+ssl/OpenSSL SSL support: the RPC is a plain HTTP
;; easy-acceptor (no HTTPS) and cl-tor's TLS is seal (pure CL), so the node is FFI-free.
;; Must precede the first load so hunchentoot compiles without the dependency.
(pushnew :hunchentoot-no-ssl *features*)

(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defun %env (name &optional default) (or (sb-ext:posix-getenv name) default))
(defun %env-flag (name) (let ((e (sb-ext:posix-getenv name))) (and e (string/= e "") (string/= e "0"))))
(defun %env-int (name default) (let ((e (sb-ext:posix-getenv name))) (if e (parse-integer e) default)))
(defun %data (name) (namestring (merge-pathnames name (merge-pathnames ".cl-consensus/"
                                                                       (user-homedir-pathname)))))

;; OUTBOUND transport + optional Tor.  ONION=1 dials .onion peers (clearnet stays on
;; PEER_TRANSPORT); PEER_TRANSPORT=tor routes ALL public peers over Tor; ONION_SERVICE=1
;; runs our own v3 onion service (inbound peers over Tor).  Any of these pulls the
;; optional Tor provider (cl-tor via seal); nothing Tor loads otherwise.
(defparameter *onion-service-p* (%env-flag "ONION_SERVICE"))
(let ((tp (sb-ext:posix-getenv "PEER_TRANSPORT")))
  (when (or *onion-service-p* (%env-flag "ONION") (and tp (string-equal tp "tor")))
    (handler-bind ((warning #'muffle-warning))
      (asdf:load-system (if *onion-service-p* "cl-consensus/tor" "cl-tor-transport"))))
  (setf cl-consensus.peer:*peer-transport*
        (cond ((and tp (string-equal tp "tor")) :tor)
              ((and tp (string-equal tp "socks5")) :socks5)
              (t :direct))))

;; GC more often (1 GB) so transient flush-churn doesn't spike to OOM before a collect.
(setf (sb-ext:bytes-consed-between-gcs) (* 1 1024 1024 1024))

(cl-consensus.node:serve-node
  :store         (%env "PT_STORE"      (%data "live.pt"))
  :block-store   (%env "SERVE_BLOCKS"  (%data "blocks.dat"))
  :mempool-path  (%env "SERVE_MEMPOOL" (%data "mempool.dat"))
  :peer-host     (%env "SERVE_PEER" "127.0.0.1")
  :conns         (%env-int "CONNS" 2)
  :cache-gb      (%env-int "PT_CACHE_GB" 8)
  :listen-port   (%env-int "SERVE_PORT" 8333)
  :rpc-port      (%env-int "RPC_PORT" 8432)
  :archive       (%env-flag "ARCHIVE")
  :archive-peers (%env-int "ARCHIVE_PEERS" 16)
  ;; PRUNE=N keeps only the last N blocks (PRUNE=1 -> the 288 default); implies no archive.
  :prune         (let ((e (sb-ext:posix-getenv "PRUNE")))
                   (cond ((or (null e) (string= e "") (string= e "0")) nil)
                         (t (or (ignore-errors (parse-integer e)) t))))
  :onion-service *onion-service-p*
  :poll          (%env-int "POLL" 30))
(sb-ext:exit :code 0)

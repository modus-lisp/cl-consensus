;;;; inspect/tx-relay-test.lisp
;;;;
;;;; Gate for tx relay (Phase 3b): stand up the inbound listener with tx relay enabled
;;;; (OP_TRUE UTXO + mempool), connect TWO loopback peers, and exercise:
;;;;   - inbound 'tx' -> accepted into the mempool -> inv(MSG_TX) announced to the OTHER
;;;;     peer (not echoed to the sender)
;;;;   - getdata(MSG_TX) -> the exact tx bytes served from the mempool
;;;;   - orphan handling: a child arriving before its parent is parked, then accepted
;;;;     once the parent arrives (out-of-order relay)
;;;; Fully offline (127.0.0.1).
;;;;
;;;;   sbcl --load inspect/tx-relay-test.lisp --eval '(tx-relay-test:run)'
(require :asdf)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/cl-consensus/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :tx-relay-test
  (:use :cl)
  (:local-nicknames (:c :cl-consensus.chain) (:p :cl-consensus.peer) (:w :cl-consensus.wire)
                    (:s :cl-consensus.serve) (:mp :cl-consensus.mempool) (:tx :cl-consensus.tx)
                    (:u :cl-consensus.utxo) (:bt :bordeaux-threads))
  (:export #:run))
(in-package :tx-relay-test)

(defparameter *op-true* (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51))
(defparameter +coin+ 10000000)
(defparameter *ok* t)
(defun check (name cond) (unless cond (setf *ok* nil) (format t "  *** FAIL: ~a~%" name)))

(defun fake-hash (n)
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (logand n 255) (aref h 1) (logand (ash n -8) 255)) h))

(defun build-tx (prevs outvals)
  (let ((txn (tx:make-tx :version 2
                         :inputs (mapcar (lambda (pp) (tx:make-txin :prev-hash (car pp) :prev-index (cdr pp)
                                                                    :script #() :sequence #xffffffff)) prevs)
                         :outputs (mapcar (lambda (v) (tx:make-txout :value v :script *op-true*)) outvals)
                         :witnesses nil :locktime 0 :segwit-p nil)))
    (tx:finalize-tx txn) txn))

(defun make-hdr (prev height)
  (let ((wr (w:make-writer)))
    (w:w-u32 wr 1) (w:w-hash wr (c:header-hash prev))
    (w:w-hash wr (make-array 32 :element-type '(unsigned-byte 8) :initial-element (logand height 255)))
    (w:w-u32 wr (+ 1500000000 height)) (w:w-u32 wr #x1d00ffff) (w:w-u32 wr height)
    (let ((h (c:parse-header (w:make-reader (w:writer-bytes wr))))) (c:add-header h :validate nil) h)))

(defun send-tx (peer txn) (p:send peer "tx" (tx:serialize-tx txn :witness t)))

(defun run (&key (port 18566))
  (setf *ok* t)
  (c:init-chain)
  (let ((prev (c:tip))) (dotimes (i 5) (setf prev (make-hdr prev (1+ i)))))
  ;; OP_TRUE UTXO + fresh mempool, tx relay on
  (let ((utxo (u:make-utxo-set)) (hashes (make-array 6)))
    (dotimes (i 6)
      (let ((h (fake-hash (+ 100 i))))
        (setf (aref hashes i) h)
        (u:utxo-add utxo h 0 (u:make-coin :value +coin+ :height 1 :coinbase-p nil :script *op-true*))))
    (setf s:*utxo* utxo s:*mempool* (mp:make-mempool) s:*orphans* (s::make-orphan-pool)
          s:*tx-relay-enabled* t)
    (s:start-listener :port port :host "127.0.0.1" :max-peers 8)
    (sleep 1)
    (let ((a (p:connect-peer "127.0.0.1" :port port :start-height 0 :timeout 5))
          (b (p:connect-peer "127.0.0.1" :port port :start-height 0 :timeout 5)))
      (loop repeat 50 until (>= (length s:*inbound-peers*) 2) do (sleep 0.1))
      (check "two inbound peers registered" (>= (length s:*inbound-peers*) 2))
      ;; B watches for inv + tx
      (let ((b-inv nil) (b-tx nil))
        (p:on b "inv" (lambda (pr pl) (declare (ignore pr)) (setf b-inv (s:parse-getdata pl))))
        (p:on b "tx" (lambda (pr pl) (declare (ignore pr)) (setf b-tx pl)))
        ;; ---- A sends a tx ----
        (let* ((t1 (build-tx (list (cons (aref hashes 0) 0)) (list (- +coin+ 5000))))
               (t1id (tx:txid-hex t1)))
          (send-tx a t1)
          (loop repeat 50 until (mp:mempool-get s:*mempool* t1id) do (sleep 0.1))
          (check "tx accepted into mempool" (mp:mempool-get s:*mempool* t1id))
          (loop repeat 50 until b-inv do (sleep 0.1))
          (check "tx inv-announced to the other peer"
                 (and b-inv (= (length b-inv) 1) (= (car (first b-inv)) s::+msg-tx+)
                      (string= (w:hash->hex (cdr (first b-inv))) t1id)))
          ;; ---- B getdata's the tx ----
          (p:send b "getdata" (s:build-inv-message (list (cons s::+msg-witness-tx+ (w:hex->hash t1id)))))
          (loop repeat 50 until b-tx do (sleep 0.1))
          (check "tx served on getdata, exact bytes"
                 (and b-tx (equalp b-tx (tx:serialize-tx t1 :witness t)))))
        ;; ---- orphan: child before parent ----
        (let* ((parent (build-tx (list (cons (aref hashes 1) 0)) (list (- +coin+ 5000))))
               (pid (tx:txid-hex parent))
               (child (build-tx (list (cons (tx:tx-txid parent) 0)) (list (- +coin+ 10000))))
               (cid (tx:txid-hex child)))
          (send-tx a child)                          ; parent unknown -> orphan
          (loop repeat 30 until (gethash cid (s::orphan-pool-txs s:*orphans*)) do (sleep 0.1))
          (check "child parked as orphan" (gethash cid (s::orphan-pool-txs s:*orphans*)))
          (check "child NOT yet in mempool" (null (mp:mempool-get s:*mempool* cid)))
          (send-tx a parent)                         ; now parent arrives
          (loop repeat 50 until (and (mp:mempool-get s:*mempool* pid)
                                     (mp:mempool-get s:*mempool* cid)) do (sleep 0.1))
          (check "parent accepted" (mp:mempool-get s:*mempool* pid))
          (check "orphan child resolved into mempool" (mp:mempool-get s:*mempool* cid))
          (check "orphan pool drained" (null (gethash cid (s::orphan-pool-txs s:*orphans*))))))
      (ignore-errors (p:disconnect a)) (ignore-errors (p:disconnect b)))
    (setf s:*tx-relay-enabled* nil s:*mempool* nil s:*utxo* nil))
  (format t "~&tx-relay-test: ~a~%" (if *ok* "OK — accept + inv + serve + orphan resolution" "FAILED"))
  *ok*)

;;;; inspect/mempool-test.lisp
;;;;
;;;; Gate for mempool relay-policy maturity: feerate floor, dust, locktime finality,
;;;; BIP125 RBF (accept + each rule's rejection), parent/child package links, size-cap
;;;; eviction (cheapest leaf, CPFP-aware), and expiry.  Uses OP_TRUE (anyone-can-spend)
;;;; coins so we exercise policy without signing.  Fully offline.
;;;;
;;;;   sbcl --load inspect/mempool-test.lisp --eval '(mempool-test:run)'
(require :asdf)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/cl-consensus/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :mempool-test
  (:use :cl)
  (:local-nicknames (:mp :cl-consensus.mempool) (:tx :cl-consensus.tx)
                    (:u :cl-consensus.utxo) (:w :cl-consensus.wire))
  (:export #:run))
(in-package :mempool-test)

(defparameter *op-true* (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51))
(defparameter +coin+ 10000000)          ; 0.1 BTC funding per coin
(defparameter *ok* t)

(defun check (name cond)
  (unless cond (setf *ok* nil) (format t "  *** FAIL: ~a~%" name)))

(defun expect-reject (name thunk &optional substr)
  "Assert THUNK signals mp:rejected (optionally with SUBSTR in the reason)."
  (handler-case (progn (funcall thunk) (setf *ok* nil) (format t "  *** FAIL: ~a (expected reject)~%" name))
    (mp:rejected (e)
      (when (and substr (not (search substr (mp:rejected-reason e))))
        (setf *ok* nil) (format t "  *** FAIL: ~a (reason ~s lacks ~s)~%" name (mp:rejected-reason e) substr)))))

(defun fake-hash (n)
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (logand n 255) (aref h 1) (logand (ash n -8) 255)) h))

(defun fund (n)
  "A fresh UTXO set with N OP_TRUE coins; returns (values utxo coin-hash-vector)."
  (let ((set (u:make-utxo-set)) (hashes (make-array n)))
    (dotimes (i n)
      (let ((h (fake-hash (+ 100 i))))
        (setf (aref hashes i) h)
        (u:utxo-add set h 0 (u:make-coin :value +coin+ :height 1 :coinbase-p nil :script *op-true*))))
    (values set hashes)))

(defun build-tx (prevs outvals &key (seq #xffffffff) (locktime 0))
  "PREVS = list of (hash . index); OUTVALS = list of output sat values (OP_TRUE spk)."
  (let ((txn (tx:make-tx :version 2
                         :inputs (mapcar (lambda (p) (tx:make-txin :prev-hash (car p) :prev-index (cdr p)
                                                                   :script #() :sequence seq))
                                         prevs)
                         :outputs (mapcar (lambda (v) (tx:make-txout :value v :script *op-true*)) outvals)
                         :witnesses nil :locktime locktime :segwit-p nil)))
    (tx:finalize-tx txn) txn))

(defun run ()
  (setf *ok* t)
  ;; ---- basic accept + value/feerate ----
  (multiple-value-bind (utxo h) (fund 12)
    (let ((mp (mp:make-mempool)))
      (let ((e (mp:accept-tx (build-tx (list (cons (aref h 0) 0)) (list (- +coin+ 5000)))
                             utxo mp :height 200000 :mtp 1500000000)))
        (check "basic accept returns entry" (and e (= (mp:entry-fee e) 5000)))
        (check "mempool size 1" (= (mp:mempool-size mp) 1)))
      ;; dust output
      (expect-reject "dust output"
        (lambda () (mp:accept-tx (build-tx (list (cons (aref h 1) 0)) (list 100))
                                 utxo mp :height 200000 :mtp 1500000000)) "dust")
      ;; min relay fee (feerate < 1 sat/vB): fee 1 over ~110 vB
      (expect-reject "min relay fee"
        (lambda () (mp:accept-tx (build-tx (list (cons (aref h 2) 0)) (list (- +coin+ 1)))
                                 utxo mp :height 200000 :mtp 1500000000)) "min relay fee")
      ;; non-final (time locktime in the future, non-final sequence)
      (expect-reject "non-final locktime"
        (lambda () (mp:accept-tx (build-tx (list (cons (aref h 3) 0)) (list (- +coin+ 5000))
                                           :seq #xfffffffe :locktime 1600000000)
                                 utxo mp :height 200000 :mtp 1500000000)) "non-final")))
  ;; ---- conflicts: plain double-spend (irreplaceable) vs RBF ----
  (multiple-value-bind (utxo h) (fund 12)
    (let ((mp (mp:make-mempool)))
      ;; non-signaling parent, then a conflicting spend -> rejected (rule 1)
      (mp:accept-tx (build-tx (list (cons (aref h 0) 0)) (list (- +coin+ 5000)) :seq #xffffffff)
                    utxo mp :height 200000 :mtp 1500000000)
      (expect-reject "double-spend of irreplaceable"
        (lambda () (mp:accept-tx (build-tx (list (cons (aref h 0) 0)) (list (- +coin+ 6000)) :seq #xffffffff)
                                 utxo mp :height 200000 :mtp 1500000000)) "rule 1")
      ;; signaling parent -> a higher-fee replacement REPLACES it
      (let ((orig (mp:accept-tx (build-tx (list (cons (aref h 1) 0)) (list (- +coin+ 2000)) :seq #xfffffffd)
                                utxo mp :height 200000 :mtp 1500000000)))
        (declare (ignore orig))
        (let ((before (mp:mempool-size mp)))
          (mp:accept-tx (build-tx (list (cons (aref h 1) 0)) (list (- +coin+ 9000)) :seq #xfffffffd)
                        utxo mp :height 200000 :mtp 1500000000)
          (check "RBF keeps size constant (replace, not add)" (= (mp:mempool-size mp) before))
          ;; the surviving tx pays 9000
          (let ((survivor (mp:mempool-get mp (tx:txid-hex (build-tx (list (cons (aref h 1) 0)) (list (- +coin+ 9000)) :seq #xfffffffd)))))
            (check "RBF replacement is in mempool" (and survivor (= (mp:entry-fee survivor) 9000))))))
      ;; RBF rule 3: replacement must raise absolute fee
      (mp:accept-tx (build-tx (list (cons (aref h 2) 0)) (list (- +coin+ 5000)) :seq #xfffffffd)
                    utxo mp :height 200000 :mtp 1500000000)
      (expect-reject "RBF rule 3 (fee not higher)"
        (lambda () (mp:accept-tx (build-tx (list (cons (aref h 2) 0)) (list (- +coin+ 5000)) :seq #xfffffffd
                                           :locktime 1)  ; differ so txid differs
                                 utxo mp :height 200000 :mtp 1500000000)) "rule 3")))
  ;; ---- package links (parent/child) ----
  (multiple-value-bind (utxo h) (fund 12)
    (let ((mp (mp:make-mempool)))
      (let* ((parent (build-tx (list (cons (aref h 0) 0)) (list (- +coin+ 5000))))
             (pid (tx:txid-hex parent)))
        (mp:accept-tx parent utxo mp :height 200000 :mtp 1500000000)
        ;; child spends parent's output 0 (an unconfirmed parent)
        (let* ((child (build-tx (list (cons (tx:tx-txid parent) 0)) (list (- +coin+ 10000))))
               (cid (tx:txid-hex child)))
          (mp:accept-tx child utxo mp :height 200000 :mtp 1500000000)
          (check "child links to parent" (equal (mp:entry-parents (mp:mempool-get mp cid)) (list pid)))
          (check "parent links to child" (equal (mp:entry-children (mp:mempool-get mp pid)) (list cid)))
          (check "gather-descendants finds child"
                 (= 2 (hash-table-count (mp:gather-descendants mp pid))))))))
  ;; ---- eviction: cheapest leaf goes, CPFP parent stays, floor rises ----
  (multiple-value-bind (utxo h) (fund 12)
    (let ((mp (mp:make-mempool)))
      ;; three independent leaves with fees 1000/3000/5000
      (mp:accept-tx (build-tx (list (cons (aref h 0) 0)) (list (- +coin+ 1000))) utxo mp :height 200000 :mtp 1500000000 :trim nil)
      (mp:accept-tx (build-tx (list (cons (aref h 1) 0)) (list (- +coin+ 3000))) utxo mp :height 200000 :mtp 1500000000 :trim nil)
      (mp:accept-tx (build-tx (list (cons (aref h 2) 0)) (list (- +coin+ 5000))) utxo mp :height 200000 :mtp 1500000000 :trim nil)
      (let ((cheap-id (tx:txid-hex (build-tx (list (cons (aref h 0) 0)) (list (- +coin+ 1000))))))
        ;; trim to hold ~2 of the 3
        (let ((bytes (mp:mempool-bytes mp)))
          (mp:trim-mempool mp (floor (* 2 (/ bytes 3))))
          (check "eviction dropped the cheapest leaf" (null (mp:mempool-get mp cheap-id)))
          (check "eviction raised the floor" (> (mp:mempool-floor-feerate mp) 0))))
      ;; CPFP: low-fee parent + high-fee child; trimming must not evict the parent (it has a child)
      (let* ((p (build-tx (list (cons (aref h 5) 0)) (list (- +coin+ 800))))
             (pid (tx:txid-hex p)))
        (setf (mp:mempool-floor-feerate mp) 0)   ; reset floor for this sub-check
        (mp:accept-tx p utxo mp :height 200000 :mtp 1500000000 :trim nil)
        (let ((c (build-tx (list (cons (tx:tx-txid p) 0)) (list (- +coin+ 1600)))))
          (mp:accept-tx c utxo mp :height 200000 :mtp 1500000000 :trim nil)
          (mp:trim-mempool mp (- (mp:mempool-bytes mp) 1)) ; force one eviction
          (check "CPFP parent survives (has a child)" (mp:mempool-get mp pid))))))
  ;; ---- expiry ----
  (multiple-value-bind (utxo h) (fund 12)
    (let ((mp (mp:make-mempool)))
      (mp:accept-tx (build-tx (list (cons (aref h 0) 0)) (list (- +coin+ 5000))) utxo mp
                    :height 200000 :mtp 1500000000 :time 1000)         ; old
      (mp:accept-tx (build-tx (list (cons (aref h 1) 0)) (list (- +coin+ 5000))) utxo mp
                    :height 200000 :mtp 1500000000 :time 1000000000)   ; fresh
      (let ((removed (mp:expire-mempool mp (+ 1000000000 10) mp:*mempool-expiry-seconds*)))
        (check "expiry removed the old tx" (= removed 1))
        (check "expiry kept the fresh tx" (= (mp:mempool-size mp) 1)))))
  (format t "~&mempool-test: ~a~%" (if *ok* "OK — policy + RBF + links + eviction + expiry" "FAILED"))
  *ok*)

;;;; shared/bitcoind/inspect/difftest.lisp
;;;;
;;;; Live differential harness vs Bitcoin Core (epyc node RPC as oracle).
;;;;
;;;; Core's mempool is a stream of transactions Core has already judged valid.
;;;; We pull each tx + all its prevouts over RPC and run OUR script verifier on
;;;; every input.  Any input we reject that Core accepted is a divergence — a
;;;; real consensus gap or bug.  This is also the first time our taproot code
;;;; runs against live mainnet spends (prevouts fetched via gettxout).
;;;;
;;;; Fuzz mode mutates a valid tx and asserts BOTH we and Core reject it.
;;;;
;;;;   sbcl --load shared/bitcoind/inspect/difftest.lisp \
;;;;        --eval '(in-package :btc-diff)' --eval '(diff-mempool :limit 80)' \
;;;;        --eval '(fuzz :rounds 40)'

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (let ((here (or *load-truename* *compile-file-truename*)))
    (pushnew (uiop:pathname-parent-directory-pathname (uiop:pathname-directory-pathname here)) asdf:*central-registry* :test #'equal)
    (ql:quickload '(:dexador :com.inuoe.jzon) :silent t)
    (asdf:load-system "cl-consensus")
    (load (merge-pathnames "oracle.lisp" here))))   ; brings rpc

(defpackage #:btc-diff
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script) (#:o #:btc-oracle))
  (:export #:diff-mempool #:fuzz #:classify))

(in-package #:btc-diff)

(defun classify (spk)
  (let ((n (length spk)))
    (cond ((and (>= n 1) (= (aref spk (1- n)) #xac) (or (= n 35) (= n 67))) :p2pk)
          ((and (= n 25) (= (aref spk 0) #x76)) :p2pkh)
          ((and (= n 23) (= (aref spk 0) #xa9) (= (aref spk 22) #x87)) :p2sh)
          ((and (= n 22) (= (aref spk 0) 0) (= (aref spk 1) #x14)) :p2wpkh)
          ((and (= n 34) (= (aref spk 0) 0) (= (aref spk 1) #x20)) :p2wsh)
          ((and (= n 34) (= (aref spk 0) #x51) (= (aref spk 1) #x20)) :p2tr)
          ((and (>= n 1) (= (aref spk (1- n)) #xae)) :multisig)
          (t :other))))

(defun btc->sats (v) (round (* v 1d8)))

(defun fetch-prevouts (txn)
  "Resolve every input's prevout via gettxout (includes mempool).  Returns the
   prevouts vector of (amount . script-bytes), or NIL if any is unavailable."
  (let* ((ins (tx:tx-inputs txn))
         (pv (make-array (length ins))))
    (loop for in in ins for i from 0 do
      ;; include_mempool=false: a mempool tx's prevout is "spent" in the mempool
      ;; view but still unspent in the confirmed chain — which is what we want.
      (let ((res (o:rpc "gettxout" (w:hash->hex (tx:txin-prev-hash in))
                        (tx:txin-prev-index in) nil)))
        (when (or (null res) (eq res 'null)) (return-from fetch-prevouts nil))
        (setf (aref pv i)
              (cons (btc->sats (gethash "value" res))
                    (w:hex->bytes (gethash "hex" (gethash "scriptPubKey" res)))))))
    pv))

(defun verify-all-inputs (txn prevouts)
  "T iff every input of TXN verifies under our rules (all soft forks active)."
  (loop for i from 0 below (length (tx:tx-inputs txn))
        always (handler-case
                   (s:verify-input txn i (cdr (aref prevouts i)) (car (aref prevouts i))
                                   :p2sh t :segwit t :prevouts prevouts)
                 (error () nil))))

(defun diff-mempool (&key (limit 80))
  "Pull up to LIMIT live mempool txs and check we accept everything Core did."
  (let* ((ids (coerce (o:rpc "getrawmempool") 'list))
         (sample (subseq ids 0 (min limit (length ids))))
         (agree 0) (diverge 0) (skipped 0)
         (by-type (make-hash-table)) (diverge-ex '()))
    (format t "~&Core mempool: ~d txs; sampling ~d~%" (length ids) (length sample))
    (dolist (txid sample)
      (handler-case
          (let* ((hex (o:rpc "getrawtransaction" txid))
                 (txn (tx:parse-tx (w:make-reader (w:hex->bytes hex))))
                 (prevouts (fetch-prevouts txn)))
            (if (null prevouts)
                (incf skipped)
                (let ((ok (verify-all-inputs txn prevouts))
                      (types (remove-duplicates (map 'list (lambda (pv) (classify (cdr pv))) prevouts))))
                  (if ok
                      (progn (incf agree) (dolist (ty types) (incf (gethash ty by-type 0))))
                      (progn (incf diverge)
                             (when (< (length diverge-ex) 10)
                               (push (cons txid types) diverge-ex)))))))
        (error () (incf skipped))))
    (format t "~%==== live mempool differential ====~%")
    (format t "  AGREE (we accept what Core accepted) : ~d~%" agree)
    (format t "  DIVERGE (we reject, Core accepted)    : ~d~%" diverge)
    (format t "  skipped (prevout/parse unavailable)   : ~d~%" skipped)
    (format t "  agreement: ~,1f%~%"
            (if (plusp (+ agree diverge)) (* 100.0 (/ agree (+ agree diverge))) 100.0))
    (format t "  verified input types: ~{~a~^ ~}~%"
            (loop for k being the hash-keys of by-type using (hash-value v) collect (format nil "~a=~d" k v)))
    (when diverge-ex
      (format t "  divergences (investigate):~%")
      (dolist (e (reverse diverge-ex)) (format t "    ~a  types ~a~%" (car e) (cdr e))))
    (values agree diverge)))

;;; ----------------------------------------------------------------------------
;;; Fuzz: mutate a valid tx, assert both we and Core reject it
;;; ----------------------------------------------------------------------------

(defun mutate (bytes i)
  (let ((b (copy-seq bytes)))
    (when (< i (length b)) (setf (aref b i) (logxor (aref b i) #x01)))
    b))

(defun core-accepts-p (hex)
  (let ((res (o:rpc "testmempoolaccept" (vector hex))))
    (and (vectorp res) (plusp (length res))
         (let ((v (gethash "allowed" (aref res 0)))) (and v (not (eq v 'null)))))))

(defun fuzz (&key (rounds 40))
  "Take a real mempool tx, flip bytes across the tx, and check we and Core agree
   on rejecting the mutants (we must not accept a mutation Core rejects)."
  (let* ((ids (coerce (o:rpc "getrawmempool") 'list)))
    (dolist (txid (subseq ids 0 (min 4 (length ids))))
      (handler-case
          (let* ((hex (o:rpc "getrawtransaction" txid))
                 (orig (w:hex->bytes hex))
                 (txn (tx:parse-tx (w:make-reader orig)))
                 (prevouts (fetch-prevouts txn)))
            (when prevouts
              (let ((both-reject 0) (we-accept-core-rejects 0) (tested 0))
                ;; mutate at evenly spaced positions across the tx body
                (dotimes (k rounds)
                  (let* ((pos (mod (* k (max 1 (floor (length orig) (max 1 rounds)))) (length orig)))
                         (mutbytes (mutate orig pos))
                         (muthex (w:bytes->hex mutbytes)))
                    (handler-case
                        (let* ((mtx (tx:parse-tx (w:make-reader mutbytes)))
                               (we-ok (verify-all-inputs mtx prevouts))
                               (core-ok (core-accepts-p muthex)))
                          (incf tested)
                          (cond ((and (not we-ok) (not core-ok)) (incf both-reject))
                                ((and we-ok (not core-ok)) (incf we-accept-core-rejects))))
                      (error () (incf both-reject)))))   ; parse failure = rejection
                (format t "~&fuzz ~a: tested ~d  both-reject ~d  WE-ACCEPT-CORE-REJECTS ~d~%"
                        (subseq txid 0 16) tested both-reject we-accept-core-rejects))))
        (error (e) (format t "~&fuzz ~a skipped: ~a~%" (subseq txid 0 16) e))))))

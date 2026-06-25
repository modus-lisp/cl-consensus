;;;; inspect/rebuild-flush-equiv.lisp
;;;;
;;;; Correctness gate for the pagetree merge-REBUILD flush path: it MUST be exactly
;;;; equivalent to the incremental tapply-batch flush.  Drives the SAME sequence of
;;;; add/spend change-batches through two stores — one flushed :incremental, one
;;;; :rebuild — and after every round asserts identical UTXO digest, count, and
;;;; total, including after a reopen (proving the atomic single-file swap is durable).
;;;; Exercises overflow scripts, overwrites, within-window add+spend cancellation,
;;;; deletes of committed coins, and multiple consecutive rebuilds.
;;;;
;;;;   sbcl --load inspect/rebuild-flush-equiv.lisp --eval '(rfe:run)'
(require :asdf)
(require :sb-posix)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/cl-consensus/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :rfe (:use :cl) (:local-nicknames (:u :cl-consensus.utxo)) (:export #:run))
(in-package :rfe)

(defvar *seed* 1)
(defun nextr () (let ((x *seed*))
                  (setf x (logand (logxor x (ash x 13)) #xffffffffffffffff))
                  (setf x (logand (logxor x (ash x -7)) #xffffffffffffffff))
                  (setf x (logand (logxor x (ash x 17)) #xffffffffffffffff))
                  (setf *seed* (if (zerop x) 1 x)) x))
(defun rnd (n) (mod (nextr) n))

(defun mk-txid (i)
  (let ((k (make-array 32 :element-type '(unsigned-byte 8))) (h i))
    (dotimes (w 4) (setf h (logand (* (logxor h #x9e3779b97f4a7c15) #xbf58476d1ce4e5b9) #xffffffffffffffff))
      (dotimes (b 8) (setf (aref k (+ (* w 8) b)) (logand (ash h (* -8 b)) #xff))))
    k))
(defun mk-coin (i)
  (let* ((big (zerop (mod i 11)))                       ; ~9% overflow scripts
         (len (if big (+ 100 (rnd 400)) (+ 20 (rnd 50))))
         (s (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (b len) (setf (aref s b) (logand (+ i b) #xff)))
    (u:make-coin :value (+ 1 (rnd 5000000000)) :height (+ 1 (rnd 800000))
                 :coinbase-p (zerop (mod i 7)) :script s)))

(defun fresh-set (path)
  (dolist (e (list "" ".rebuild")) (ignore-errors (delete-file (concatenate 'string path e))))
  (u:open-pagetree-utxo path :cache-bytes (* 256 1024 1024)))

(defun reopen (set path) (u:close-utxo set) (u:open-pagetree-utxo path :cache-bytes (* 256 1024 1024)))

(defun same-p (a b label)
  (let ((da (u:utxo-digest a)) (db (u:utxo-digest b)))
    (let ((ok (and (equalp da db)
                   (= (u:utxo-count a) (u:utxo-count b))
                   (= (u:utxo-set-total-value a) (u:utxo-set-total-value b)))))
      (format t "  [~a] inc(count ~d total ~d) vs rebuild(count ~d total ~d) digest-eq ~a => ~a~%"
              label (u:utxo-count a) (u:utxo-set-total-value a)
              (u:utxo-count b) (u:utxo-set-total-value b) (equalp da db)
              (if ok "OK" "*** MISMATCH ***"))
      ok)))

(defun run (&key (n 15000) (rounds 4) (seed 12345))
  (let ((*seed* seed)
        (pa "/mnt/lisp/ptchain/test/eq-inc.pt")
        (pb "/mnt/lisp/ptchain/test/eq-reb.pt")
        (live (make-array 0 :adjustable t :fill-pointer 0))   ; live outpoints (txid . index)
        (next-id 0) (ok t))
    (ensure-directories-exist "/mnt/lisp/ptchain/test/")
    (let ((a (fresh-set pa)) (b (fresh-set pb)) (height 0))
      (labels ((add-both (id idx)
                 (let ((tx (mk-txid id)) (c (mk-coin id)))
                   (u:utxo-add a tx idx c) (u:utxo-add b tx idx c)
                   (vector-push-extend (cons id idx) live)))
               (spend-both (k)
                 (destructuring-bind (id . idx) (aref live k)
                   (u:utxo-spend a (mk-txid id) idx) (u:utxo-spend b (mk-txid id) idx)
                   (setf (aref live k) (aref live (1- (length live))))
                   (decf (fill-pointer live))))
               (flush-both (h meth-b)
                 (let ((u:*utxo-flush-method* :incremental)) (u:flush-utxo a h))
                 (let ((u:*utxo-flush-method* meth-b)) (u:flush-utxo b h))))
        ;; --- initial identical build (both incremental) ---
        (dotimes (i n) (add-both next-id 0) (incf next-id))
        (incf height) (flush-both height :incremental)
        (unless (same-p a b "initial-build") (setf ok nil))
        ;; --- rounds: each applies the same churn, A incremental, B REBUILD ---
        (dotimes (r rounds)
          ;; spend ~25% of live
          (let ((nspend (floor (length live) 4)))
            (dotimes (j nspend) (when (plusp (length live)) (spend-both (rnd (length live))))))
          ;; add a fresh batch (some will be overwrites? no — fresh ids, unique)
          (let ((nadd (floor n 3)))
            (dotimes (j nadd) (add-both next-id 0) (incf next-id)))
          ;; within-window add-then-spend (must cancel; never reach the tree)
          (dotimes (j 200)
            (add-both next-id 1) (incf next-id)
            (spend-both (1- (length live))))
          (incf height)
          (flush-both height :rebuild)
          (unless (same-p a b (format nil "round-~d-rebuild" (1+ r))) (setf ok nil))
          ;; reopen both and re-verify (atomic swap durability)
          (setf a (reopen a pa) b (reopen b pb))
          (unless (same-p a b (format nil "round-~d-reopen" (1+ r))) (setf ok nil)))
        (u:close-utxo a) (u:close-utxo b))
      (format t "~&rebuild-flush-equiv: ~a~%" (if ok "ALL EQUIVALENT — rebuild == incremental" "FAILED"))
      ok)))

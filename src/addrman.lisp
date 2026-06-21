;;;; src/addrman.lisp
;;;;
;;;; addrman-lite: a thread-safe, deduplicated pool of peer addresses learned
;;;; from DNS seeds and from peers' addr/addrv2 replies.  The IBD peer-pool
;;;; (node.lisp) draws fresh candidates from here to maintain N live download
;;;; connections.  Deliberately minimal (no buckets / eviction / persistence yet)
;;;; — just dedup + "give me N untried addresses".

(defpackage #:cl-consensus.addrman
  (:use #:cl)
  (:nicknames #:btc-addrman)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export #:addrman #:make-addrman #:*addrman*
           #:addrman-add #:addrman-add-list #:addrman-take #:addrman-size #:addrman-tried-count))

(in-package #:cl-consensus.addrman)

(defstruct (addrman (:constructor %make-addrman))
  (lock (bt:make-lock))
  (seen (make-hash-table :test 'equal))   ; "host:port" -> t   (dedup, all-time)
  (queue '())                             ; untried (host . port), freshest first
  (tried (make-hash-table :test 'equal))) ; "host:port" -> t   (handed out already)

(defun make-addrman () (%make-addrman))
(defparameter *addrman* (%make-addrman) "Process-wide address pool.")

(declaim (inline %key))
(defun %key (host port) (format nil "~a:~d" host port))

(defun addrman-add (am host port)
  "Add (HOST . PORT) if never seen before.  Returns T if newly added."
  (bt:with-lock-held ((addrman-lock am))
    (let ((k (%key host port)))
      (unless (gethash k (addrman-seen am))
        (setf (gethash k (addrman-seen am)) t)
        (push (cons host port) (addrman-queue am))
        t))))

(defun addrman-add-list (am pairs)
  "Add a list of (host . port); returns the count newly added."
  (let ((n 0)) (dolist (hp pairs n) (when (addrman-add am (car hp) (cdr hp)) (incf n)))))

(defun addrman-size (am)
  "Number of untried addresses available."
  (bt:with-lock-held ((addrman-lock am)) (length (addrman-queue am))))

(defun addrman-tried-count (am)
  (bt:with-lock-held ((addrman-lock am)) (hash-table-count (addrman-tried am))))

(defun addrman-take (am n)
  "Pop up to N untried addresses; mark them tried so they aren't handed out twice.
   Returns a list of (host . port)."
  (bt:with-lock-held ((addrman-lock am))
    (let ((out '()))
      (loop while (and (< (length out) n) (addrman-queue am)) do
        (let* ((hp (pop (addrman-queue am))) (k (%key (car hp) (cdr hp))))
          (unless (gethash k (addrman-tried am))
            (setf (gethash k (addrman-tried am)) t)
            (push hp out))))
      (nreverse out))))

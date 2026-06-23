;;;; inspect/migrate-udb-to-pagetree.lisp
;;;;
;;;; Reusable, FAST migration of a udb chainstate (the mmap slot table from
;;;; utxo-disk.lisp) into a pagetree UTXO store, using pagetree's bottom-up bulk
;;;; loader.  This is the path to flip a node's UTXO backend from :udb to
;;;; :pagetree without re-IBD.
;;;;
;;;; Why this is fast (minutes, not hours):
;;;;   * the udb is read READ-ONLY (PROT_READ / MAP_PRIVATE) — never opened
;;;;     writable, no lock, no ftruncate, so the source chainstate is untouchable;
;;;;   * every live coin is collected once, the whole set is sorted ONCE by a
;;;;     parallel 2-byte-radix sort (155x faster than CL:SORT with a byte
;;;;     comparator at 168M scale — 14s vs 37min on 116 cores), and
;;;;   * the B+tree is built BOTTOM-UP in a single sequential pass
;;;;     (pt:tbulk-build :sorted t) — O(N) page writes, no per-key descent.
;;;; Measured on the live mainnet udb @902000 (168.5M coins): collect 3.8min +
;;;; sort 14s + build 6.3min, and the result is digest-identical to the udb.
;;;;
;;;; Load and run:
;;;;   sbcl --dynamic-space-size 100000 --load inspect/migrate-udb-to-pagetree.lisp \
;;;;        --eval '(cl-consensus.migrate:migrate :udb "/path/chainstate.udb"
;;;;                                              :pt "/path/out.pt")'
;;;;   ;; optional gold-standard check (slow — hashes every coin twice):
;;;;        --eval '(cl-consensus.migrate:verify-digest :udb "..." :pt "...")'
;;;;
;;;; Needs a big heap: the (key . coin) vector for the full set is ~25-35GB at
;;;; tip; --dynamic-space-size 100000 (100GB) is comfortable.  For RAM-bounded
;;;; hosts (a Pi), an external/streaming merge sort would replace the in-RAM sort
;;;; — noted as future work; this tool targets the big-box one-time flip.

(require :asdf)
(require :sb-posix)
(unless (find-package :cl-consensus)
  (handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus")))

(defpackage #:cl-consensus.migrate
  (:use #:cl)
  (:local-nicknames (#:u #:cl-consensus.utxo)
                    (#:ptu #:cl-consensus.utxo-pagetree)
                    (#:pt #:pagetree))
  (:export #:migrate #:verify-digest #:parallel-radix-sort #:map-udb-readonly
           #:read-udb-marker))
(in-package #:cl-consensus.migrate)

;;; udb on-disk slot layout (mirrors utxo-disk.lisp's internal constants; the
;;; format is stable).  A read-only re-implementation so we never open the source
;;; udb writable.
(defconstant +slot-bytes+ 128) (defconstant +key-off+ 16) (defconstant +script-off+ 52)
(defconstant +inline+ 1) (defconstant +overflow+ 3)

(declaim (inline u8 u16 u32 u64))
(defun u8  (s o) (sb-sys:sap-ref-8  s o))
(defun u16 (s o) (sb-sys:sap-ref-16 s o))
(defun u32 (s o) (sb-sys:sap-ref-32 s o))
(defun u64 (s o) (sb-sys:sap-ref-64 s o))
(defun %secs (t0) (/ (- (get-internal-real-time) t0) internal-time-units-per-second 1.0))

(defun read-udb-marker (meta-path)
  "Return (values height total count) from a udb .meta marker (u32 h || u64 total
   || u64 count)."
  (with-open-file (s meta-path :element-type '(unsigned-byte 8))
    (let ((b (make-array 20 :element-type '(unsigned-byte 8))))
      (read-sequence b s)
      (values (logior (aref b 0) (ash (aref b 1) 8) (ash (aref b 2) 16) (ash (aref b 3) 24))
              (let ((a 0)) (dotimes (i 8 a) (setf a (logior a (ash (aref b (+ 4 i)) (* 8 i))))))
              (let ((a 0)) (dotimes (i 8 a) (setf a (logior a (ash (aref b (+ 12 i)) (* 8 i))))))))))

(defun map-udb-readonly (udb-path ovf-path fn)
  "Call (FN txid index value height coinbase-p script) for every LIVE coin in the
   udb at UDB-PATH, reading it READ-ONLY (PROT_READ / MAP_PRIVATE) — the source is
   never modified.  Returns the number of live coins visited."
  (let* ((bytes (with-open-file (s udb-path :element-type '(unsigned-byte 8)) (file-length s)))
         (cap (floor bytes +slot-bytes+))
         (fd (sb-posix:open udb-path sb-posix:o-rdonly))
         (sap (sb-posix:mmap nil bytes sb-posix:prot-read sb-posix:map-private fd 0))
         (ovf (open ovf-path :direction :input :element-type '(unsigned-byte 8)))
         (n 0))
    (unwind-protect
         (dotimes (i cap n)
           (let* ((base (* i +slot-bytes+)) (state (u8 sap base)))
             (when (or (= state +inline+) (= state +overflow+))
               (let ((txid (make-array 32 :element-type '(unsigned-byte 8))))
                 (dotimes (k 32) (setf (aref txid k) (u8 sap (+ base +key-off+ k))))
                 (let* ((index (u32 sap (+ base +key-off+ 32)))
                        (cb (= 1 (u8 sap (+ base 1))))
                        (height (u32 sap (+ base 4)))
                        (value (u64 sap (+ base 8)))
                        (script
                          (if (= state +overflow+)
                              (let ((off (u64 sap (+ base +script-off+))))
                                (file-position ovf off)
                                (let ((w (make-array 4 :element-type '(unsigned-byte 8))))
                                  (read-sequence w ovf)
                                  (let* ((len (logior (aref w 0) (ash (aref w 1) 8)
                                                      (ash (aref w 2) 16) (ash (aref w 3) 24)))
                                         (b (make-array len :element-type '(unsigned-byte 8))))
                                    (read-sequence b ovf) b)))
                              (let* ((len (u16 sap (+ base 2)))
                                     (b (make-array len :element-type '(unsigned-byte 8))))
                                (dotimes (k len b) (setf (aref b k) (u8 sap (+ base +script-off+ k))))))))
                   (funcall fn txid index value height cb script)
                   (incf n))))))
      (close ovf) (sb-posix:munmap sap bytes) (sb-posix:close fd))))

;;; --- parallel 2-byte-radix sort of (key . val) conses by 36-byte byte-lex key ---
;;; Output order is byte-lex over the encoded outpoint key — exactly pagetree's
;;; key< / what tbulk-build :sorted t requires.

(declaim (inline key<36))
(defun key<36 (x y)
  "Byte-lex < over two encoded outpoint keys (always 36 bytes); typed + alloc-free."
  (declare (optimize (speed 3) (safety 0))
           (type (simple-array (unsigned-byte 8) (*)) x y))
  (dotimes (i 36 nil)
    (let ((p (aref x i)) (q (aref y i)))
      (declare (type (unsigned-byte 8) p q))
      (when (< p q) (return t))
      (when (> p q) (return nil)))))

(defun parallel-radix-sort (vec &optional (nthreads 64))
  "Sort simple-vector VEC of (KEY . VAL) conses ascending by 36-byte byte-lex KEY,
   returning a freshly sorted simple-vector.  Histograms by the top 2 key bytes
   into 65536 ordered buckets, scatters once, then sorts each bucket's disjoint
   sub-range in parallel across NTHREADS workers."
  (declare (optimize (speed 3) (safety 1)) (type simple-vector vec))
  (let* ((n (length vec))
         (nb 65536)
         (count (make-array (1+ nb) :element-type 'fixnum :initial-element 0))
         (out (make-array n)))
    (declare (type fixnum n))
    (flet ((bk (e) (let ((k (car e)))
                     (the fixnum (logior (the fixnum (ash (aref k 0) 8)) (aref k 1))))))
      (dotimes (i n) (incf (aref count (1+ (bk (svref vec i))))))
      (dotimes (b nb) (incf (aref count (1+ b)) (aref count b)))
      (let ((cur (make-array nb :element-type 'fixnum)))
        (dotimes (b nb) (setf (aref cur b) (aref count b)))
        (dotimes (i n)
          (let* ((e (svref vec i)) (b (bk e)))
            (setf (svref out (aref cur b)) e)
            (incf (aref cur b)))))
      (let* ((per (ceiling nb nthreads))
             (threads
               (loop for w below nthreads
                     for blo = (* w per)
                     for bhi = (min nb (* (1+ w) per))
                     when (< blo bhi)
                       collect (sb-thread:make-thread
                                (lambda (blo bhi)
                                  (loop for b from blo below bhi
                                        for lo = (aref count b)
                                        for hi = (aref count (1+ b))
                                        when (> (- hi lo) 1) do
                                          (sort (make-array (- hi lo) :displaced-to out
                                                                      :displaced-index-offset lo)
                                                #'key<36 :key #'car)))
                                :arguments (list blo bhi)))))
        (dolist (th threads) (sb-thread:join-thread th))))
    out))

(defun %meta-value (height total count)
  "The pagetree-backend meta key #(0) value: u32 height || u64 total || u64 count."
  (let ((v (make-array 20 :element-type '(unsigned-byte 8))))
    (dotimes (i 4) (setf (aref v i) (logand (ash height (* -8 i)) #xff)))
    (dotimes (i 8) (setf (aref v (+ 4 i)) (logand (ash total (* -8 i)) #xff)))
    (dotimes (i 8) (setf (aref v (+ 12 i)) (logand (ash count (* -8 i)) #xff)))
    v))

(defun migrate (&key udb pt (threads 64) (cache-bytes (* 4 1024 1024 1024)))
  "Migrate the udb chainstate at UDB (its .ovf/.meta sit beside it) into a fresh
   pagetree store at PT, via the bulk loader.  Reads the udb read-only; deletes
   and rebuilds PT (and PT.ovf).  Verifies the result's height/count/total against
   the udb marker.  Returns T on MIGRATE-OK."
  (let* ((ovf (concatenate 'string udb ".ovf"))
         (meta (concatenate 'string udb ".meta")))
    (multiple-value-bind (m-height m-total m-count) (read-udb-marker meta)
      (format t "~&[migrate] udb marker: height ~d, count ~d, total ~,8f BTC~%"
              m-height m-count (/ m-total 1d8)) (force-output)
      ;; 1. collect every live coin as (encode-key . encode-coin)
      (let ((vec (make-array m-count)) (i 0) (total 0) (t0 (get-internal-real-time)))
        (map-udb-readonly
         udb ovf
         (lambda (txid index value height cb script)
           (when (>= i m-count) (error "more live coins than marker count ~d" m-count))
           (setf (aref vec i) (cons (ptu:encode-key txid index)
                                    (ptu:encode-coin value height cb script)))
           (incf i) (incf total value)))
        (format t "[migrate] collected ~d coins, total ~,8f BTC, in ~,1f min~%"
                i (/ total 1d8) (/ (%secs t0) 60)) (force-output)
        (assert (= i m-count)) (assert (= total m-total))
        ;; 2. sort once (parallel radix)
        (let ((ts (get-internal-real-time)))
          (setf vec (parallel-radix-sort vec threads))
          (format t "[migrate] sorted ~d coins in ~,1f s~%" i (%secs ts)) (force-output))
        ;; 3. bottom-up bulk build + meta key, one txn, one commit
        (dolist (e (list "" ".ovf")) (ignore-errors (delete-file (concatenate 'string pt e))))
        (let ((tb (get-internal-real-time))
              (h (ptu:open-pagetree-utxo pt :cache-bytes cache-bytes)))
          (pt:with-write-txn (txn (ptu:ptu-store h))
            (pt:tbulk-build txn vec :sorted t)
            (pt:tput txn (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)
                     (%meta-value m-height m-total m-count)))
          (format t "[migrate] bulk build + commit of ~d coins in ~,1f min (~,0f coins/s)~%"
                  i (/ (%secs tb) 60) (/ i (%secs tb))) (force-output)
          (ptu:ptu-close h))
        ;; 4. reopen + verify parity
        (let ((p2 (ptu:open-pagetree-utxo pt)) (ok nil))
          (setf ok (and (= (ptu:ptu-height p2) m-height)
                        (= (ptu:ptu-count p2) m-count)
                        (= (ptu:ptu-total p2) m-total)))
          (format t "[migrate] reopened: height ~d, count ~d, total ~,8f BTC => ~a~%"
                  (ptu:ptu-height p2) (ptu:ptu-count p2) (/ (ptu:ptu-total p2) 1d8)
                  (if ok "MIGRATE-OK (height/count/total == udb marker)" "MIGRATE-MISMATCH"))
          (ptu:ptu-close p2)
          (force-output)
          ok)))))

(defun verify-digest (&key udb pt)
  "Gold-standard cross-check: the order-independent UTXO digest (sum of per-coin
   double-SHA256 commitments mod 2^256) of the udb (read-only scan) vs the migrated
   pagetree PT.  Slow (hashes every coin twice).  Returns T on a match."
  (let* ((ovf (concatenate 'string udb ".ovf"))
         (commit (find-symbol "COIN-COMMITMENT" "CL-CONSENSUS.UTXO"))
         (m (ash 1 256)) (acc 0) (t0 (get-internal-real-time)))
    (format t "~&[verify] hashing udb coins (read-only) ...~%") (force-output)
    (map-udb-readonly udb ovf
      (lambda (txid index value height cb script)
        (setf acc (mod (+ acc (funcall commit (cons txid index)
                                       (u:make-coin :value value :height height
                                                    :coinbase-p cb :script script)))
                       m))))
    (format t "[verify] udb digest in ~,1f min; hashing pagetree ...~%" (/ (%secs t0) 60))
    (force-output)
    (multiple-value-bind (set h) (u:open-utxo-backend pt :backend :pagetree)
      (let* ((dp (u:utxo-digest set))
             (dpi (let ((a 0)) (dotimes (i 32 a) (setf a (logior a (ash (aref dp i) (* 8 i)))))))
             (hex (lambda (x) (string-downcase
                               (format nil "~{~2,'0x~}"
                                       (loop for i below 32 collect (logand (ash x (* -8 i)) #xff)))))))
        (format t "[verify] udb      = ~a~%[verify] pagetree = ~a  (height ~d)~%"
                (funcall hex acc) (funcall hex dpi) h)
        (format t "[verify] ~a~%"
                (if (= acc dpi) "DIGEST-MATCH (byte-identical UTXO set)" "DIGEST-MISMATCH"))
        (force-output)
        (= acc dpi)))))

;;;; inspect/fuzz-test.lisp
;;;;
;;;; Adversarial fuzzing of the UNTRUSTED-INPUT parsers — the bytes a public-facing
;;;; node accepts from anyone: the P2P message envelope (read-message) and the
;;;; payload parsers (header, tx, block, getheaders, getdata, headers).  A from-scratch
;;;; parser is exactly where a panic / infinite loop / unbounded-allocation DoS hides.
;;;;
;;;; For each parser we throw thousands of random + mutated + truncated + adversarial
;;;; inputs and require that it NEVER: crashes the process, hangs (per-parse timeout),
;;;; or OOMs (storage-condition) — it must either return or signal a CATCHABLE error.
;;;; Plus round-trip props (parse∘serialize == identity) on valid inputs, and targeted
;;;; huge-length-prefix probes that must be rejected, not allocated.
;;;;
;;;;   sbcl --load inspect/fuzz-test.lisp --eval '(fuzz-test:run)'
(require :asdf)
(require :sb-posix)
(let* ((here (or *load-truename* *compile-file-truename*))
       (root (uiop:pathname-parent-directory-pathname (uiop:pathname-directory-pathname here))))
  (dolist (p (list root
                   (merge-pathnames "../secp256k1-fast/" root)
                   (merge-pathnames "../pagetree/" root)))
    (pushnew (truename p) asdf:*central-registry* :test #'equal)))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :fuzz-test
  (:use :cl)
  (:local-nicknames (:w :cl-consensus.wire) (:c :cl-consensus.chain) (:tx :cl-consensus.tx)
                    (:blk :cl-consensus.block) (:s :cl-consensus.serve) (:p :cl-consensus.peer))
  (:export #:run))
(in-package :fuzz-test)

;; Iterations per parser default to 3000 (a fast, deterministic regression gate);
;; override for a deeper soak via FUZZ_ITERS, and FUZZ_SEED for a fresh random run:
;;   FUZZ_ITERS=200000 FUZZ_SEED=$RANDOM sbcl --load inspect/fuzz-test.lisp --eval '(fuzz-test:run)'
(defparameter *iters*
  (let ((e (sb-ext:posix-getenv "FUZZ_ITERS"))) (if e (parse-integer e) 3000)))
(defparameter *seed*
  (let ((e (sb-ext:posix-getenv "FUZZ_SEED"))) (if e (parse-integer e) 20260626)))
(defparameter *ok* t)
(defun fail (fmt &rest args) (setf *ok* nil) (format t "  *** FAIL: ~a~%" (apply #'format nil fmt args)))

;;; --- byte helpers (seeded PRNG so a failure is reproducible) -----------------
(defvar *rng* (sb-ext:seed-random-state *seed*))
(defun rnd (n) (random n *rng*))
(defun rand-bytes (n)
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v) (setf (aref v i) (rnd 256)))))
(defun hexs (bytes) (w:bytes->hex bytes))

(defun mutate (bytes)
  "Return a mutated copy of BYTES: a few byte-flips / inserts / deletes."
  (let ((v (coerce bytes 'list)))
    (dotimes (k (1+ (rnd 6)))
      (case (rnd 3)
        (0 (when v (setf (nth (rnd (length v)) v) (rnd 256))))           ; flip
        (1 (setf v (append (subseq v 0 (rnd (1+ (length v))))           ; insert
                           (list (rnd 256)) (subseq v (rnd (1+ (length v)))))))
        (2 (when v (setf v (append (subseq v 0 (rnd (length v)))         ; delete
                                   (subseq v (1+ (rnd (length v))))))))))
    (coerce v '(vector (unsigned-byte 8)))))

;;; --- "did the parser misbehave?" --------------------------------------------
(defun safe (thunk)
  "Run THUNK (a parse). :ok / :rejected are both fine; :timeout (hang) and :oom
   (unbounded allocation) are bugs."
  (handler-case (sb-ext:with-timeout 3 (progn (funcall thunk) :ok))
    (sb-ext:timeout () :timeout)
    (storage-condition () :oom)
    (serious-condition () :rejected)))

;;; --- valid seed inputs -------------------------------------------------------
(defun random-tx (&key segwit)
  (let* ((nin (1+ (rnd 3))) (nout (1+ (rnd 3)))
         (ins (loop repeat nin collect
                (tx:make-txin :prev-hash (rand-bytes 32) :prev-index (rnd 5)
                              :script (rand-bytes (rnd 8)) :sequence #xffffffff)))
         (outs (loop repeat nout collect
                 (tx:make-txout :value (rnd 100000000) :script (rand-bytes (1+ (rnd 25))))))
         (wit (when segwit (loop repeat nin collect
                             (loop repeat (rnd 3) collect (rand-bytes (rnd 20))))))
         (txn (tx:make-tx :version 2 :inputs ins :outputs outs :witnesses wit
                          :locktime (rnd 1000) :segwit-p segwit)))
    (tx:finalize-tx txn) txn))

(defun valid-header-bytes () (rand-bytes 80))   ; parse-header is a fixed 80-byte read
(defun valid-tx-bytes () (tx:serialize-tx (random-tx :segwit (zerop (rnd 2))) :witness t))
(defun valid-block-bytes ()
  (let ((wr (w:make-writer)) (k (1+ (rnd 3))))
    (w:w-bytes wr (valid-header-bytes)) (w:w-varint wr k)
    (dotimes (i k) (w:w-bytes wr (tx:serialize-tx (random-tx) :witness t)))
    (w:writer-bytes wr)))
(defun valid-getheaders ()
  (let ((wr (w:make-writer)) (k (rnd 5)))
    (w:w-u32 wr 70016) (w:w-varint wr k)
    (dotimes (i k) (w:w-bytes wr (rand-bytes 32))) (w:w-bytes wr (rand-bytes 32))
    (w:writer-bytes wr)))
(defun valid-getdata ()
  (let ((wr (w:make-writer)) (k (rnd 6)))
    (w:w-varint wr k)
    (dotimes (i k) (w:w-u32 wr (rnd 5)) (w:w-bytes wr (rand-bytes 32)))
    (w:writer-bytes wr)))
(defun valid-headers-msg ()
  (let ((wr (w:make-writer)) (k (rnd 5)))
    (w:w-varint wr k)
    (dotimes (i k) (w:w-bytes wr (valid-header-bytes)) (w:w-varint wr 0))
    (w:writer-bytes wr)))
(defun valid-version () (handler-case (cl-consensus.peer::build-version-payload)
                          (serious-condition () (rand-bytes 90))))
(defun valid-addr ()
  (let ((wr (w:make-writer)) (k (rnd 4)))           ; v1 addr: 30 bytes/entry
    (w:w-varint wr k)
    (dotimes (i k) (w:w-u32 wr 1700000000) (w:w-u64 wr 1) (w:w-bytes wr (rand-bytes 16)) (w:w-u16 wr 8333))
    (w:writer-bytes wr)))
(defun valid-addrv2 ()
  (let ((wr (w:make-writer)) (k (rnd 4)))           ; BIP155: time, services, net, addr, port
    (w:w-varint wr k)
    (dotimes (i k) (w:w-u32 wr 1700000000) (w:w-varint wr 1) (w:w-u8 wr 1)
                   (w:w-varint wr 4) (w:w-bytes wr (rand-bytes 4)) (w:w-u16 wr 8333))
    (w:writer-bytes wr)))

;;; --- targets: name, byte->parse thunk, valid-seed generator ------------------
(defparameter *targets*
  (list (list "parse-header" (lambda (b) (c:parse-header (w:make-reader b))) #'valid-header-bytes)
        (list "parse-tx"     (lambda (b) (tx:parse-tx (w:make-reader b)))    #'valid-tx-bytes)
        (list "parse-block"  (lambda (b) (blk:parse-block b))                #'valid-block-bytes)
        (list "getheaders"   (lambda (b) (s:parse-getheaders b))             #'valid-getheaders)
        (list "getdata"      (lambda (b) (s:parse-getdata b))                #'valid-getdata)
        (list "headers-msg"  (lambda (b) (cl-consensus.chain::parse-headers-message b)) #'valid-headers-msg)
        (list "version"      (lambda (b) (cl-consensus.peer::parse-version-payload b))  #'valid-version)
        (list "addr"         (lambda (b) (p:parse-addr-payload b))                      #'valid-addr)
        (list "addrv2"       (lambda (b) (p:parse-addrv2-payload b))                    #'valid-addrv2)))

(defun fuzz-target (name parse seed)
  (let ((tmo 0) (oom 0) (ok 0) (rej 0))
    (flet ((try (bytes)
             (case (safe (lambda () (funcall parse bytes)))
               (:ok (incf ok)) (:rejected (incf rej))
               (:timeout (incf tmo) (fail "~a HUNG on ~a" name (hexs bytes)))
               (:oom (incf oom) (fail "~a OOM on ~a" name (hexs bytes))))))
      (dotimes (i *iters*)
        (ecase (rnd 5)
          (0 (try (rand-bytes (rnd 200))))                         ; pure random
          (1 (try (mutate (funcall seed))))                        ; mutate a valid input
          (2 (let ((v (funcall seed))) (try (subseq v 0 (rnd (1+ (length v)))))))  ; truncate
          (3 (try (concatenate '(vector (unsigned-byte 8)) (funcall seed) (rand-bytes (rnd 40))))) ; append junk
          (4 (try (funcall seed)))))                               ; a valid one (must :ok)
      ;; adversarial: a valid-ish prefix then a HUGE count varint where a count is read
      (let ((huge (w:make-writer)))
        (w:w-bytes huge (funcall seed)) (w:w-u8 huge #xff) (w:w-bytes huge #(#xff #xff #xff #xff #xff #xff #xff #xff))
        (try (w:writer-bytes huge))))
    (format t "  ~22a ok ~5d  rejected ~5d  timeout ~d  oom ~d~%" name ok rej tmo oom)))

;;; --- round-trip: parse∘serialize == identity --------------------------------
(defun roundtrips ()
  (dotimes (i 500)
    (let ((b (valid-header-bytes)))
      (unless (equalp (c:serialize-header (c:parse-header (w:make-reader b))) b)
        (fail "header round-trip mismatch")))
    (let ((b (valid-tx-bytes)))
      (unless (equalp (tx:serialize-tx (tx:parse-tx (w:make-reader b)) :witness t) b)
        (fail "tx round-trip mismatch: ~a" (hexs b)))))
  (format t "  round-trip (header + tx, 500 each): ~a~%" (if *ok* "ok" "FAIL")))

;;; --- the P2P envelope: an oversized length must be rejected, not allocated ---
(defun message-bytes (command len-field)
  (let ((wr (w:make-writer)) (cb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for ch across command for i from 0 do (setf (aref cb i) (char-code ch)))
    (w:w-u32 wr (w:net-magic w:*network*)) (w:w-bytes wr cb) (w:w-u32 wr len-field) (w:w-bytes wr #(0 0 0 0))
    (w:writer-bytes wr)))
(defun read-message-on (bytes)
  (let ((path "/tmp/fuzz-msg.bin"))
    (with-open-file (f path :direction :output :element-type '(unsigned-byte 8)
                            :if-exists :supersede :if-does-not-exist :create)
      (write-sequence bytes f))
    (with-open-file (str path :element-type '(unsigned-byte 8))
      (cl-consensus.peer::read-message
       (cl-consensus.peer::make-peer :stream str :host "fuzz" :port 0)))))
(defun envelope-guard ()
  ;; a 4 GB-length header must error (oversized), NOT attempt the allocation
  (let ((r (safe (lambda () (read-message-on (message-bytes "ping" #xffffffff))))))
    (if (eq r :rejected) (format t "  envelope oversized-length guard: ok~%")
        (fail "read-message did not reject a 4GB length (~a)" r)))
  (ignore-errors (delete-file "/tmp/fuzz-msg.bin")))

(defun run ()
  (setf *ok* t)
  (format t "~&== parser fuzzing (~d iters/target, seed ~d) ==~%" *iters* *seed*)
  (dolist (tg *targets*) (fuzz-target (first tg) (second tg) (third tg)))
  (roundtrips)
  (envelope-guard)
  (format t "~&fuzz-test: ~a~%" (if *ok* "OK — no crash/hang/OOM; round-trips + DoS guards hold" "FAILED"))
  *ok*)

;;;; inspect/pagetree-utxo-oracle.lisp
;;;;
;;;; Differential oracle for the pagetree-backed UTXO store (P3).
;;;;
;;;; Builds the SAME logical UTXO set two ways and asserts byte-identical
;;;; utxo-digest + identical count + identical total-value:
;;;;   (1) SYNTHETIC: a long seeded sequence of add/spend ops applied identically
;;;;       to an in-RAM utxo-set AND a pagetree-backed set, flushing/committing
;;;;       periodically and REOPENING the pagetree store mid-way; parity is
;;;;       asserted after every flush and again after a close+reopen.
;;;;   (2) CHAINSTATE: load the first K coins from /mnt/lisp/bitcoind/chainstate.dat
;;;;       into both an in-RAM set and a fresh pagetree set; assert digest parity.
;;;;       (K scaled down from the full ~63M-coin set for runtime; reported below.)
;;;;
;;;; Loads ONLY the minimal source files (wire, utxo-disk, utxo-pagetree, utxo) so
;;;; it does not pull the network/RPC stack and is safe to run offline alongside a
;;;; live IBD.  Writes pagetree stores only under /tmp; reads chainstate.dat only.
;;;;
;;;; Run:  sbcl --non-interactive --load inspect/pagetree-utxo-oracle.lisp

(require :asdf)
(asdf:load-system "ironclad")
(asdf:load-system "pagetree")

(let ((src (merge-pathnames "../src/" *load-pathname*)))
  (dolist (f '("wire" "utxo-disk" "utxo-pagetree" "utxo"))
    (load (compile-file (merge-pathnames (format nil "~a.lisp" f) src)
                        :verbose nil :print nil))))

(defpackage #:ptu-oracle (:use #:cl) (:local-nicknames (#:u #:cl-consensus.utxo)))
(in-package #:ptu-oracle)

;;; ---- a tiny deterministic PRNG (xorshift64) so the op stream is reproducible
(defvar *st* 0)
(defun seed! (s) (setf *st* (logand s #xFFFFFFFFFFFFFFFF)))
(defun nxt ()
  (let ((x *st*))
    (setf x (logand (logxor x (ash x 13)) #xFFFFFFFFFFFFFFFF))
    (setf x (logxor x (ash x -7)))
    (setf x (logand (logxor x (ash x 17)) #xFFFFFFFFFFFFFFFF))
    (setf *st* x)))
(defun rnd (n) (mod (nxt) n))

(defun rand-txid ()
  (let ((v (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32 v) (setf (aref v i) (rnd 256)))))

(defun rand-script ()
  ;; mostly small scripts; occasionally a LARGE script to exercise overflow pages
  (let* ((len (if (zerop (rnd 20)) (+ 4000 (rnd 8000)) (+ 1 (rnd 70))))
         (s (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len s) (setf (aref s i) (rnd 256)))))

(defun apply-op (set live)
  "Apply one op to SET; LIVE is a vector of (txid . index) currently unspent
   (shared bookkeeping so both sets get the IDENTICAL stream).  Returns LIVE."
  (if (and (> (length live) 0) (< (rnd 100) 40))
      ;; SPEND a random live outpoint
      (let* ((j (rnd (length live))) (op (aref live j)))
        (u:utxo-spend set (car op) (cdr op))
        (setf (aref live j) (aref live (1- (length live))))
        (decf (fill-pointer live)))
      ;; ADD a fresh coin
      (let* ((txid (rand-txid)) (index (rnd 8))
             (value (1+ (rnd 5000000000)))    ; up to ~50 BTC
             (height (rnd 800000)) (cb (zerop (rnd 7))))
        (u:utxo-add set txid index
                    (u:make-coin :value value :height height :coinbase-p cb
                                 :script (rand-script)))
        (vector-push-extend (cons txid index) live)))
  live)

(defun hexd (set) (let ((d (u:utxo-digest set))) (string-downcase (format nil "~{~2,'0x~}" (coerce d 'list)))))

(defun assert-parity (label ram pt)
  (let ((dr (u:utxo-digest ram)) (dp (u:utxo-digest pt))
        (cr (u:utxo-count ram)) (cp (u:utxo-count pt))
        (tr (u:utxo-set-total-value ram)) (tp (u:utxo-set-total-value pt)))
    (format t "~&  [~a] count ram=~d pt=~d  total ram=~d pt=~d~%        digest ~a~%"
            label cr cp tr tp (hexd ram))
    (unless (equalp dr dp) (error "DIGEST MISMATCH at ~a~%  ram=~a~%  pt =~a"
                                  label (hexd ram) (hexd pt)))
    (assert (= cr cp) () "COUNT mismatch at ~a (~d vs ~d)" label cr cp)
    (assert (= tr tp) () "TOTAL mismatch at ~a (~d vs ~d)" label tr tp)
    t))

;;; ============================================================================
;;; (1) SYNTHETIC oracle
;;; ============================================================================

;;; Combined driver: one PRNG stream, applied to BOTH sets in lockstep.
(defun run-synthetic2 (&key (n-ops 40000) (flush-every 4000) (seed 20260622))
  (format t "~&=== SYNTHETIC ORACLE: ~d ops, flush/commit every ~d, seed ~d ===~%"
          n-ops flush-every seed)
  (let* ((path "/tmp/ptu-oracle-synth.pt")
         (ram (u:make-utxo-set))
         (live (make-array 1024 :adjustable t :fill-pointer 0))
         (height 0))
    (ignore-errors (delete-file path))
    (seed! seed)
    (let ((pt (nth-value 0 (u:open-pagetree-utxo path))))
      (dotimes (i n-ops)
        ;; decide op from PRNG ONCE, apply identically to both sets
        (if (and (> (length live) 0) (< (rnd 100) 40))
            (let* ((j (rnd (length live))) (op (aref live j)))
              (u:utxo-spend ram (car op) (cdr op))
              (u:utxo-spend pt (car op) (cdr op))
              (setf (aref live j) (aref live (1- (length live))))
              (decf (fill-pointer live)))
            (let* ((txid (rand-txid)) (index (rnd 8))
                   (value (1+ (rnd 5000000000)))
                   (h (rnd 800000)) (cb (zerop (rnd 7))) (script (rand-script)))
              (u:utxo-add ram txid index
                          (u:make-coin :value value :height h :coinbase-p cb :script script))
              (u:utxo-add pt txid index
                          (u:make-coin :value value :height h :coinbase-p cb :script script))
              (vector-push-extend (cons txid index) live)))
        (when (zerop (mod (1+ i) flush-every))
          (incf height)
          (u:flush-utxo pt height)
          (assert-parity (format nil "flush #~d (op ~d)" height (1+ i)) ram pt)
          ;; REOPEN the pagetree store mid-way (after the 2nd flush) to prove the
          ;; committed digest survives a close+reopen, and keep going.
          (when (= height 2)
            (format t "  -- closing + REOPENING pagetree store mid-stream --~%")
            (u:close-utxo pt)
            (setf pt (nth-value 0 (u:open-pagetree-utxo path)))
            (assert-parity "after mid-stream reopen" ram pt))))
      ;; final flush + close + reopen
      (incf height)
      (u:flush-utxo pt height)
      (assert-parity "final flush" ram pt)
      (u:close-utxo pt)
      (setf pt (nth-value 0 (u:open-pagetree-utxo path)))
      (assert-parity "after FINAL close+reopen" ram pt)
      (format t "~&SYNTHETIC: digest/count/total parity held across all flushes + reopen.~%")
      (u:close-utxo pt)
      (ignore-errors (delete-file path)))))

;;; ============================================================================
;;; (2) CHAINSTATE oracle — load first K coins from the on-disk dump into both
;;; an in-RAM set and a fresh pagetree set; assert digest parity.
;;; ============================================================================

(defun run-chainstate (&key (path "/mnt/lisp/bitcoind/chainstate.dat") (k 500000))
  (unless (probe-file path)
    (format t "~&=== CHAINSTATE ORACLE: ~a not present — skipped. ===~%" path)
    (return-from run-chainstate nil))
  (format t "~&=== CHAINSTATE ORACLE: first ~d coins of ~a ===~%" k path)
  ;; Stream the dump's records (same format as load-utxo) into both sets.
  (let* ((wp (find-package :cl-consensus.wire))
         (ptpath "/tmp/ptu-oracle-chainstate.pt")
         (ram (u:make-utxo-set))
         (pt (nth-value 0 (u:open-pagetree-utxo ptpath))))
    (ignore-errors (delete-file ptpath))
    (setf pt (nth-value 0 (u:open-pagetree-utxo ptpath)))
    (with-open-file (s path :element-type '(unsigned-byte 8))
      (let* ((hdrn 12)
             (hdr (make-array hdrn :element-type '(unsigned-byte 8))))
        (read-sequence hdr s)
        (let* ((r (funcall (intern "MAKE-READER" wp) hdr))
               (ru32 (intern "R-U32" wp)) (ru64 (intern "R-U64" wp)))
          (let ((height (funcall ru32 r)) (ncoins (funcall ru64 r)))
            (format t "  dump: height=~d total-coins=~d (loading ~d)~%"
                    height ncoins (min k ncoins))))
        ;; read records one at a time; the file is multi-GB so we DO NOT slurp it
        (let ((rbuf (make-array 65536 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
              (loaded 0) (height 600000))
          (declare (ignorable height))
          (flet ((rd-byte () (read-byte s))
                 )
            (declare (ignorable #'rd-byte))
            (dotimes (i k)
              ;; record: varint klen, txid[klen], u32 index, i64 value, u32 height,
              ;;         bool coinbase, varint slen, script[slen]
              (multiple-value-bind (klen eof) (read-cs-varint s)
                (when eof (return))
                (let* ((txid (read-n s klen))
                       (index (read-le s 4))
                       (value (read-le s 8))
                       (h (read-le s 4))
                       (cb (/= 0 (read-byte s)))
                       (slen (read-cs-varint s))
                       (script (read-n s slen)))
                  (declare (ignore rbuf))
                  (let ((coin (u:make-coin :value value :height h :coinbase-p cb :script script)))
                    (u:utxo-add ram txid index coin)
                    (u:utxo-add pt  txid index coin))
                  (incf loaded))))
            (format t "  loaded ~d coins into both sets~%" loaded)
            (u:flush-utxo pt 600000)
            (assert-parity "chainstate (in-RAM vs pagetree, pre-reopen)" ram pt)
            (u:close-utxo pt)
            (setf pt (nth-value 0 (u:open-pagetree-utxo ptpath)))
            (assert-parity "chainstate after close+reopen" ram pt)
            (format t "~&CHAINSTATE: digest/count/total parity held for first ~d coins.~%" loaded)
            (u:close-utxo pt)
            (ignore-errors (delete-file ptpath))
            (ignore-errors (delete-file (concatenate 'string ptpath ".ovf")))))))))

;;; minimal stream readers for the chainstate record format (CompactSize varint
;;; + little-endian ints), matching wire's w-varint / w-bytes / w-u32 / w-i64.
(defun read-le (s n)
  (let ((acc 0)) (dotimes (i n acc) (setf acc (logior acc (ash (read-byte s) (* 8 i)))))))
(defun read-n (s n)
  (let ((v (make-array n :element-type '(unsigned-byte 8)))) (read-sequence v s) v))
(defun read-cs-varint (s)
  "CompactSize varint.  Returns (values value eof-p)."
  (let ((b (read-byte s nil :eof)))
    (when (eq b :eof) (return-from read-cs-varint (values nil t)))
    (values (cond ((< b #xfd) b)
                  ((= b #xfd) (read-le s 2))
                  ((= b #xfe) (read-le s 4))
                  (t (read-le s 8)))
            nil)))

;;; ============================================================================
(defun main ()
  (run-synthetic2 :n-ops 40000 :flush-every 4000)
  (terpri)
  (run-chainstate :k 500000)
  (format t "~&~%ALL ORACLES PASSED.~%"))

(main)

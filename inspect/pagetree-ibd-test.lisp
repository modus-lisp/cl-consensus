;;;; inspect/pagetree-ibd-test.lisp
;;;;
;;;; End-to-end, on the REAL chain, proof that the pagetree UTXO backend
;;;; behaves identically to the mmap "udb" backend under real CONNECT-BLOCK.
;;;;
;;;; Approach: from GENESIS, download blocks 1..H from the local full node
;;;; (epyc-docker.lan:8333) ONCE per batch and connect each block — same blocks,
;;;; same order — onto TWO freshly-created UTXO sets in lockstep:
;;;;   (a) a PAGETREE-backed set   (the new backend being proven)
;;;;   (b) a UDB-backed set        (the existing mmap backend, the reference)
;;;; Both go through the SAME connect-block consensus code (the backend is
;;;; meant to be transparent).  At H we flush+save+close BOTH (exercising the
;;;; checkpoint/flush/close path for each), reopen, and assert that
;;;;   utxo-digest  AND  utxo-set-total-value  AND  utxo-count
;;;; are byte-identical between the two backends.
;;;;
;;;; assumevalid: scripts below H are NOT re-verified (we are proving UTXO-set
;;;; equivalence, not re-checking scripts).  Every other consensus rule and the
;;;; full UTXO mutation pass still run identically for both backends.
;;;;
;;;; All test stores live under /mnt/lisp/pttest/ (created here, cleaned at end).
;;;; The live IBD's files under /mnt/lisp/bitcoind/ are NEVER written (headers.dat
;;;; is read-only-loaded).
;;;;
;;;; Run:
;;;;   sbcl --dynamic-space-size 16384 --non-interactive \
;;;;        --load inspect/pagetree-ibd-test.lisp [--eval '(pt-ibd:main :to 150000)']

(require :asdf)
;; cl-consensus + its deps (pagetree, secp256k1-fast) are on the asdf
;; source-registry tree under /home/claude/; just load the system.
(asdf:load-system "cl-consensus")

(defpackage #:pt-ibd
  (:use #:cl)
  (:local-nicknames (#:u  #:cl-consensus.utxo)
                    (#:c  #:cl-consensus.chain)
                    (#:p  #:cl-consensus.peer)
                    (#:blk #:cl-consensus.block)
                    (#:v  #:cl-consensus.validate)
                    (#:w  #:cl-consensus.wire))
  (:export #:main))
(in-package #:pt-ibd)

(defparameter *testdir* "/mnt/lisp/pttest/")
(defparameter *peer-host* "epyc-docker.lan")

(defun hexd (set)
  (string-downcase (format nil "~{~2,'0x~}" (coerce (u:utxo-digest set) 'list))))

;;; -- on-disk size of a store's file set (sum of all path.* siblings) ----------
(defun file-size (path) (if (probe-file path) (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s)) 0))

(defun du-bytes (path)
  "Allocated (real) bytes on disk for PATH — `du -B1` reports BLOCKS ACTUALLY
   ALLOCATED (sparse holes excluded), so this is the TRUE space cost (the udb is
   a sparse mmap whose apparent size is its full capacity)."
  (let ((o (with-output-to-string (s)
             (sb-ext:run-program "du" (list "-B1" (namestring path))
                                 :search t :output s :error nil :wait t))))
    (ignore-errors (parse-integer (subseq o 0 (position #\Tab o))))))

(defun store-disk-bytes (paths)
  "Sum of allocated on-disk bytes across a backend's file set."
  (reduce #'+ (mapcar (lambda (p) (or (du-bytes p) 0)) paths) :initial-value 0))

(defun rm-f (&rest paths)
  (dolist (p paths) (ignore-errors (delete-file p))))

;;; ----------------------------------------------------------------------------
;;; The shared connect loop: download each batch ONCE, connect to BOTH sets.
;;; ----------------------------------------------------------------------------
(defun connect-both (peer pt udb &key (from 1) (to 150000) (batch 200)
                                      (progress-every 10000))
  (let ((t0 (get-internal-real-time)) (height from))
    (loop while (<= height to) do
      (let* ((hi (min to (+ height batch -1)))
             (hashes (loop for h from height to hi
                           collect (c:header-hash (c:header-at-height h))))
             (blocks (blk:get-blocks peer hashes :timeout 30 :retries 6)))
        (loop for b across blocks
              for h from height do
          (unless b (error "peer did not return block ~d" h))
          ;; structural checks run once inside connect-block (skip-structural nil);
          ;; below H we skip script verification (assumevalid).  Identical args to
          ;; both backends so the only difference is the UTXO store.
          (v:connect-block b h pt  :verify-scripts nil)
          (v:connect-block b h udb :verify-scripts nil)
          (when (zerop (mod h progress-every))
            (let ((secs (/ (- (get-internal-real-time) t0) internal-time-units-per-second)))
              (format t "~&[ibd] h=~d  pt{utxos=~d total=~,4f}  udb{utxos=~d total=~,4f}  ~,0f blk/s~%"
                      h (u:utxo-count pt) (/ (u:utxo-set-total-value pt) 1d8)
                      (u:utxo-count udb) (/ (u:utxo-set-total-value udb) 1d8)
                      (if (plusp secs) (/ (- h from -1) secs) 0))
              (force-output))))
        (setf height (1+ hi))))))

;;; ----------------------------------------------------------------------------
(defun main (&key (to 150000) (batch 200))
  (ensure-directories-exist *testdir*)
  (let* ((pt-path  (concatenate 'string *testdir* "pt-chainstate.pt"))
         (udb-path (concatenate 'string *testdir* "udb-chainstate.udb"))
         (udb-meta (concatenate 'string udb-path ".meta"))
         (udb-ovf  (concatenate 'string udb-path ".ovf"))
         (udb-wal  (concatenate 'string udb-path ".wal"))
         (udb-lock (concatenate 'string udb-path ".lock")))
    ;; fresh stores
    (apply #'rm-f pt-path udb-path udb-meta udb-ovf udb-wal udb-lock nil)
    (format t "~&=== PAGETREE vs UDB — REAL IBD equivalence, genesis..~d ===~%" to)
    (format t "test stores under ~a (cleaned at end); peer ~a:8333~%~%" *testdir* *peer-host*)

    ;; headers (read-only load of the existing headers.dat in data-dir)
    (let ((nh (c:load-headers)))
      (when (< (c:tip-height) to)
        (error "headers only reach height ~d (< requested ~d); need more headers.dat"
               (c:tip-height) to))
      (format t "[chain] header tip ~d (loaded ~d)~%" (c:tip-height) nh))

    ;; smaller udb capacity for a test set (a full 500M-slot capacity is a 64GB
    ;; sparse file — fine, but a tighter capacity keeps the .udb apparent size sane
    ;; while staying well above the H-block live coin count).  ~4M slots @ 128B.
    (let* ((udb-cap 4000037)
           (pt (nth-value 0 (u:open-pagetree-utxo pt-path)))
           (udb (nth-value 0 (u:open-disk-utxo udb-path udb-cap)))
           (peer (p:connect-peer *peer-host* :timeout 20)))
      (format t "[peer] connected to ~a (height ~d, ~a)~%~%"
              (p:peer-addr peer) (p:peer-height peer) (p:peer-subver peer))
      (unwind-protect
        (progn
          (connect-both peer pt udb :from 1 :to to :batch batch)

          ;; ---- in-memory (pre-flush) parity at H -----------------------------
          (let ((dpt (hexd pt)) (dudb (hexd udb)))
            (format t "~&~%--- AT HEIGHT ~d (in-memory, staging not yet flushed) ---~%" to)
            (format t "  pagetree:  count=~d  total=~d sat (~,8f BTC)  digest=~a~%"
                    (u:utxo-count pt) (u:utxo-set-total-value pt)
                    (/ (u:utxo-set-total-value pt) 1d8) dpt)
            (format t "  udb     :  count=~d  total=~d sat (~,8f BTC)  digest=~a~%"
                    (u:utxo-count udb) (u:utxo-set-total-value udb)
                    (/ (u:utxo-set-total-value udb) 1d8) dudb))

          ;; ---- exercise the CHECKPOINT path for BOTH (flush+save+close) -------
          ;; save-utxo routes both backends through flush-utxo (the fix); this is
          ;; exactly what connect-block's checkpoint barrier calls.
          (u:save-utxo pt  pt-path  to)
          (u:save-utxo udb udb-path to)
          (u:close-utxo pt)
          (u:close-utxo udb)
          (format t "~&[flush] both backends flushed + closed at height ~d~%" to)

          ;; ---- on-disk sizes (post-flush, while closed) ----------------------
          (let* ((pt-bytes  (store-disk-bytes (list pt-path)))
                 (udb-bytes (store-disk-bytes (list udb-path udb-ovf)))
                 (pt-app    (file-size pt-path))
                 (udb-app   (+ (file-size udb-path) (file-size udb-ovf))))

            ;; ---- REOPEN both and assert committed parity ---------------------
            (multiple-value-bind (pt2 pth) (u:open-pagetree-utxo pt-path)
              (multiple-value-bind (udb2 udbh) (u:open-disk-utxo udb-path udb-cap)
                (let* ((dpt (hexd pt2)) (dudb (hexd udb2))
                       (cpt (u:utxo-count pt2)) (cudb (u:utxo-count udb2))
                       (tpt (u:utxo-set-total-value pt2)) (tudb (u:utxo-set-total-value udb2))
                       (digest-ok (string= dpt dudb))
                       (count-ok  (= cpt cudb))
                       (total-ok  (= tpt tudb))
                       (parity    (and digest-ok count-ok total-ok)))
                  (format t "~&~%=== REOPENED FROM DISK — committed-set parity at H=~d ===~%" to)
                  (format t "  pagetree (reopened @ height ~d):~%" pth)
                  (format t "    count = ~d~%    total = ~d sat (~,8f BTC)~%    digest= ~a~%"
                          cpt tpt (/ tpt 1d8) dpt)
                  (format t "  udb      (reopened @ height ~d):~%" udbh)
                  (format t "    count = ~d~%    total = ~d sat (~,8f BTC)~%    digest= ~a~%"
                          cudb tudb (/ tudb 1d8) dudb)
                  (format t "~&  digest match: ~a   count match: ~a   total match: ~a~%"
                          digest-ok count-ok total-ok)
                  (format t "~&  >>> PARITY VERDICT: ~a <<<~%"
                          (if parity "PASS — pagetree == udb (byte-identical)" "FAIL"))

                  ;; ---- bytes/coin -----------------------------------------------
                  (format t "~&~%=== ON-DISK SIZE @ H=~d (UTXO set built by REAL IBD) ===~%" to)
                  (format t "  live coins at H: ~d~%" cpt)
                  (format t "  pagetree:  allocated ~d B (~,2f MiB)  apparent ~d B  =>  ~,2f bytes/coin~%"
                          pt-bytes (/ pt-bytes 1048576d0) pt-app
                          (if (plusp cpt) (/ pt-bytes cpt) 0))
                  (format t "  udb     :  allocated ~d B (~,2f MiB)  apparent ~d B  =>  ~,2f bytes/coin~%"
                          udb-bytes (/ udb-bytes 1048576d0) udb-app
                          (if (plusp cudb) (/ udb-bytes cudb) 0))
                  (format t "  (udb is a sparse mmap: allocated = touched pages; apparent = capacity-sized file)~%")
                  (format t "  pagetree is ~,2fx the udb allocated size~%"
                          (if (plusp udb-bytes) (/ (float pt-bytes) udb-bytes) 0))

                  (u:close-utxo pt2)
                  (u:close-utxo udb2)

                  ;; ---- cleanup --------------------------------------------------
                  (apply #'rm-f pt-path udb-path udb-meta udb-ovf udb-wal udb-lock nil)
                  (ignore-errors
                    (sb-ext:run-program "find" (list *testdir* "-maxdepth" "1" "-type" "f"
                                                     "-name" "udb-chainstate*" "-delete")
                                        :search t :wait t))
                  (format t "~&[cleanup] removed test stores under ~a~%" *testdir*)

                  (unless parity (sb-ext:exit :code 1))
                  parity)))))
        (ignore-errors (p:disconnect peer))))))

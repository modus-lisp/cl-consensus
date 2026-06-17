;;;; inspect/bench.lisp
;;;;
;;;; Micro-benchmark the consensus hot paths to test the assumption that pure-Lisp
;;;; crypto is the IBD bottleneck, and to estimate IBD throughput.
;;;;
;;;;   sbcl --load inspect/bench.lisp --eval '(btc-bench:run)'

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (pushnew (uiop:pathname-parent-directory-pathname
            (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
           asdf:*central-registry* :test #'equal)
  (asdf:load-system "cl-consensus"))

(defpackage #:btc-bench
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:ec #:cl-consensus.crypto.secp256k1)
                    (#:sch #:cl-consensus.crypto.schnorr))
  (:export #:run #:estimate-ibd))

(in-package #:btc-bench)

(defun fmt-duration (secs)
  (cond ((< secs 90) (format nil "~,1f s" secs))
        ((< secs 5400) (format nil "~,1f min" (/ secs 60)))
        ((< secs 172800) (format nil "~,1f hours" (/ secs 3600)))
        (t (format nil "~,1f days" (/ secs 86400)))))

(defun estimate-ibd (&key (verify/s 43.5) (sigs 2.5d9) (cores 116) (efficiency 0.85))
  "Estimate full-verify IBD time (script-verify every signature in the chain).
   SIGS = total signature verifications chain-wide (~2.5e9 by mid-2026, approx).
   CORES * EFFICIENCY = effective parallel speedup (verification is per-input
   independent, so it scales near-linearly)."
  (format t "~&==== full-verify IBD estimate ====~%")
  (format t "  assumptions: ~,2e signature verifications chain-wide,~%" sigs)
  (format t "               ~,1f ECDSA verify/s per core, ~d cores @ ~d% efficiency~%~%"
          verify/s cores (round (* 100 efficiency)))
  (let ((single (/ sigs verify/s))
        (multi  (/ sigs (* verify/s cores efficiency))))
    (format t "  single-core full verify : ~a~%" (fmt-duration single))
    (format t "  ~d-core full verify     : ~a~%" cores (fmt-duration multi))
    (format t "~%  with assumevalid (Core's default — skip script checks below a~%")
    (format t "  known-good block): signature cost ~~0; IBD becomes I/O + UTXO + hash~%")
    (format t "  bound (hashing alone for ~~600 GB @ 115 MiB/s ~~ ~a).~%"
            (fmt-duration (/ (* 600 1024) 115)))
    (values single multi)))

(defun secs (thunk reps)
  "Run THUNK REPS times; return seconds elapsed (wall, via internal-run-time)."
  (let ((start (get-internal-run-time)))
    (dotimes (i reps) (funcall thunk))
    (/ (float (- (get-internal-run-time) start))
       internal-time-units-per-second)))

(defun bench (label reps thunk)
  (let* ((s (secs thunk reps))
         (per (/ s reps)))
    (format t "  ~22a ~8,1f op/s   (~,3f ms/op, ~d reps, ~,2fs)~%"
            label (/ reps s) (* 1000 per) reps s)
    (/ reps s)))

(defun run (&key (ecdsa-reps 200) (schnorr-reps 200))
  (ec:secp-init)
  (format t "~&==== cl-consensus crypto / consensus micro-benchmark ====~%")
  (format t "SBCL ~a~%~%" (lisp-implementation-version))

  ;; ---- primitives -----------------------------------------------------------
  (format t "primitives:~%")
  (let* ((a (1+ (random (1- ec:*secp256k1-p*))))
         (b (1+ (random (1- ec:*secp256k1-p*)))))
    (bench "field mul (mod p)" 2000000 (lambda () (ec:secp-mul a b)))
    (bench "field inverse" 20000 (lambda () (ec:secp-inv a))))
  (let ((k (1+ (random (1- ec:*secp256k1-n*)))) (g (ec:secp-generator)))
    (bench "scalar mult k*G" 200 (lambda () (ec:secp-mul-point k g))))

  ;; ---- hashing ---------------------------------------------------------------
  (format t "~%hashing:~%")
  (let ((buf (make-array (* 1024 1024) :element-type '(unsigned-byte 8) :initial-element 7)))
    (let ((r (bench "sha256 (1 MiB)" 200 (lambda () (w:sha256 buf)))))
      (format t "  -> ~,1f MiB/s~%" r)))
  (let ((small (make-array 64 :element-type '(unsigned-byte 8) :initial-element 3)))
    (bench "hash256 (64 B)" 200000 (lambda () (w:hash256 small))))

  ;; ---- ECDSA -----------------------------------------------------------------
  (format t "~%ECDSA (secp256k1):~%")
  (let* ((priv (1+ (random (1- ec:*secp256k1-n*))))
         (pub (ec:secp-pubkey priv))
         (hash (w:hash256 (ironclad:ascii-string-to-byte-array "benchmark message")))
         (sig (multiple-value-list (ec:ecdsa-sign-raw priv hash)))
         (r (first sig)) (s (second sig)))
    (bench "ecdsa-verify" ecdsa-reps (lambda () (ec:ecdsa-verify pub hash r s)))
    (values))

  ;; ---- Schnorr (BIP340 / taproot) -------------------------------------------
  (format t "~%Schnorr (BIP340):~%")
  (let* ((priv (sch:tagged-hash "x" (ironclad:ascii-string-to-byte-array "k")))
         (d (1+ (mod (ec:bytes-to-int priv) (1- ec:*secp256k1-n*))))
         (px (ec:int-to-bytes32 (car (ec:secp-pubkey d))))
         (msg (w:sha256 (ironclad:ascii-string-to-byte-array "schnorr bench")))
         (sig (sch:schnorr-sign d msg)))
    (bench "schnorr-verify" schnorr-reps (lambda () (sch:schnorr-verify px msg sig))))

  (format t "~%(see estimate-ibd for what this means for sync)~%"))

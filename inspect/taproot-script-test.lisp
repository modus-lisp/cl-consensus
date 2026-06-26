;;;; inspect/taproot-script-test.lisp
;;;;
;;;; Gate for BIP341 taproot SCRIPT-PATH spending (single tapleaf, leaf 0xc0,
;;;; script = <xonly> OP_CHECKSIG).
;;;;
;;;; Picks a leaf private key, derives its x-only pubkey, builds the leaf script
;;;; and the taproot output spk, then builds + signs a script-path spend of a
;;;; synthetic prevout carrying that spk and asserts it VERIFIES under our
;;;; Core-differential-tested interpreter.
;;;;
;;;;   sbcl --non-interactive --load inspect/taproot-script-test.lisp \
;;;;        --eval '(taproot-script-test:run)'
(require :asdf)
;; NB: register THIS worktree's repo root (run pwd), not /home/claude/cl-consensus.
(pushnew (truename (merge-pathnames "../" (directory-namestring *load-pathname*)))
         asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :taproot-script-test
  (:use :cl)
  (:local-nicknames (:w :cl-consensus.wire) (:tx :cl-consensus.tx)
                    (:s :cl-consensus.script) (:tps :cl-consensus.taproot-script)
                    (:secp :secp256k1-fast) (:sch :secp256k1-fast.schnorr))
  (:export #:run))
(in-package :taproot-script-test)

(defparameter *ok* t)
(defun checkt (name cond) (if cond
                              (format t "  ok   ~a~%" name)
                              (progn (setf *ok* nil) (format t "  *** FAIL ~a~%" name))))
(defun hx (s) (w:hex->bytes s))

(defun run ()
  (setf *ok* t)
  (let* (;; leaf private key (the script's x-only pubkey must correspond to it)
         (leaf-priv (secp:bytes-to-int
                     (hx "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef")))
         (internal-xonly (sch:pubkey-xonly leaf-priv))
         (leaf-script (tps:checksig-leaf-script internal-xonly)))
    ;; leaf script is exactly 0x20 || xonly || 0xac (34 bytes)
    (checkt "leaf script = 0x20 || xonly || 0xac"
            (and (= (length leaf-script) 34)
                 (= (aref leaf-script 0) #x20)
                 (equalp (subseq leaf-script 1 33) internal-xonly)
                 (= (aref leaf-script 33) #xac)))
    ;; build the output spk + Q parity
    (multiple-value-bind (spk q-parity) (tps:taproot-output-spk internal-xonly leaf-script)
      (checkt "spk is OP_1 0x20 Qx (34 bytes)"
              (and (= (length spk) 34) (= (aref spk 0) #x51) (= (aref spk 1) #x20)))
      (checkt "q-parity is a bit" (member q-parity '(0 1)))
      ;; control block is exactly 33 bytes, control byte = 0xc0 | parity
      (let ((ctrl (tps:control-block internal-xonly q-parity)))
       (checkt "control block is 33 bytes" (= (length ctrl) 33))
       (checkt "control byte = 0xc0 | parity" (= (aref ctrl 0) (logior #xc0 q-parity)))
       (checkt "control carries internal x-only key"
               (equalp (subseq ctrl 1 33) internal-xonly))
      ;; ---- build + sign a script-path spend of a synthetic prevout ----
      (let* ((amount 1000000)
             (prev-txid (hx "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
             (txn (tps:build-script-path-spend prev-txid 0 amount spk leaf-priv)))
        ;; witness layout = [signature, leaf-script, control-block]
        (let ((wit (first (tx:tx-witnesses txn))))
          (checkt "witness has 3 items" (= (length wit) 3))
          (checkt "witness[0] = 64-byte schnorr sig" (= (length (first wit)) 64))
          (checkt "witness[1] = leaf script" (equalp (second wit) leaf-script))
          (checkt "witness[2] = control block" (equalp (third wit) ctrl)))
        ;; THE GATE: it must verify under our interpreter
        (handler-case
            (checkt "script-path spend VERIFIES"
                    (s:verify-input txn 0 spk amount
                                    :prevouts (vector (cons amount spk))))
          (s:script-error (e)
            (setf *ok* nil) (format t "  *** verify raised: ~a~%" e)))))))
  ;; ==========================================================================
  ;; Multi-leaf taptrees: 2 leaves and 3 leaves, DISTINCT key per leaf, spend
  ;; EACH leaf in turn and assert every script-path spend verifies.
  ;; ==========================================================================
  (let* ((leaf-privs (mapcar (lambda (h) (secp:bytes-to-int (hx h)))
                             '("0000000000000000000000000000000000000000000000000000000000000003"
                               "0000000000000000000000000000000000000000000000000000000000000005"
                               "0000000000000000000000000000000000000000000000000000000000000007")))
         ;; internal key distinct from every leaf key
         (internal-priv (secp:bytes-to-int
                         (hx "00000000000000000000000000000000000000000000000000000000000000aa")))
         (internal-xonly (sch:pubkey-xonly internal-priv))
         (leaf-scripts (mapcar (lambda (lp) (tps:checksig-leaf-script (sch:pubkey-xonly lp)))
                               leaf-privs))
         (amount 1000000)
         (prev-txid (hx "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")))
    (flet ((spend-each (label scripts privs n-leaves expected-depths)
             ;; expected-depths: per-leaf control-path sibling count for the shape.
             (multiple-value-bind (spk q-parity)
                 (tps:taproot-output-spk internal-xonly scripts)
               (declare (ignore q-parity))
               (checkt (format nil "~a: spk is OP_1 0x20 Qx" label)
                       (and (= (length spk) 34) (= (aref spk 0) #x51) (= (aref spk 1) #x20)))
               (dotimes (li n-leaves)
                 (let* ((path (tps:taptree-leaf-path scripts li))
                        (txn (tps:build-script-path-spend
                              prev-txid 0 amount spk (nth li privs)
                              :leaf-scripts scripts :leaf-index li
                              :internal-priv internal-priv)))
                   (checkt (format nil "~a leaf ~d: path depth = ~d"
                                   label li (nth li expected-depths))
                           (= (length path) (nth li expected-depths)))
                   (let* ((wit (first (tx:tx-witnesses txn)))
                          (ctrl (third wit)))
                     (checkt (format nil "~a leaf ~d: witness has 3 items" label li)
                             (= (length wit) 3))
                     (checkt (format nil "~a leaf ~d: leaf script revealed" label li)
                             (equalp (second wit) (nth li scripts)))
                     (checkt (format nil "~a leaf ~d: control block = 33 + 32*depth" label li)
                             (= (length ctrl) (+ 33 (* 32 (nth li expected-depths)))))
                     (checkt (format nil "~a leaf ~d: control carries internal key" label li)
                             (equalp (subseq ctrl 1 33) internal-xonly)))
                   (handler-case
                       (checkt (format nil "~a leaf ~d: script-path spend VERIFIES" label li)
                               (s:verify-input txn 0 spk amount
                                               :prevouts (vector (cons amount spk))))
                     (s:script-error (e)
                       (setf *ok* nil)
                       (format t "  *** ~a leaf ~d verify raised: ~a~%" label li e))))))))
      ;; 2-leaf balanced tree: root = TapBranch(L0,L1); both leaves at depth 1.
      (spend-each "2-leaf" (subseq leaf-scripts 0 2) leaf-privs 2 '(1 1))
      ;; 3-leaf balanced (documented shape): L0,L1 at depth 2; L2 at depth 1.
      (spend-each "3-leaf" leaf-scripts leaf-privs 3 '(2 2 1))))
  (format t "~&taproot-script-test: ~a~%"
          (if *ok* "OK — single-leaf + 2-leaf + 3-leaf taptree script-path spends all verify"
              "FAILED"))
  *ok*)

;;;; src/taproot-script.lisp
;;;;
;;;; BIP341 taproot SCRIPT-PATH spending — an N-leaf taptree.
;;;;
;;;; Key-path taproot already lives in wallet.lisp (taproot-output-key/-tweak,
;;;; sign-input :p2tr).  This module is the script-path analog: an output that
;;;; commits to a taptree, spent by REVEALING a chosen leaf script, satisfying
;;;; it, and supplying a control block whose merkle path proves the leaf is in
;;;; the committed tree.
;;;;
;;;; Leaf scope: leaf-version 0xc0, script = <32-byte x-only pubkey> OP_CHECKSIG
;;;; (bytes: 0x20 || xonly || 0xac).  Each leaf may carry a DISTINCT key.
;;;;
;;;; Tree shape (deterministic, documented):  a BALANCED tree built bottom-up by
;;;; pairing the leaf list left-to-right.  Each level pairs adjacent nodes
;;;; (0,1),(2,3),...; an odd trailing node is carried up UNPAIRED to the next
;;;; level (no duplication — BIP341 has no "duplicate last" rule; a lone node
;;;; simply becomes its parent).  Repeat until one node remains: the merkle root.
;;;;
;;;;   1 leaf  : root = tapleaf, depth 0 (no path; control block = 33 bytes)
;;;;   2 leaves: root = TapBranch(L0,L1), each at depth 1
;;;;   3 leaves: lvl1 = [B(L0,L1), L2]; root = TapBranch(B(L0,L1), L2)
;;;;             L0,L1 at depth 2 ; L2 at depth 1
;;;;
;;;; The control block's merkle path is the ordered list of SIBLING hashes from
;;;; the chosen leaf up to the root — exactly what verify-tapscript folds (it
;;;; lexicographically sorts (current, sibling) before each TapBranch hash).
;;;;
;;;; Success bar: a spend built here VERIFIES under cl-consensus.script:verify-input,
;;;; whose tapscript path is already differential-tested to 0 divergence vs Core.

(defpackage #:cl-consensus.taproot-script
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script)
                    (#:secp #:secp256k1-fast) (#:sch #:secp256k1-fast.schnorr))
  (:export
   #:tapleaf-hash #:tapbranch-hash #:checksig-leaf-script
   #:build-taptree #:taptree-root #:taptree-leaf-path
   #:taproot-output-spk #:control-block
   #:build-script-path-spend))

(in-package #:cl-consensus.taproot-script)

(defconstant +tapscript-leaf-version+ #xc0
  "BIP342 tapscript leaf version (the only one we execute).")

(defun cat (&rest seqs)
  "Concatenate byte sequences into a fresh (unsigned-byte 8) vector."
  (apply #'concatenate '(vector (unsigned-byte 8)) seqs))

(defun compact-size (n)
  "Bitcoin CompactSize (varint) bytes for N."
  (let ((wr (w:make-writer))) (w:w-varint wr n) (w:writer-bytes wr)))

(defun lex<= (a b)
  "Lexicographic compare of two equal-length byte vectors:  a <= b ?"
  (dotimes (i (min (length a) (length b)) (<= (length a) (length b)))
    (let ((x (aref a i)) (y (aref b i)))
      (cond ((< x y) (return t)) ((> x y) (return nil))))))

;;; ----------------------------------------------------------------------------
;;; Leaf script + tapleaf hash + tapbranch hash
;;; ----------------------------------------------------------------------------

(defun checksig-leaf-script (xonly)
  "The leaf script <32-byte x-only pubkey> OP_CHECKSIG  =  0x20 || xonly || 0xac."
  (assert (= (length xonly) 32))
  (cat (vector #x20) xonly (vector #xac)))

(defun tapleaf-hash (script &optional (leaf-version +tapscript-leaf-version+))
  "BIP341 TapLeaf hash:
   tagged_hash(\"TapLeaf\", leaf_version || compact_size(len(script)) || script)."
  (sch:tagged-hash "TapLeaf"
                   (cat (vector leaf-version) (compact-size (length script)) script)))

(defun tapbranch-hash (a b)
  "BIP341 TapBranch hash: tagged_hash(\"TapBranch\", c1 || c2) where (c1,c2) is
   (a,b) sorted lexicographically (the two 32-byte child hashes are sorted
   before hashing so the result is order-independent)."
  (if (lex<= a b)
      (sch:tagged-hash "TapBranch" (cat a b))
      (sch:tagged-hash "TapBranch" (cat b a))))

;;; ----------------------------------------------------------------------------
;;; Taptree construction:  leaf scripts -> root + per-leaf merkle path
;;; ----------------------------------------------------------------------------

(defun %as-script-list (leaf-scripts)
  "Accept either a single leaf-script byte vector or a LIST of them; return a list."
  (if (and (vectorp leaf-scripts) (not (stringp leaf-scripts)))
      (list leaf-scripts)
      leaf-scripts))

(defun build-taptree (leaf-scripts &optional (leaf-version +tapscript-leaf-version+))
  "Build a balanced taptree (shape documented at top of file) from a single leaf
   script or a LIST of leaf scripts.  Returns (values ROOT PATHS) where ROOT is
   the 32-byte merkle root and PATHS is a list, parallel to the leaves, of merkle
   paths.  Each path is an ordered list of 32-byte SIBLING hashes from that leaf
   up to (but excluding) the root — i.e. the path supplied in the control block.
   A single leaf yields root = its tapleaf-hash and an empty path."
  (let ((scripts (%as-script-list leaf-scripts)))
    (assert (plusp (length scripts)))
    ;; A node = (cons HASH LEAF-INDEX-LIST): subtree hash plus the original-leaf
    ;; indices it covers.  Pairing siblings lets us append, for every covered
    ;; leaf, the sibling's hash to that leaf's accumulating path.
    (let* ((paths (make-array (length scripts) :initial-element nil))
           (level (loop for sc in scripts for i from 0
                        collect (cons (tapleaf-hash sc leaf-version) (list i)))))
      (loop while (> (length level) 1) do
        (setf level
              (loop for rest on level by #'cddr
                    for left = (first rest)
                    for right = (second rest)
                    collect
                    (if right
                        (progn
                          (dolist (li (cdr left))  (push (car right) (aref paths li)))
                          (dolist (li (cdr right)) (push (car left)  (aref paths li)))
                          (cons (tapbranch-hash (car left) (car right))
                                (append (cdr left) (cdr right))))
                        ;; lone trailing node carries up unchanged (no sibling)
                        left))))
      ;; siblings were pushed level-by-level bottom-up, so PUSH already left each
      ;; path in root->leaf order; reverse to get leaf->root (nearest sibling first).
      (values (car (first level))
              (loop for i below (length scripts)
                    collect (reverse (aref paths i)))))))

(defun taptree-root (leaf-scripts &optional (leaf-version +tapscript-leaf-version+))
  "The merkle root of the taptree over LEAF-SCRIPTS (single script or list)."
  (values (build-taptree leaf-scripts leaf-version)))

(defun taptree-leaf-path (leaf-scripts leaf-index
                          &optional (leaf-version +tapscript-leaf-version+))
  "The merkle PATH (ordered list of 32-byte sibling hashes, leaf->root) for the
   leaf at LEAF-INDEX of the taptree over LEAF-SCRIPTS."
  (multiple-value-bind (root paths) (build-taptree leaf-scripts leaf-version)
    (declare (ignore root))
    (nth leaf-index paths)))

;;; ----------------------------------------------------------------------------
;;; Output scriptPubKey  (OP_1 0x20 Qx)  + Q's y-parity
;;; ----------------------------------------------------------------------------

(defun taproot-output-spk-from-root (internal-xonly merkle-root)
  "Build the taproot output committing to MERKLE-ROOT.

   tweak t = int(tagged_hash(\"TapTweak\", internal-xonly || merkle-root)) mod n
   Q       = lift_x(internal-xonly) + t*G

   Returns (values spk q-parity) — SPK = #(0x51 0x20) || Q.x, Q-PARITY = parity
   (0 even / 1 odd) of Q's y, needed for the control byte."
  (let* ((tweak (mod (secp:bytes-to-int
                      (sch:tagged-hash "TapTweak" (cat internal-xonly merkle-root)))
                     secp:*secp256k1-n*))
         (p-even (sch:lift-x (secp:bytes-to-int internal-xonly)))
         (q (secp:secp-add-points p-even (secp:secp-pubkey tweak)))
         (qx (secp:int-to-bytes32 (secp:secp-x q)))
         (q-parity (logand (secp:secp-y q) 1)))
    (values (cat (vector #x51 #x20) qx) q-parity)))

(defun taproot-output-spk (internal-xonly leaf-scripts
                           &optional (leaf-version +tapscript-leaf-version+))
  "Build the taproot output for the taptree over LEAF-SCRIPTS.

   LEAF-SCRIPTS may be a single leaf-script byte vector (single-leaf API,
   back-compat) or a LIST of leaf scripts.  The merkle root is the taptree root;
   the output is then tweaked exactly as the key-path version.

   Returns (values spk q-parity)."
  (taproot-output-spk-from-root internal-xonly (taptree-root leaf-scripts leaf-version)))

;;; ----------------------------------------------------------------------------
;;; Control block  =  control byte || internal-xonly || merkle path
;;; ----------------------------------------------------------------------------

(defun control-block (internal-xonly q-parity
                      &optional (merkle-path nil) (leaf-version +tapscript-leaf-version+))
  "BIP341 control block for the chosen leaf:
     byte (leaf_version | parity-of-Q.y) || internal-xonly (32) || merkle-path
   where MERKLE-PATH is the ordered list of 32-byte sibling hashes (leaf->root).
   Total length 33 + 32*depth bytes.  A NIL/empty path ⇒ 33 bytes (single leaf)."
  (assert (member q-parity '(0 1)))
  (dolist (sib merkle-path) (assert (= (length sib) 32)))
  (apply #'cat
         (vector (logior leaf-version q-parity))
         internal-xonly
         merkle-path))

;;; ----------------------------------------------------------------------------
;;; Spend builder
;;; ----------------------------------------------------------------------------

(defun build-script-path-spend (prev-txid prev-vout amount spk leaf-priv
                                &key leaf-scripts (leaf-index 0) (internal-priv nil)
                                     (out-value (max 0 (- amount 1000)))
                                     (out-script (cat (vector #x51)))   ; OP_1 anyone-can-spend
                                     (sequence #xffffffff) (locktime 0))
  "Build + sign a v2 segwit tx spending the taproot output {AMOUNT, SPK} at
   PREV-TXID:PREV-VOUT via the SCRIPT path of one leaf of a taptree.

   LEAF-PRIV   : integer private key whose x-only pubkey is the one embedded in
                 the CHOSEN leaf script (signs that leaf's CHECKSIG).
   LEAF-SCRIPTS: the full list of leaf scripts in the taptree (defines the merkle
                 root + each leaf's path).  When NIL, the tree is the lone leaf
                 <pubkey(LEAF-PRIV)> OP_CHECKSIG (single-leaf back-compat).
   LEAF-INDEX  : which leaf of LEAF-SCRIPTS to spend (default 0).
   INTERNAL-PRIV: integer private key of the taproot INTERNAL key (the key the
                 output was tweaked from).  When NIL, defaults to LEAF-PRIV (the
                 single-leaf convention: same key as internal + in the leaf).

   The witness is [signature, leaf-script, control-block-with-path].
   Returns the signed TX.  Errors if the rebuilt SPK != the supplied prevout SPK."
  (let* ((ipriv (or internal-priv leaf-priv))
         (internal-xonly (sch:pubkey-xonly ipriv))
         (scripts (if leaf-scripts
                      (%as-script-list leaf-scripts)
                      (list (checksig-leaf-script (sch:pubkey-xonly leaf-priv)))))
         (leaf-script (nth leaf-index scripts)))
    (multiple-value-bind (root paths) (build-taptree scripts)
      (multiple-value-bind (built-spk q-parity)
          (taproot-output-spk-from-root internal-xonly root)
        (unless (equalp built-spk spk)
          (error "build-script-path-spend: internal key + taptree do not match the prevout spk~%  built ~a~%  spk   ~a"
                 (w:bytes->hex built-spk) (w:bytes->hex spk)))
        (let* ((path (nth leaf-index paths))
               (ctrl (control-block internal-xonly q-parity path))
               (leaf-h (tapleaf-hash leaf-script))
               (txn (tx:make-tx
                     :version 2
                     :inputs (list (tx:make-txin :prev-hash prev-txid :prev-index prev-vout
                                                 :script #() :sequence sequence))
                     :outputs (list (tx:make-txout :value out-value :script out-script))
                     :witnesses (list nil)
                     :locktime locktime
                     :segwit-p t))
               (prevouts (vector (cons amount spk)))
               ;; BIP341 tapscript sighash: ext-flag 1, THIS leaf's hash, no annex,
               ;; codesep-pos = 0xffffffff (no executed OP_CODESEPARATOR).
               (sighash (s:taproot-sighash txn 0 prevouts 0
                                           :ext-flag 1
                                           :annex nil
                                           :tapleaf-hash leaf-h
                                           :codesep-pos #xffffffff))
               ;; BIP341 tapscript sigs are BIP340 over the x-only LEAF key.
               ;; SIGHASH_DEFAULT ⇒ 64-byte signature (no trailing hashtype byte).
               (sig (sch:schnorr-sign leaf-priv sighash)))
          (setf (first (tx:tx-witnesses txn)) (list sig leaf-script ctrl))
          (tx:finalize-tx txn)
          txn)))))

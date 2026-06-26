;;;; src/taproot-script.lisp
;;;;
;;;; BIP341 taproot SCRIPT-PATH spending — a clean first cut for a SINGLE tapleaf.
;;;;
;;;; Key-path taproot already lives in wallet.lisp (taproot-output-key/-tweak,
;;;; sign-input :p2tr).  This module is the script-path analog: an output that
;;;; commits to a taptree (here a lone leaf), spent by REVEALING the leaf script,
;;;; satisfying it, and supplying a control block.
;;;;
;;;; Scope: one leaf, leaf-version 0xc0, script = <32-byte x-only pubkey> OP_CHECKSIG
;;;; (bytes: 0x20 || xonly || 0xac).  A single leaf ⇒ the merkle root IS the
;;;; tapleaf hash and the control block carries no merkle path (exactly 33 bytes).
;;;;
;;;; Success bar: a spend built here VERIFIES under cl-consensus.script:verify-input,
;;;; whose tapscript path is already differential-tested to 0 divergence vs Core.

(defpackage #:cl-consensus.taproot-script
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:s #:cl-consensus.script)
                    (#:secp #:secp256k1-fast) (#:sch #:secp256k1-fast.schnorr))
  (:export
   #:tapleaf-hash #:checksig-leaf-script
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

;;; ----------------------------------------------------------------------------
;;; Leaf script + tapleaf hash
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

;;; ----------------------------------------------------------------------------
;;; Output scriptPubKey  (OP_1 0x20 Qx)  + Q's y-parity
;;; ----------------------------------------------------------------------------

(defun taproot-output-spk (internal-xonly leaf-script
                           &optional (leaf-version +tapscript-leaf-version+))
  "Build the taproot output for a single-leaf taptree.

   merkle root k = tapleaf_hash(leaf-script)
   tweak t       = int(tagged_hash(\"TapTweak\", internal-xonly || k)) mod n
   Q             = lift_x(internal-xonly) + t*G

   Returns (values spk q-parity) where SPK is #(0x51 0x20) || Q.x and Q-PARITY is
   the parity (0 even / 1 odd) of Q's y-coordinate — needed for the control block."
  (let* ((k (tapleaf-hash leaf-script leaf-version))
         (tweak (mod (secp:bytes-to-int (sch:tagged-hash "TapTweak" (cat internal-xonly k)))
                     secp:*secp256k1-n*))
         (p-even (sch:lift-x (secp:bytes-to-int internal-xonly)))
         (q (secp:secp-add-points p-even (secp:secp-pubkey tweak)))
         (qx (secp:int-to-bytes32 (secp:secp-x q)))
         (q-parity (logand (secp:secp-y q) 1)))
    (values (cat (vector #x51 #x20) qx) q-parity)))

;;; ----------------------------------------------------------------------------
;;; Control block  (single leaf ⇒ no merkle path ⇒ exactly 33 bytes)
;;; ----------------------------------------------------------------------------

(defun control-block (internal-xonly q-parity
                      &optional (leaf-version +tapscript-leaf-version+))
  "33-byte control block: control byte (leaf_version | parity-of-Q.y) then the
   33th..1st = the 32-byte internal x-only pubkey.  No merkle path (single leaf)."
  (assert (member q-parity '(0 1)))
  (cat (vector (logior leaf-version q-parity)) internal-xonly))

;;; ----------------------------------------------------------------------------
;;; Spend builder
;;; ----------------------------------------------------------------------------

(defun build-script-path-spend (prev-txid prev-vout amount spk leaf-priv
                                &key (out-value (max 0 (- amount 1000)))
                                     (out-script (cat (vector #x51)))   ; OP_1 anyone-can-spend
                                     (sequence #xffffffff) (locktime 0))
  "Build + sign a v2 segwit tx spending the single taproot output {AMOUNT, SPK}
   at PREV-TXID:PREV-VOUT via the SCRIPT path of a lone <xonly> OP_CHECKSIG leaf.

   LEAF-PRIV is the integer private key whose BIP340 x-only pubkey is the one
   embedded in the leaf script AND is used as the internal key.  (For a single
   leaf with the same key in script and as internal key, this is the simplest
   self-consistent spend; the script-path commitment + tapscript CHECKSIG both
   resolve to this key.)

   The witness is set to [signature, leaf-script, control-block].
   Returns the signed TX (txid/sizes finalized)."
  (let* ((internal-xonly (sch:pubkey-xonly leaf-priv))
         (leaf-script (checksig-leaf-script internal-xonly)))
    (multiple-value-bind (built-spk q-parity)
        (taproot-output-spk internal-xonly leaf-script)
      ;; sanity: the spk we'd build for this key must match the prevout's spk
      (unless (equalp built-spk spk)
        (error "build-script-path-spend: leaf-priv does not match the prevout spk~%  built ~a~%  spk   ~a"
               (w:bytes->hex built-spk) (w:bytes->hex spk)))
      (let* ((ctrl (control-block internal-xonly q-parity))
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
             ;; BIP341 tapscript sighash: ext-flag 1, this leaf's hash, no annex,
             ;; codesep-pos = 0xffffffff (no executed OP_CODESEPARATOR).
             (sighash (s:taproot-sighash txn 0 prevouts 0
                                         :ext-flag 1
                                         :annex nil
                                         :tapleaf-hash leaf-h
                                         :codesep-pos #xffffffff))
             ;; BIP341 tapscript signatures are BIP340 over the x-only LEAF key.
             ;; SIGHASH_DEFAULT ⇒ 64-byte signature (no trailing hashtype byte).
             (sig (sch:schnorr-sign leaf-priv sighash)))
        (setf (first (tx:tx-witnesses txn)) (list sig leaf-script ctrl))
        (tx:finalize-tx txn)
        txn))))

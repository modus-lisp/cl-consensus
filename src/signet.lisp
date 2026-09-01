;;;; src/signet.lisp
;;;;
;;;; BIP325 — signet block signatures.
;;;;
;;;; On mainnet, a block is expensive because of the work in its header.  On
;;;; signet the difficulty is deliberately trivial, so work secures nothing: what
;;;; makes a signet block valid is a SIGNATURE, made by whoever holds the key for
;;;; the network's challenge script.  A validator that checks signet's
;;;; proof-of-work and skips this check is not validating anything — anyone can
;;;; grind a signet header in milliseconds.  That is why this file exists.
;;;;
;;;; The construction is BIP322-flavoured.  Two transactions are built that exist
;;;; only to be verified, never to be broadcast:
;;;;
;;;;   to_spend  — one input spending nothing (a null outpoint), whose scriptSig
;;;;               commits to the block; one output paying to the CHALLENGE.
;;;;   to_sign   — spends to_spend's output, carrying the block's signature as
;;;;               its scriptSig + witness.
;;;;
;;;; Verifying the block reduces to verifying that to_sign spends to_spend — an
;;;; ordinary script verification, which cl-consensus's interpreter already does
;;;; and which the conformance suite already tests to 100% against Core.
;;;;
;;;; The signature itself lives inside the coinbase's witness-commitment output,
;;;; appended to the OP_RETURN push behind a 4-byte header.  It must be REMOVED
;;;; before the block is hashed for signing — otherwise the signature would have
;;;; to commit to itself — which is why the merkle root is recomputed here over a
;;;; modified coinbase.
;;;;
;;;; Reference: https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki
;;;;            Bitcoin Core src/signet.cpp

(defpackage #:cl-consensus.signet
  (:use #:cl)
  (:nicknames #:btc-signet)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:blk #:cl-consensus.block) (#:script #:cl-consensus.script)
                    (#:c #:cl-consensus.chain))
  (:export
   #:check-signet-block-solution #:signet-block-signature-p
   #:+signet-header+ #:signet-txs #:make-signet-txs
   #:signet-txs-to-spend #:signet-txs-to-sign))

(in-package #:cl-consensus.signet)

(defparameter +signet-header+ #(#xec #xc7 #xda #xa2)
  "Marks the signet solution inside the coinbase's witness-commitment push.")

(defparameter +signet-script-flags+ '(:p2sh :witness :dersig :nulldummy)
  "BLOCK_SCRIPT_VERIFY_FLAGS from Core's signet.cpp.  Deliberately a FIXED set,
   not the height-derived consensus flags: the block signature's rules must not
   drift as soft forks activate.")

(defun bytes (&rest seqs)
  (apply #'concatenate '(vector (unsigned-byte 8)) seqs))

;;; ----------------------------------------------------------------------------
;;; Script (re)building
;;;
;;; Core rebuilds the witness-commitment script by pushing each element back
;;; through CScript::operator<<, so we must reproduce ITS encoding, not a
;;; "minimal" one: a zero-length element becomes a 0x00 push (not OP_0), and a
;;; single small byte becomes a 1-byte push (not OP_1..OP_16).  Encoding it any
;;; other way changes the coinbase txid and so the merkle root, and the
;;; signature stops verifying for reasons that are very hard to see.
;;; ----------------------------------------------------------------------------

(defun push-data (data)
  "CScript::operator<<(vector) — size-prefixed, never OP_N."
  (let ((n (length data)))
    (cond ((< n 76) (bytes (vector n) data))
          ((<= n #xff) (bytes (vector 76 n) data))                    ; OP_PUSHDATA1
          ((<= n #xffff) (bytes (vector 77 (ldb (byte 8 0) n) (ldb (byte 8 8) n)) data))
          (t (bytes (vector 78 (ldb (byte 8 0) n) (ldb (byte 8 8) n)
                            (ldb (byte 8 16) n) (ldb (byte 8 24) n))
                    data)))))

(defun fetch-and-clear-commitment-section (script)
  "Split the signet solution out of SCRIPT.  Returns
   (values modified-script solution) — or (values SCRIPT nil) if there is none.

   The solution is the tail of the first push that both starts with
   +SIGNET-HEADER+ and is strictly longer than it; that push is truncated back to
   the bare header and the script is rebuilt around it."
  (let ((ops (handler-case (script:parse-script script)
               (error () (return-from fetch-and-clear-commitment-section
                           (values script nil)))))
        (found nil)
        (out '()))
    (dolist (op ops)
      (if (and (consp op) (eq (car op) :push))
          (let ((data (cddr op)))
            (if (and (not found)
                     (> (length data) (length +signet-header+))
                     (equalp (subseq data 0 (length +signet-header+)) +signet-header+))
                (progn
                  (setf found (subseq data (length +signet-header+)))
                  (push (push-data (subseq data 0 (length +signet-header+))) out))
                (push (push-data data) out)))
          (push (vector op) out)))
    (if found
        (values (apply #'bytes (nreverse out)) found)
        (values script nil))))

;;; ----------------------------------------------------------------------------
;;; The two synthetic transactions
;;; ----------------------------------------------------------------------------

(defstruct signet-txs to-spend to-sign)

(defun %null-outpoint () (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(defun parse-solution (solution)
  "The solution blob is a serialized (scriptSig, witness stack) pair.  Returns
   (values scriptsig witness-stack), or NIL if it is malformed or has trailing
   bytes — Core rejects extraneous data, and so must we, or a block would have
   two distinct encodings."
  (handler-case
      (let* ((r (w:make-reader solution))
             (sig (w:r-bytes r (w:r-varint r)))
             (n (w:r-varint r))
             (stack (loop repeat n collect (w:r-bytes r (w:r-varint r)))))
        (if (w:reader-eof-p r) (values sig stack) nil))
    (error () nil)))

(defun compute-modified-merkle-root (modified-coinbase block)
  "Merkle root of the block with the coinbase replaced by MODIFIED-COINBASE (the
   one with the signature stripped).  Uses txids, not wtxids."
  (let ((txs (blk:block-txs block)))
    (blk:compute-merkle-root
     (cons (tx:tx-txid modified-coinbase)
           (loop for i from 1 below (length txs) collect (tx:tx-txid (aref txs i)))))))

(defun rebuild-tx (template)
  "Re-parse a transaction we assembled by hand, so its txid/sizes are computed by
   the same code path as any transaction off the wire."
  (tx:parse-tx (w:make-reader (tx:serialize-tx template))))

(defun make-signet-txs-for (block challenge)
  "Build the to_spend / to_sign pair for BLOCK under CHALLENGE, or NIL if the
   block is structurally unable to carry a solution."
  (let ((txs (blk:block-txs block)))
    (when (zerop (length txs)) (return-from make-signet-txs-for nil))
    (let* ((coinbase (aref txs 0))
           (cidx (position-if (lambda (out)
                                (let ((s (tx:txout-script out)))
                                  (and (>= (length s) 38)
                                       (equalp (subseq s 0 6)
                                               #(#x6a #x24 #xaa #x21 #xa9 #xed)))))
                              (tx:tx-outputs coinbase) :from-end t)))
      ;; BIP325 requires a witness commitment: it is where the signature lives.
      (unless cidx (return-from make-signet-txs-for nil))
      (multiple-value-bind (modified-script solution)
          (fetch-and-clear-commitment-section
           (tx:txout-script (nth cidx (tx:tx-outputs coinbase))))
        (let (sig stack)
          (when solution
            (multiple-value-bind (s w) (parse-solution solution)
              (unless s (return-from make-signet-txs-for nil))   ; malformed → invalid block
              (setf sig s stack w)))
          ;; A coinbase with the signature spliced out; its txid feeds the merkle
          ;; root the signature commits to.
          (let* ((modified-cb
                   (rebuild-tx
                    (tx:make-tx
                     :version (tx:tx-version coinbase)
                     :inputs (tx:tx-inputs coinbase)
                     :outputs (loop for out in (tx:tx-outputs coinbase)
                                    for i from 0
                                    collect (if (= i cidx)
                                                (tx:make-txout :value (tx:txout-value out)
                                                               :script modified-script)
                                                out))
                     :witnesses (tx:tx-witnesses coinbase)
                     :locktime (tx:tx-locktime coinbase)
                     :segwit-p (tx:tx-segwit-p coinbase))))
                 (signet-merkle (compute-modified-merkle-root modified-cb block))
                 ;; What the signature actually commits to: the header, but with
                 ;; the modified merkle root — and WITHOUT nBits or nNonce, so a
                 ;; block can be re-ground for work without re-signing.
                 (hdr (blk:block-header block))
                 (block-data (let ((wr (w:make-writer)))
                               (w:w-i32 wr (c:header-version hdr))
                               (w:w-hash wr (c:header-prev hdr))
                               (w:w-hash wr signet-merkle)
                               (w:w-u32 wr (c:header-time hdr))
                               (w:writer-bytes wr)))
                 (to-spend
                   (rebuild-tx
                    (tx:make-tx
                     :version 0 :locktime 0 :segwit-p nil
                     :inputs (list (tx:make-txin :prev-hash (%null-outpoint)
                                                 :prev-index #xffffffff
                                                 ;; OP_0 <block_data>
                                                 :script (bytes #(0) (push-data block-data))
                                                 :sequence 0))
                     :outputs (list (tx:make-txout :value 0 :script challenge))
                     :witnesses (list nil)))))
            (make-signet-txs
             :to-spend to-spend
             :to-sign
             (rebuild-tx
              (tx:make-tx
               :version 0 :locktime 0 :segwit-p (and stack t)
               :inputs (list (tx:make-txin :prev-hash (tx:tx-txid to-spend)
                                           :prev-index 0
                                           :script (or sig #())
                                           :sequence 0))
               :outputs (list (tx:make-txout :value 0 :script #(#x6a)))  ; OP_RETURN
               :witnesses (list stack))))))))))

;;; ----------------------------------------------------------------------------
;;; The check
;;; ----------------------------------------------------------------------------

(defun signet-block-signature-p (block challenge)
  "T if BLOCK carries a signature satisfying CHALLENGE."
  (let ((pair (make-signet-txs-for block challenge)))
    (and pair
         (handler-case
             (and (script:verify-input (signet-txs-to-sign pair) 0
                                       (tx:txout-script
                                        (first (tx:tx-outputs (signet-txs-to-spend pair))))
                                       0
                                       :flags +signet-script-flags+)
                  t)
           (error () nil)))))

(defun check-signet-block-solution (block &optional (net w:*network*))
  "Enforce BIP325 on BLOCK.  A no-op on non-signet networks.  The genesis block
   is exempt — it predates any challenge and every signet shares it."
  (let ((challenge (w:net-signet-challenge net)))
    (when challenge
      (unless (equalp (w:hash->hex (blk:block-hash block)) (w:net-genesis-hash net))
        (unless (signet-block-signature-p block challenge)
          (error "BIP325: block ~a carries no valid signet signature"
                 (w:hash->hex (blk:block-hash block))))))
    t))

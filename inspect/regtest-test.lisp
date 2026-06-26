;;;; inspect/regtest-test.lisp
;;;;
;;;; A real regtest harness: select the regtest network (its own genesis + trivial PoW
;;;; target + early soft-fork activation), MINE blocks with actual nonce-grinding, and
;;;; drive the full node end-to-end — including the one loop we'd never exercised: mine
;;;; coins, fund a wallet, build+sign a spend, accept it to the mempool, MINE it into a
;;;; block, and confirm the wallet sees it.  Plus a real-mined reorg.  Fully offline.
;;;;
;;;;   sbcl --load inspect/regtest-test.lisp --eval '(regtest-test:run)'
(require :asdf)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/cl-consensus/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :regtest-test
  (:use :cl)
  (:local-nicknames (:w :cl-consensus.wire) (:c :cl-consensus.chain) (:tx :cl-consensus.tx)
                    (:blk :cl-consensus.block) (:v :cl-consensus.validate) (:u :cl-consensus.utxo)
                    (:mp :cl-consensus.mempool) (:wal :cl-consensus.wallet) (:s :cl-consensus.script)
                    (:r :cl-consensus.reorg))
  (:export #:run #:run-reorg #:mine #:setup-regtest))
(in-package :regtest-test)

(defparameter *op-true* (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51))
(defparameter *ok* t)
(defun check (name got want) (unless (eql got want)
  (setf *ok* nil) (format t "  *** FAIL ~a: got ~a want ~a~%" name got want)))
(defun checkt (name cond) (unless cond (setf *ok* nil) (format t "  *** FAIL ~a~%" name)))
(defun zeros (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

;;; --- mining ---------------------------------------------------------------

(defun hdr-bytes (version prev merkle time bits nonce)
  (let ((wr (w:make-writer)))
    (w:w-u32 wr version) (w:w-hash wr prev) (w:w-hash wr merkle)
    (w:w-u32 wr time) (w:w-u32 wr bits) (w:w-u32 wr nonce)
    (w:writer-bytes wr)))

(defun le-int (bytes) (loop for i below 32 sum (ash (aref bytes i) (* 8 i))))

(defun bip34-scriptsig (height tag)
  "Coinbase scriptSig: push the block height (BIP34, heights < 128) then a branch TAG
   byte so coinbases on competing branches differ (distinct txids -> distinct blocks)."
  (concatenate '(vector (unsigned-byte 8)) (vector 1 height 1 tag)))

(defun coinbase-tx (height value script &optional (tag 0) commitment)
  "Coinbase paying VALUE to SCRIPT.  With COMMITMENT (32 bytes) add the BIP141 witness-
   commitment OP_RETURN output + the coinbase witness (reserved value = 32 zeros), making
   it a segwit coinbase (required when the block carries any witness tx)."
  (let ((outs (list (tx:make-txout :value value :script script))))
    (when commitment
      (setf outs (append outs (list (tx:make-txout :value 0
                    :script (concatenate '(vector (unsigned-byte 8))
                                         #(#x6a #x24 #xaa #x21 #xa9 #xed) commitment))))))
    (let ((cb (tx:make-tx :version 1
                :inputs (list (tx:make-txin :prev-hash (zeros 32) :prev-index #xffffffff
                                            :script (bip34-scriptsig height tag) :sequence #xffffffff))
                :outputs outs
                :witnesses (when commitment (list (list (zeros 32))))
                :locktime 0 :segwit-p (and commitment t))))
      (tx:finalize-tx cb) cb)))

(defun witness-commitment-for (txs)
  "BIP141 commitment HASH256(witness-merkle-root || reserved) for a block whose non-
   coinbase txs are TXS (coinbase wtxid is defined as 0)."
  (w:hash256 (concatenate '(vector (unsigned-byte 8))
                          (blk:compute-merkle-root (cons (zeros 32) (mapcar #'tx:tx-wtxid txs)))
                          (zeros 32))))

(defparameter *blocks* (make-hash-table :test 'equal)
  "hash-hex -> block*, so a reorg's fetch-block can retrieve any mined block.")

(defun block-bytes (header-bytes txs)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr header-bytes)
    (w:w-varint wr (length txs))
    (dolist (txn txs) (w:w-bytes wr (tx:serialize-tx txn :witness t)))
    (w:writer-bytes wr)))

(defun grind (version prev merkle time bits)
  "Find a nonce whose header hash meets the (trivial, regtest) target; return the block
   bytes.  Regtest target is huge so this is ~1-2 hashes."
  (let ((target (c::compact->target bits)))
    (loop for nonce from 0 below 100000
          for hb = (hdr-bytes version prev merkle time bits nonce)
          when (<= (le-int (w:hash256 hb)) target) do (return-from grind hb))
    (error "grind failed")))

(defun mine (utxo &key txs (coinbase-script *op-true*) wallet undo (tag 0))
  "Mine the next block on the current tip (real nonce-grinding) with optional TXS,
   connect it to UTXO (recording per-height undo into UNDO if given), and (with WALLET)
   update the wallet.  Stores the block for later fetch.  Returns the block*."
  (let* ((tip (c:tip)) (height (1+ (c:tip-height)))
         (commitment (when (some #'tx:tx-segwit-p txs) (witness-commitment-for txs)))
         (cb (coinbase-tx height (v:block-subsidy height) coinbase-script tag commitment))
         (all (cons cb txs))
         (merkle (blk:compute-merkle-root (mapcar #'tx:tx-txid all)))
         (hb (grind #x20000000 (c:header-hash tip) merkle (1+ (c:header-time tip)) #x207fffff))
         (blk (blk:parse-block (block-bytes hb all))))
    (c:add-header (blk:block-header blk))
    (multiple-value-bind (fees u) (v:connect-block blk height utxo)
      (declare (ignore fees))
      (when undo (r:undo-put undo height u)))
    (setf (gethash (c:header-hash-hex (blk:block-header blk)) *blocks*) blk)
    (when wallet (wal:wallet-process-block wallet blk height))
    blk))

(defun mine-header-only (prev &key (tag 1))
  "Mine a coinbase-only block on PREV (a header, possibly a side branch), add its header
   to the chain (validate t = real PoW/difficulty/MTP checks), store the block, and
   return the new header.  Does NOT connect to any UTXO — used to build a competing
   branch the reorg machinery then activates."
  (let* ((height (1+ (c:header-height prev)))
         (cb (coinbase-tx height (v:block-subsidy height) *op-true* tag))
         (merkle (blk:compute-merkle-root (list (tx:tx-txid cb))))
         (hb (grind #x20000000 (c:header-hash prev) merkle (1+ (c:header-time prev)) #x207fffff))
         (blk (blk:parse-block (block-bytes hb (list cb)))))
    (c:add-header (blk:block-header blk))
    (setf (gethash (c:header-hash-hex (blk:block-header blk)) *blocks*) blk)
    (blk:block-header blk)))

(defun setup-regtest ()
  (w:select-network :regtest)
  (c:init-chain)
  (u:make-utxo-set))

;;; --- the gate -------------------------------------------------------------

(declaim (ftype (function () t) run-reorg run-taproot))   ; defined below; called by RUN

(defun run ()
  (setf *ok* t)
  (let ((utxo (setup-regtest)))
    (checkt "regtest genesis hash" (string= (c:header-hash-hex (c:tip))
                                            (w:net-genesis-hash w:*network*)))
    ;; mine 101 blocks (coinbase -> OP_TRUE) so block 1's coinbase matures
    (dotimes (i 101) (mine utxo))
    (check "tip after mining" (c:tip-height) 101)
    (check "utxo has 101 coinbase coins" (u:utxo-count utxo) 101)
    ;; fund a P2PKH wallet by spending block 1's coinbase (OP_TRUE) to the wallet.
    ;; The coinbase is deterministic, so re-deriving coinbase-tx(1) reproduces its txid.
    (let* ((wallet (wal:make-wallet-from-seed (w:hex->bytes "000102030405060708090a0b0c0d0e0f")
                                              :type :p2pkh))
           (wspk (wal::waddr-script (aref (wal:wallet-receive wallet) 0)))
           (cb1-txid (tx:tx-txid (coinbase-tx 1 (v:block-subsidy 1) *op-true*))))
      (let ((funding (tx:make-tx :version 1
                       :inputs (list (tx:make-txin :prev-hash cb1-txid :prev-index 0
                                                   :script #() :sequence #xffffffff))
                       :outputs (list (tx:make-txout :value 4999990000 :script wspk))
                       :witnesses nil :locktime 0 :segwit-p nil)))
        (tx:finalize-tx funding)
        (mine utxo :txs (list funding) :wallet wallet)
        (check "wallet funded from coinbase" (wal:wallet-balance wallet) 4999990000)
        ;; ---- the full loop: wallet build -> mempool -> mine -> confirm ----
        (let* ((mpool (mp:make-mempool))
               (spend (wal:create-tx wallet (list (cons "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" 1000000000))
                                     :feerate 2)))
          ;; broadcast: accept into the mempool (validated vs the live UTXO)
          (mp:accept-tx spend utxo mpool :height (1+ (c:tip-height))
                                         :mtp (c:median-time-past (c:tip)))
          (checkt "spend accepted to mempool" (= 1 (mp:mempool-size mpool)))
          ;; mine the mempool tx into a block
          (let ((spend-txn (mp:entry-tx (mp:mempool-get mpool (first (mp:mempool-txids mpool))))))
            (mine utxo :txs (list spend-txn) :wallet wallet)
            (mp:mempool-on-block mpool (list spend-txn)))
          (check "mempool drained after mining" (mp:mempool-size mpool) 0)
          ;; wallet now reflects the confirmed spend: original coin gone, change present
          (checkt "wallet spent the funded coin + holds change"
                  (and (< (wal:wallet-balance wallet) 4999990000)
                       (> (wal:wallet-balance wallet) 3999000000)))
          (format t "[regtest-test] post-spend wallet balance ~d sat (change)~%"
                  (wal:wallet-balance wallet))))))
  (run-taproot)
  (run-reorg)
  (format t "~&regtest-test: ~a~%"
          (if *ok* "OK — mine->send->confirm (P2PKH + P2TR) + reorg" "FAILED"))
  *ok*)

(defun run-taproot ()
  "End-to-end taproot: mine coins, fund a P2TR (BIP86) wallet, build a KEY-PATH spend,
   accept it to the mempool, MINE it into a SEGWIT block (witness commitment), and
   confirm the wallet sees it — exercising the BIP341 output tweak, Schnorr signing, the
   taproot sighash, and witness-commitment block construction."
  (setf *blocks* (make-hash-table :test 'equal))
  (let ((utxo (setup-regtest)))
    (dotimes (i 101) (mine utxo))                      ; OP_TRUE coinbases (block 1 matures)
    (let* ((wallet (wal:make-wallet-from-seed (w:hex->bytes "000102030405060708090a0b0c0d0e0f")
                                              :type :p2tr))
           (wspk (wal::waddr-script (aref (wal:wallet-receive wallet) 0)))
           (cb1 (tx:tx-txid (coinbase-tx 1 (v:block-subsidy 1) *op-true* 0)))
           (funding (tx:make-tx :version 1
                      :inputs (list (tx:make-txin :prev-hash cb1 :prev-index 0
                                                  :script #() :sequence #xffffffff))
                      :outputs (list (tx:make-txout :value 4999990000 :script wspk))
                      :witnesses nil :locktime 0 :segwit-p nil)))
      (tx:finalize-tx funding)
      (mine utxo :txs (list funding) :wallet wallet)   ; legacy block (OP_TRUE input, no witness)
      (check "P2TR wallet funded" (wal:wallet-balance wallet) 4999990000)
      (let* ((mpool (mp:make-mempool))
             (spend (wal:create-tx wallet
                                   (list (cons (wal:wallet-receive-address wallet 5) 1000000000))
                                   :feerate 2)))
        (checkt "P2TR spend is segwit (witness)" (tx:tx-segwit-p spend))
        ;; broadcast -> mempool (full taproot script verify vs the live UTXO)
        (mp:accept-tx spend utxo mpool :height (1+ (c:tip-height))
                                       :mtp (c:median-time-past (c:tip)))
        (checkt "P2TR spend accepted to mempool" (= 1 (mp:mempool-size mpool)))
        ;; mine it into a SEGWIT block (coinbase witness commitment required + built)
        (let ((spend-txn (mp:entry-tx (mp:mempool-get mpool (first (mp:mempool-txids mpool))))))
          (mine utxo :txs (list spend-txn) :wallet wallet)
          (mp:mempool-on-block mpool (list spend-txn)))
        (checkt "P2TR spend confirmed (coin spent, change held)"
                (and (< (wal:wallet-balance wallet) 4999990000)
                     (> (wal:wallet-balance wallet) 3999000000)))
        (format t "[regtest-test] P2TR key-path spend mined into a segwit block; balance ~d~%"
                (wal:wallet-balance wallet))))))

(defun run-reorg ()
  "Real-mined reorg: branch A (3 connected blocks) is out-weighed by a later, longer
   branch B (4 blocks) mined as side-chain headers; activate-best-chain must roll the
   UTXO from A onto B, and the reorged UTXO must equal a fresh connect of B (digest +
   count) — disconnect/reconnect with REAL proof-of-work blocks."
  (setf *blocks* (make-hash-table :test 'equal))
  (let* ((utxo (setup-regtest)) (undo (r:make-mem-undo-store)) (genesis (c:tip)))
    ;; branch A: 3 connected blocks (tag 0), per-height undo recorded
    (dotimes (i 3) (mine utxo :undo undo :tag 0))
    (let ((a-height (c:tip-height)))
      (check "branch A tip height" a-height 3)
      (check "utxo has A's 3 coinbases" (u:utxo-count utxo) 3)
      ;; branch B: 4 header-only blocks on genesis (tag 1) — heavier, but not connected
      (let ((prev genesis)) (dotimes (i 4) (setf prev (mine-header-only prev :tag 1))))
      ;; reorg the UTXO A -> B
      (multiple-value-bind (h2 reorged depth)
          (r:activate-best-chain utxo a-height undo
                                 (lambda (hdr) (gethash (c:header-hash-hex hdr) *blocks*)))
        (checkt "reorged" reorged)
        (check "new committed height" h2 4)
        (check "reorg depth" depth 3))
      (check "tip is now B (height 4)" (c:tip-height) 4)
      (check "utxo now has B's 4 coinbases" (u:utxo-count utxo) 4)
      (checkt "A's block-1 coinbase removed"
              (null (u:utxo-get utxo (tx:tx-txid (coinbase-tx 1 (v:block-subsidy 1) *op-true* 0)) 0)))
      ;; digest-exact: the reorged UTXO equals a fresh connect of branch B
      (let ((fresh (u:make-utxo-set)))
        (loop for h from 1 to 4 do
          (v:connect-block (gethash (c:header-hash-hex (c:header-at-height h)) *blocks*) h fresh))
        (checkt "reorg UTXO == fresh-B (digest)" (equalp (u:utxo-digest utxo) (u:utxo-digest fresh)))
        (check "reorg UTXO count == fresh-B" (u:utxo-count utxo) (u:utxo-count fresh)))
      (format t "[regtest-test] real-mined reorg A(3)->B(4): UTXO rolled + digest-exact~%"))))

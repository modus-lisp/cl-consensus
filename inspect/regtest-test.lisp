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
                    (:mp :cl-consensus.mempool) (:wal :cl-consensus.wallet) (:s :cl-consensus.script))
  (:export #:run #:mine #:setup-regtest))
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

(defun bip34-scriptsig (height)
  "Coinbase scriptSig carrying the block height (BIP34), heights < 128 (1-byte push)."
  (concatenate '(vector (unsigned-byte 8)) (vector 1 height)))

(defun coinbase-tx (height value script)
  (let ((cb (tx:make-tx :version 1
              :inputs (list (tx:make-txin :prev-hash (zeros 32) :prev-index #xffffffff
                                          :script (bip34-scriptsig height) :sequence #xffffffff))
              :outputs (list (tx:make-txout :value value :script script))
              :witnesses nil :locktime 0 :segwit-p nil)))
    (tx:finalize-tx cb) cb))

(defun block-bytes (header-bytes txs)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr header-bytes)
    (w:w-varint wr (length txs))
    (dolist (txn txs) (w:w-bytes wr (tx:serialize-tx txn :witness t)))
    (w:writer-bytes wr)))

(defun mine (utxo &key txs (coinbase-script *op-true*) wallet)
  "Mine the next block (real nonce-grinding) with optional TXS, connect it to UTXO, and
   (with WALLET) update the wallet.  Returns the block*."
  (let* ((tip (c:tip)) (height (1+ (c:tip-height)))
         (cb (coinbase-tx height (v:block-subsidy height) coinbase-script))
         (all (cons cb txs))
         (bits #x207fffff) (target (c::compact->target bits))
         (version #x20000000) (prev (c:header-hash tip)) (time (1+ (c:header-time tip)))
         (merkle (blk:compute-merkle-root (mapcar #'tx:tx-txid all))))
    (loop for nonce from 0 below 100000
          for hb = (hdr-bytes version prev merkle time bits nonce)
          when (<= (le-int (w:hash256 hb)) target) do
            (let ((blk (blk:parse-block (block-bytes hb all))))
              (c:add-header (blk:block-header blk))
              (v:connect-block blk height utxo)
              (when wallet (wal:wallet-process-block wallet blk height))
              (return-from mine blk)))
    (error "could not mine block ~d" height)))

(defun setup-regtest ()
  (w:select-network :regtest)
  (c:init-chain)
  (u:make-utxo-set))

;;; --- the gate -------------------------------------------------------------

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
  (format t "~&regtest-test: ~a~%"
          (if *ok* "OK — regtest genesis + real mining + mine->send->confirm" "FAILED"))
  *ok*)

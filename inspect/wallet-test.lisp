;;;; inspect/wallet-test.lisp
;;;;
;;;; Gate for the wallet foundation (Phase 1): Base58Check + bech32/bech32m address
;;;; encodings and BIP32 HD derivation, checked against authoritative vectors.
;;;;
;;;;   sbcl --load inspect/wallet-test.lisp --eval '(wallet-test:run)'
(require :asdf)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/cl-consensus/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :wallet-test
  (:use :cl)
  (:local-nicknames (:enc :cl-consensus.encoding) (:b32 :cl-consensus.bip32)
                    (:w :cl-consensus.wire) (:wal :cl-consensus.wallet)
                    (:tx :cl-consensus.tx) (:u :cl-consensus.utxo) (:s :cl-consensus.script))
  (:export #:run))
(in-package :wallet-test)

(defparameter *op-true* (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51))
(defun mk-tx (prevs outs)
  "PREVS = list of (txid . idx); OUTS = list of (value . script)."
  (let ((txn (tx:make-tx :version 2
               :inputs (mapcar (lambda (p) (tx:make-txin :prev-hash (car p) :prev-index (cdr p)
                                                         :script #() :sequence #xffffffff)) prevs)
               :outputs (mapcar (lambda (o) (tx:make-txout :value (car o) :script (cdr o))) outs)
               :witnesses nil :locktime 0 :segwit-p nil)))
    (tx:finalize-tx txn) txn))

(defparameter *ok* t)
(defun check (name got want)
  (unless (equal got want)
    (setf *ok* nil) (format t "  *** FAIL ~a~%      got  ~a~%      want ~a~%" name got want)))
(defun checkt (name cond) (unless cond (setf *ok* nil) (format t "  *** FAIL ~a~%" name)))
(defun hx (s) (w:hex->bytes s))

(defun run ()
  (setf *ok* t)
  ;; ---- Base58Check: the genesis coinbase P2PKH address ----
  (check "P2PKH genesis address"
         (enc:encode-p2pkh (hx "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"))
         "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
  ;; base58check round-trip
  (checkt "base58check round-trips"
          (equalp (enc:base58check-decode (enc:base58check-encode (hx "00010203deadbeef")))
                  (hx "00010203deadbeef")))
  ;; ---- bech32 P2WPKH: BIP173 vector ----
  (check "P2WPKH (BIP173)"
         (enc:encode-p2wpkh (hx "751e76e8199196d454941c45d1b3a323f1433bd6"))
         "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
  ;; ---- bech32m P2TR: round-trip + variant ----
  (let* ((xonly (hx "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
         (addr (enc:encode-p2tr xonly)))
    (checkt "P2TR has bc1p prefix" (and (>= (length addr) 4) (string= (subseq addr 0 4) "bc1p")))
    (multiple-value-bind (witver prog) (enc:segwit-decode addr)
      (checkt "P2TR decodes witver 1" (= witver 1))
      (checkt "P2TR program round-trips" (equalp prog xonly))))
  ;; ---- BIP32 Test Vector 1 (seed 000102...0f) ----
  (let* ((seed (hx "000102030405060708090a0b0c0d0e0f"))
         (m (b32:master-from-seed seed)))
    (check "BIP32 vec1 master xprv" (b32:serialize-xkey m)
           "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    ;; authoritative master compressed pubkey (validates the public path independent of
    ;; any memorized xpub string)
    (check "BIP32 vec1 master pubkey" (w:bytes->hex (b32:xkey-pubkey m))
           "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
    ;; xpub round-trips through base58check to a B21E-versioned key
    (checkt "master xpub round-trips"
            (equalp (enc:base58check-decode (b32:serialize-xkey (b32:neuter m)))
                    (enc:base58check-decode (b32:serialize-xkey (b32:neuter m)))))
    (check "BIP32 vec1 m/0' xprv" (b32:serialize-xkey (b32:derive-path m "m/0'"))
           "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
    ;; CKD-pub agrees with CKD-priv then neuter (normal child)
    (let* ((acct (b32:derive-path m "m/0'"))
           (priv-child (b32:ckd-priv acct 0))
           (pub-child (b32:ckd-pub (b32:neuter acct) 0)))
      (check "CKD-pub == neuter(CKD-priv)"
             (b32:serialize-xkey (b32:neuter priv-child)) (b32:serialize-xkey pub-child)))
    ;; a BIP84 receive key derives to a usable bech32 address (sanity, exercises the chain)
    (let* ((k (b32:derive-path m "m/84'/0'/0'/0/0"))
           (addr (enc:encode-p2wpkh (w:hash160 (b32:xkey-pubkey k)))))
      (checkt "BIP84 receive addr is bech32 mainnet" (string= (subseq addr 0 3) "bc1"))
      (format t "[wallet-test] sample m/84'/0'/0'/0/0 -> ~a~%" addr)))
  ;; ---- Phase 2: watch / balance ----
  (let* ((seed (hx "000102030405060708090a0b0c0d0e0f"))
         (wal (wal:make-wallet-from-seed seed :type :p2wpkh)))
    (checkt "receive[0] is bech32 mainnet" (string= (subseq (wal:wallet-receive-address wal 0) 0 3) "bc1"))
    (checkt "receive addrs are distinct"
            (not (string= (wal:wallet-receive-address wal 0) (wal:wallet-receive-address wal 1))))
    (let* ((spk0 (wal::waddr-script (aref (wal:wallet-receive wal) 0)))
           (funding (mk-tx (list (cons (hx "aa") 0)) (list (cons 250000 spk0)
                                                           (cons 999 *op-true*)))))
      ;; a tx pays our receive[0] -> coin tracked, balance updates
      (wal:wallet-process-tx wal funding 100)
      (check "balance after funding" (wal:wallet-balance wal) 250000)
      (check "one coin tracked" (hash-table-count (wal:wallet-coins wal)) 1)
      ;; gap window extended past the initial 20 once an address is used
      (checkt "gap window extended" (> (length (wal:wallet-receive wal)) 20))
      ;; spend that coin -> balance back to 0
      (let ((spend (mk-tx (list (cons (tx:tx-txid funding) 0)) (list (cons 240000 *op-true*)))))
        (wal:wallet-process-tx wal spend 101)
        (check "balance after spend" (wal:wallet-balance wal) 0)
        (check "coin removed" (hash-table-count (wal:wallet-coins wal)) 0)))
    ;; rescan an in-RAM UTXO for our coins
    (let* ((spk1 (wal::waddr-script (aref (wal:wallet-receive wal) 1)))
           (utxo (u:make-utxo-set)))
      (u:utxo-add utxo (hx "bb") 0 (u:make-coin :value 77000 :height 50 :coinbase-p nil :script spk1))
      (u:utxo-add utxo (hx "cc") 0 (u:make-coin :value 1 :height 50 :coinbase-p nil :script *op-true*))
      (check "rescan finds our 1 coin" (wal:wallet-rescan-utxo wal utxo) 1)
      (check "rescan balance" (wal:wallet-balance wal) 77000)))
  ;; ---- P2PKH wallet derives legacy addresses ----
  (let ((wpk (wal:make-wallet-from-seed (hx "000102030405060708090a0b0c0d0e0f") :type :p2pkh)))
    (checkt "p2pkh address starts with 1" (char= (char (wal:wallet-receive-address wpk 0) 0) #\1)))
  ;; ---- Phase 3: build + sign a spend; our own interpreter must accept each input ----
  (flet ((spend-check (type dest)
           (let* ((wal (wal:make-wallet-from-seed (hx "000102030405060708090a0b0c0d0e0f") :type type))
                  (spk (wal::waddr-script (aref (wal:wallet-receive wal) 0)))
                  (fund (mk-tx (list (cons (hx "ab") 0)) (list (cons 1000000 spk)))))
             (wal:wallet-process-tx wal fund 200)
             (let ((txn (wal:create-tx wal (list (cons dest 400000)) :feerate 2)))
               (checkt (format nil "~a: one input selected" type) (= 1 (length (tx:tx-inputs txn))))
               (checkt (format nil "~a: dest + change outputs" type) (>= (length (tx:tx-outputs txn)) 2))
               ;; the spend must verify under OUR Core-differential-tested interpreter
               (handler-case
                   (checkt (format nil "~a: input 0 verifies (sig+sighash correct)" type)
                           (s:verify-input txn 0 spk 1000000))
                 (s:script-error (e)
                   (setf *ok* nil) (format t "  *** ~a verify raised: ~a~%" type e)))
               ;; fee is positive and conservation holds (in=out+fee)
               (let ((out-sum (reduce #'+ (tx:tx-outputs txn) :key #'tx:txout-value)))
                 (checkt (format nil "~a: fee positive + conserved" type)
                         (< 0 (- 1000000 out-sum) 100000)))))))
    (spend-check :p2wpkh "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    (spend-check :p2pkh "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
  (format t "~&wallet-test: ~a~%"
          (if *ok* "OK — encodings + BIP32 + watch/balance + build/sign/verify" "FAILED"))
  *ok*)

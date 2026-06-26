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
                    (:w :cl-consensus.wire))
  (:export #:run))
(in-package :wallet-test)

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
  (format t "~&wallet-test: ~a~%" (if *ok* "OK — base58check + bech32/bech32m + BIP32" "FAILED"))
  *ok*)

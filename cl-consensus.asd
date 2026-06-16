;;;; cl-consensus.asd

(defsystem "cl-consensus"
  :description "A from-scratch, clean-room Bitcoin consensus engine and full node
                in Common Lisp — differential-tested to 100% against Bitcoin Core's
                script test suite."
  :version "0.1.0"
  :license "MIT"
  :depends-on ("ironclad" "usocket" "bordeaux-threads" "com.inuoe.jzon" "hunchentoot")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:module "crypto"
      :serial t
      :components ((:file "secp256k1")    ; ECDSA over secp256k1
                   (:file "schnorr")))    ; BIP340 schnorr (taproot)
     (:file "wire")        ; serialization, message envelope, network params
     (:file "tx")          ; transactions (legacy + segwit), txid/wtxid
     (:file "peer")        ; P2P: handshake, message loop
     (:file "chain")       ; header chain: PoW, retarget, MTP, sync
     (:file "utxo")        ; UTXO set
     (:file "block")       ; block parse, merkle root, block download
     (:file "script")      ; the Script interpreter + sighash (the consensus core)
     (:file "validate")    ; connect/disconnect-block, consensus rules, IBD
     (:file "mempool")     ; mempool acceptance
     (:file "node")))))    ; daemon: JSON-RPC + control socket

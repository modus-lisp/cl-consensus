;;;; cl-consensus.asd

(defsystem "cl-consensus"
  :description "A from-scratch, clean-room Bitcoin consensus engine and full node
                in Common Lisp — differential-tested to 100% against Bitcoin Core's
                script test suite."
  :version "0.1.0"
  :license "MIT"
  :depends-on ("secp256k1-fast" "pagetree" "ironclad" "usocket" "bordeaux-threads" "com.inuoe.jzon" "hunchentoot" "cl-transport")
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
     (:file "encoding")    ; base58check + bech32/bech32m (addresses, xprv/xpub)
     (:file "bip32")       ; HD key derivation (master/CKD, xprv/xpub)
     (:file "tx")          ; transactions (legacy + segwit), txid/wtxid
     (:file "peer")        ; P2P: handshake, message loop
     (:file "addrman")     ; address pool (dedup) for peer discovery
     (:file "discovery")   ; DNS seeds + getaddr-driven peer pool
     (:file "chain")       ; header chain: PoW, retarget, MTP, sync
     (:file "utxo-disk")   ; mmap open-addressing slot table (disk UTXO core)
     (:file "utxo-pagetree") ; pagetree CoW-B+tree UTXO backend (modus-portable A/B)
     (:file "utxo")        ; UTXO set (in-RAM + disk-backed via utxo-disk / pagetree)
     (:file "block")       ; block parse, merkle root, block download
     (:file "blockstore")  ; append-only raw-block store (serve blocks we've fetched)
     (:file "script")      ; the Script interpreter + sighash (the consensus core)
     (:file "validate")    ; connect/disconnect-block, consensus rules, IBD
     (:file "reorg")       ; tip reorg / best-chain activation
     (:file "mempool")     ; mempool acceptance + relay policy (fee/dust/RBF/eviction)
     (:file "fees")        ; mempool-based fee estimation (estimatesmartfee)
     (:file "serve")       ; network citizen: inbound listener + serve headers/blocks + tx relay
     (:file "node")        ; daemon: JSON-RPC + control socket + consolidated serve-node
     (:file "wallet")      ; HD wallet: addresses, watch/balance, build+sign+broadcast
     (:file "bip39")       ; BIP39 mnemonic seed phrases (entropy<->words, seed)
     (:file "bip39-wordlist") ; canonical 2048-word English list (order matters)
     (:file "wallet-store")   ; persist/restore a wallet (seed + tracked coins)
     (:file "rpc-wallet")     ; wallet-backed JSON-RPC (getnewaddress/sendtoaddress/...)
     (:file "taproot-script")))))  ; BIP341 taproot script-path spend construction

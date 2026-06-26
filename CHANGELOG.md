# Changelog

All notable changes to cl-consensus. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0 and the
API may still change.

## [0.1.0] — unreleased

First public-ready cut: a from-scratch, clean-room Bitcoin consensus engine, full
node, and HD wallet in Common Lisp — nothing wraps Core.

### Consensus & validation
- Complete Script interpreter (legacy / segwit-v0 / taproot), all sighash schemes,
  ECDSA + BIP340 Schnorr — **differential-tested to 100% agreement with Core's
  `script_tests.json` (1217/1217)** and fuzzed against Core's compiled
  `libbitcoinkernel` (0 divergence).
- connect/disconnect-block with full rules: no-double-spend, coinbase maturity,
  value conservation, subsidy/halving, weight + sigop limits, BIP30/34/68/113/141,
  CLTV/CSV, witness commitment; height-gated soft-fork activation.
- Resumable IBD; disk-backed UTXO via the pagetree CoW B+tree.
- **Reorg**: best-chain activation by cumulative work with a persistent undo store;
  digest-exact vs a fresh build of the winning branch (verified with real-mined blocks).

### Networking & node
- P2P handshake + async message loop; header-chain sync (PoW/retarget/MTP).
- **Network peer**: inbound listener; serve headers + blocks; **relay** new blocks
  (BIP130 headers / inv) and transactions; advertise NODE_NETWORK.
- **Mempool** with relay policy: min-relay feerate + dynamic floor, dust/weight/
  finality standardness, BIP125 opt-in RBF, parent/child packages, size-cap
  eviction, expiry, and **persistence** across restarts (re-validated on load).
- **Consolidated `serve-node`**: a single-writer daemon that validates each block to
  the tip (reorg-aware) while serving + relaying with a tip-current UTXO + mempool.
- bitcoind-compatible JSON-RPC (chain, mempool, and wallet methods) + a control socket.

### Wallet
- BIP39 mnemonics (generate + restore + passphrase), BIP32 HD derivation.
- Addresses & spending: P2PKH, P2WPKH, P2TR — taproot **key-path and script-path**
  (including multi-leaf taptrees). Coin selection, fee estimation, signing, broadcast.
- At-rest encrypted persistence (PBKDF2 + AES-256 + HMAC); wallet JSON-RPC.

### Regtest & tooling
- Real regtest harness: select the network, **mine** blocks (nonce-grinding), and
  drive mine → fund → spend → mine → confirm, plus real-mined reorgs.
- `inspect/run-all.sh` runs the full offline gate suite; `inspect/regression.sh`
  runs the differential-vs-Core regression.

### Notes
- Crypto and the pagetree store live in sibling repos (`secp256k1-fast`, `pagetree`).
- **Not audited.** Research/educational; do not custody real funds. See the README.

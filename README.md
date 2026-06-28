# cl-consensus

A from-scratch, clean-room **Bitcoin consensus engine and full node in Common Lisp.**

It speaks the P2P protocol, syncs and validates the header chain, parses blocks
and transactions, runs a complete Script interpreter, maintains a UTXO set with
full consensus validation and reorg handling, accepts transactions into a
relay-policy mempool, **serves and relays** to other peers, drives an **HD
wallet** (BIP39/32, send + receive), and serves a bitcoind-compatible JSON-RPC
API — with a **regtest** harness that mines and confirms its own transactions.

The point of difference from existing wrappers (e.g. an FFI binding to libsecp /
Bitcoin Core) is that **nothing here wraps Core** — the consensus rules, the
script interpreter, secp256k1/ECDSA and BIP340 Schnorr are all re-implemented in
Lisp. It's the open analog of `libbitcoinkernel` ("Core's consensus, extracted"),
except independently derived and **differential-tested to 100% agreement with
Bitcoin Core's `script_tests.json` (1217/1217)**.

## ⚠️ Status & disclaimer

cl-consensus is a **clean-room, from-scratch** implementation — differential-tested
to 100% agreement with Bitcoin Core's `script_tests` and exercised against mainnet —
but it has **NOT been audited or hardened for production**. It is **research /
educational software**. Do **not** rely on it as your only validator, and do **not**
use the wallet to custody real funds. The crypto's secret operations (key
generation and ECDSA/Schnorr signing) are constant-time on the x86-64/arm64
backend — but only at the algorithm + field-arithmetic level; a GC'd runtime
gives no formal microarchitectural guarantee, and the portable fallback is
variable-time. No warranty of any kind (see [LICENSE](LICENSE)).

## Status

- **P2P** — version/verack handshake, ping/pong, async message loop, block download.
- **Header chain** — proof-of-work, difficulty retarget, median-time-past,
  cumulative work, getheaders/headers sync. Verified 8/8 vs Core RPC.
- **Transactions / blocks** — legacy + segwit (BIP144) parse, txid/wtxid, merkle root.
- **Script** — full opcode set; legacy / BIP143 / BIP341 sighash; ECDSA + Schnorr;
  P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR (key-path + tapscript); the SCRIPT_VERIFY
  rule set (MINIMALDATA, DERSIG/STRICTENC, LOW_S, NULLDUMMY, NULLFAIL, CLEANSTACK,
  WITNESS_PUBKEYTYPE, …). **100% conformance with Core's script_tests.**
- **Validation** — connect/disconnect-block, no-double-spend, coinbase maturity,
  value conservation, subsidy/halving, weight + sigop limits, BIP30/34/68/113/141,
  CLTV/CSV, witness-commitment, height-gated soft-fork activation, resumable IBD.
- **Reorg** — best-chain activation by cumulative work, disconnect/reconnect with a
  persistent undo store; digest-exact vs a fresh build of the winning branch.
- **Network peer** — inbound listener; serve headers + blocks (getheaders/getdata);
  **relay** new blocks (BIP130 headers / inv) and transactions; advertise NODE_NETWORK.
- **Mempool** — relay policy: min-relay feerate + dynamic floor, dust/weight/finality
  standardness, BIP125 opt-in RBF, parent/child packages, size-cap eviction, expiry,
  and **persistence** across restarts (`mempool.dat`, re-validated on load).
- **Wallet** — BIP39 mnemonics (generate + restore + passphrase), BIP32 HD; P2PKH /
  P2WPKH / P2TR (taproot **key-path and script-path**, incl. multi-leaf taptrees);
  coin selection, fee estimation, signing, broadcast; encrypted at-rest persistence.
- **Node** — a consolidated **single-writer** daemon that validates each block to the
  tip (reorg-aware) while serving + relaying with a tip-current UTXO + mempool;
  bitcoind-compatible JSON-RPC (incl. wallet methods), control socket, live follow.
- **Regtest** — a real harness: select the regtest network, **mine** blocks (real
  nonce-grinding), and drive the full loop — mine → fund a wallet → build a spend →
  accept to the mempool → mine it into a block → confirm — plus real-mined reorgs.

For the full inventory of how correctness is validated — every layer, every
harness, every number — see **[VERIFICATIONS.md](VERIFICATIONS.md)**.

## Layout

```
cl-consensus.asd        ASDF system
src/
  crypto/                secp256k1 ECDSA + BIP340 Schnorr shims over secp256k1-fast
  wire tx peer chain     P2P, serialization, header chain
  utxo block script      UTXO set, block/merkle, the Script interpreter + sighash
  validate reorg         connect/disconnect-block, IBD, best-chain activation
  mempool serve node     relay-policy mempool, serve/relay layer, the daemon
  encoding bip32 bip39    base58check/bech32(m), HD derivation, mnemonics
  wallet wallet-store     HD wallet (addresses/balance/spend) + (encrypted) persistence
  rpc-wallet taproot-script  wallet JSON-RPC; taproot script-path construction
inspect/
  run-all.sh            ONE command: the full OFFLINE gate suite (no Core/network)
  regression.sh         differential vs Core: fetch vectors, conformance + block sweep
  conformance / core-diff / oracle / difftest   the vs-Core harnesses (need a peer/FFI)
  *-test.lisp           the offline gates (wallet, mempool, regtest, reorg, serve, …)
VERIFICATIONS.md        the full correctness-validation inventory
bin/cl-consensus.lisp   run the daemon
```

## Dependencies

Pure SBCL + a few Quicklisp libs (`ironclad`, `usocket`, `bordeaux-threads`,
`com.inuoe.jzon`, `hunchentoot`) — **plus two companion repos** that are not yet on
Quicklisp: `secp256k1-fast` (the crypto) and `pagetree` (the disk-backed UTXO store).
They're vendored as git submodules under `deps/`, so clone recursively:

```sh
git clone --recursive https://github.com/modus-lisp/cl-consensus.git
# (already cloned?  git submodule update --init)
```

Point ASDF at the tree (or symlink the systems into `~/quicklisp/local-projects/`):

```sh
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$PWD\") :inherit-configuration)"
```

`inspect/run-all.sh` sets this up automatically and also works with a side-by-side
sibling checkout of the two repos.

## Quick start

```lisp
(asdf:load-system "cl-consensus")
```

Run the full offline gate suite (wallet, mempool, regtest, reorg, serve/relay, …):

```sh
inspect/run-all.sh
```

Make a wallet and an address (REPL):

```lisp
(multiple-value-bind (wallet mnemonic)
    (cl-consensus.bip39:generate-wallet :type :p2wpkh)   ; fresh BIP39 + BIP84 wallet
  (format t "~&backup phrase: ~a~%" mnemonic)
  (format t "receive address: ~a~%" (cl-consensus.wallet:wallet-receive-address wallet 0)))
;; backup phrase: legal winner thank year wave ...
;; receive address: bc1q...
```

Restore it later with
`(cl-consensus.bip39:make-wallet-from-mnemonic "<phrase>" :type :p2wpkh)`.

Run the node — `serve-node`: validate each block to the tip while serving +
relaying, with JSON-RPC on :8432 and a control socket on :4008. It syncs from a
peer (a local `bitcoind` on 127.0.0.1 by default; set `CL_CONSENSUS_PEER`) and
keeps its chainstate under `~/.cl-consensus/`. A mainnet UTXO is large, so give it
a big heap:

```sh
CL_CONSENSUS_PEER=127.0.0.1 sbcl --dynamic-space-size 81920 --load bin/cl-consensus.lisp
```

(Pure-Lisp validation makes a from-scratch IBD slow; point it at a peer you trust
and let it follow the tip. For an RPC server over a static chainstate without full
validation, call `cl-consensus.node:start` instead.)

Differential regression against Bitcoin Core (after any change to the interpreter):

```sh
inspect/regression.sh        # conformance vs vectors + confirmed-block sweep + (if built) FFI fuzz
```

For the **hardcore** gate — diffing against Core's *actual compiled code* — build
`libbitcoinkernel` (v29.1) + the C shim once, then fuzz against it:

```sh
inspect/build-libkernel.sh                          # checks out v29.1, builds libbitcoinkernel + core_shim.so
sbcl --load inspect/core-diff.lisp \
     --eval '(in-package :core-diff)' \
     --eval '(vectors)' --eval '(fuzz-mutate 200000)'
```

`core_shim.cpp` calls Core's `VerifyScript` directly, so we pass the FULL
`SCRIPT_VERIFY_*` flag set (consensus + policy, incl. TAPROOT) — `(vectors)`
re-runs all of Core's `script_tests` through its live v29 code, and the fuzzers run
random + mutated scripts
through both Core and us, flagging any divergence with a reproducer. (0 so far.)

The live tools (`oracle.lisp`, `difftest.lisp`) expect a reachable Bitcoin Core
node for P2P (sync from) and JSON-RPC (ground-truth oracle); set the host/cookie
at the top of those files.

## License

MIT.

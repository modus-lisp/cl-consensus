# cl-consensus

A from-scratch, clean-room **Bitcoin consensus engine and full node in Common Lisp.**

It speaks the P2P protocol, syncs and validates the header chain, parses blocks
and transactions, runs a complete Script interpreter, maintains a UTXO set with
full consensus validation and reorg handling, accepts transactions into a
mempool, and serves a bitcoind-compatible JSON-RPC API.

The point of difference from existing wrappers (e.g. an FFI binding to libsecp /
Bitcoin Core) is that **nothing here wraps Core** — the consensus rules, the
script interpreter, secp256k1/ECDSA and BIP340 Schnorr are all re-implemented in
Lisp. It's the open analog of `libbitcoinkernel` ("Core's consensus, extracted"),
except independently derived and **differential-tested to 100% agreement with
Bitcoin Core's `script_tests.json` (1217/1217)**.

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
- **Node** — mempool acceptance, JSON-RPC daemon, control socket, live chain-follow.

## Layout

```
cl-consensus.asd        ASDF system
src/
  crypto/secp256k1.lisp ECDSA over secp256k1 (no FFI)
  crypto/schnorr.lisp   BIP340 Schnorr
  wire tx peer chain utxo block script validate mempool node   (the layers)
inspect/
  conformance.lisp      run Core's script_tests.json through our interpreter
  block-sweep.lisp      stable regression: verify a confirmed block's in-block spends
  difftest.lisp         live differential vs a Core node's mempool (RPC oracle)
  oracle.lisp           ground-truth cross-check vs Core RPC
  regression.sh         one-command: fetch vectors, run both gates, PASS/FAIL
bin/cl-consensus.lisp   run the daemon
```

## Quick start

```lisp
(asdf:load-system "cl-consensus")
```

Run the daemon (JSON-RPC on :8432, control socket on :4008):

```sh
sbcl --load bin/cl-consensus.lisp
```

Differential regression against Bitcoin Core (after any change to the interpreter):

```sh
inspect/regression.sh        # conformance vs vectors + confirmed-block sweep + (if built) FFI fuzz
```

For the **hardcore** gate — diffing against Core's *actual compiled code* — build
`libbitcoinconsensus` once and fuzz against it:

```sh
inspect/build-libconsensus.sh                       # checks out bitcoin v26.2, builds the lib
sbcl --load inspect/core-diff.lisp \
     --eval '(in-package :core-diff)' --eval '(fuzz-mutate 200000)'
```

This FFIs into Core's real `interpreter.cpp` and runs random + mutated scripts
through both Core and us, flagging any divergence with a reproducer. (0 so far.)

The live tools (`oracle.lisp`, `difftest.lisp`) expect a reachable Bitcoin Core
node for P2P (sync from) and JSON-RPC (ground-truth oracle); set the host/cookie
at the top of those files.

## License

MIT.

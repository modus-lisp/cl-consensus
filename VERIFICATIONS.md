# Verifications

`cl-consensus` is a **clean-room** re-implementation of Bitcoin's consensus
rules — nothing here wraps Bitcoin Core. That makes correctness the whole game:
a clean-room consensus engine that disagrees with the network by one rule is
worse than useless, because it would fork off or reject valid blocks.

So every layer is checked against an **independent ground truth**. We use three,
in increasing strength:

1. **Recorded vectors** — Bitcoin Core's own `script_tests.json` (the static
   expected results checked into Core's tree).
2. **Core's compiled code** — an FFI shim into the *actual* compiled
   `libbitcoinkernel` (v29.1), so we diff against the bytes Core ships, not a
   transcription of them.
3. **The live network** — a real mainnet `bitcoind` peered over P2P and queried
   over JSON-RPC as an oracle, plus real mainnet blocks and signatures.

This document is the inventory of what has been checked, how, and the result.
Everything marked **GATE** is reproducible and wired into `inspect/regression.sh`;
everything marked **MILESTONE** is a one-time end-to-end result.

> One command runs the standing gates:
> ```
> inspect/regression.sh
> ```
> It fetches Core's vectors, then runs the conformance gate, the block-900000
> sweep, and the compiled-Core FFI differential, exiting non-zero on any
> divergence.

---

## 1. Script interpreter — the consensus core

### 1.1 Static conformance vs Core's `script_tests.json` — **GATE**

Every case in Core's script test suite is reconstructed exactly as Core's
`script_tests.cpp` does (a synthetic credit tx funding the scriptPubKey, a spend
tx carrying the scriptSig/witness) and run through our `verify-input` under the
exact per-case `SCRIPT_VERIFY_*` flag set.

| Metric | Result |
|---|---|
| Cases | **1217 / 1217 (100%)** |
| False positives (we accept, Core rejects) | **0** |
| False negatives (we reject, Core accepts) | **0** |

A false negative is treated as a hard failure (`max-fn 0` in the gate): rejecting
a script Core accepts could reject a valid block.

- Harness: `inspect/conformance.lisp` (`btc-conf:run` / `btc-conf:ci`)
- Vectors compiled from Core's raw assembly mini-language to bytes **in Lisp**
  (`inspect/vectors.lisp`, `btc-vectors:load-script-tests`) — no external tooling.

### 1.2 Differential vs Core's *compiled* `libbitcoinkernel` — **GATE**

The hardcore check: a C++ shim (`inspect/core_shim.cpp`) calls Core's real
`VerifyScript` from the compiled v29.1 `libbitcoinkernel`, and we diff our
verdict against it over the **full** `SCRIPT_VERIFY_*` set (consensus + policy +
TAPROOT). Built with `inspect/build-libkernel.sh`; driven by `inspect/core-diff.lisp`.

| Differential | Cases | Divergences |
|---|---|---|
| All `script_tests` through Core's live code | 1217 | **0** (Core-vs-ours), **0** (Core-vs-recorded) |
| Random script fuzz, full flag set | 100k+ historical / 3k per gate run | **0** |
| Mutation fuzz over the corpus | 100k+ historical / 3k per gate run | **0** |
| Constructed taproot spends (key-path + tapscript) + witness mutations | per gate run | **0** |
| Core's `script_assets_test.json` (full taproot/tapscript spends) | **5235** | **0** (Core-vs-ours), **0** (Core-vs-expected) |

The `script_assets_test.json` corpus is the deepest tapscript test: full spending
transactions with all prevouts, exercising OP_SUCCESS, unknown tapleaf versions,
the tapscript sigops budget, CODESEPARATOR, unknown sighash types, annexes,
multi-input mixes, and the rare opcodes. (It is bring-your-own — Core's Python
test framework generates it — and gated only when present.)

### 1.3 Bugs this found and fixed

Differential testing isn't decoration; it found real consensus bugs in our own
code, each fixed and now regression-gated:

- **DoS** — a huge `PUSHDATA4` length OOM'd the reader (now bounded).
- **BIP141 forward-compatibility** — unknown/future witness programs must be
  anyone-can-spend; we had hard-coded v1–v32.
- **CLTV/CSV** — must *not* be `DISCOURAGE_UPGRADABLE_NOPS`-discouraged when their
  own flag is off (Core excludes NOP2/NOP3).
- **STRICTENC** — pubkey encoding must be checked even for an empty signature.
- **Order-dependent lazy init** — secp256k1 constants were set lazily inside
  `ecdsa-verify`, so the first verify in a fresh image could silently fail; now
  initialized at load. (Surfaced by the stable block sweep, §3.)
- **Full BIP342 tapscript** — OP_SUCCESS, unknown tapleaf versions (anyone-can-
  spend), the sigops budget, tapscript CHECKSIG/CHECKSIGADD semantics,
  CODESEPARATOR position, unknown-sighash-type rejection, consensus MINIMALIF.
  Drove `script_assets` divergences from 2176 → 0.

---

## 2. Real mainnet signatures

### 2.1 Block-900000 self-contained sweep — **GATE**

Download a confirmed mainnet block and verify every input that spends an output
created **earlier in the same block** — so all prevouts are self-contained (no
UTXO set, no RPC race). Real mainnet blocks are valid, so every such input *must*
verify; any failure is a regression.

| Block | Inputs verified | Failures |
|---|---|---|
| 900000 | **598** (P2PKH + P2WPKH + P2WSH) | **0** |

- Harness: `inspect/block-sweep.lisp` (`btc-sweep:run`). 94 taproot inputs in the
  block are skipped here because they need the full prevout set (verified instead
  via §1.2's constructed + asset taproot differentials).

### 2.2 Historic spends — **MILESTONE**

- **Block 170** (the first Bitcoin transaction, Satoshi → Hal Finney): parsed,
  merkle root recomputed, the 10-BTC spend verified end-to-end.
- Legacy + segwit-v0 across the chain: the genesis→20000 full-verify run (§4).

---

## 3. Live network differential

A real mainnet `bitcoind` on `epyc-docker.lan` is peered over P2P (sync source)
and queried over JSON-RPC (ground-truth oracle).

- **Header chain vs Core RPC** — `inspect/oracle.lisp` (`check-headers` /
  `check-tip`) cross-checks our hashes against Core's `getblockhash`: **8/8**
  sampled heights match (genesis, all four halvings, recent tip).
- **Live mempool differential** — `inspect/difftest.lisp` pulls Core-accepted
  mempool txs + their prevouts and runs our verifier on every input. ~99/100
  agree; the residue is RPC races (mempool churns in seconds, so a prevout can be
  spent between fetches), **not** consensus divergence — which is exactly why the
  *stable* block-900000 sweep (§2.1), not the live mempool, is the gate.

---

## 4. Chain validation & state

End-to-end results from running the engine (**MILESTONE** unless noted):

- **Header chain** — 953,865 headers synced; proof-of-work, difficulty retarget,
  and median-time-past all enforced; all four halving block hashes match the
  public record.
- **Full block validation** — genesis → height 20000 validated with
  connect-block + a live UTXO set: no double-spends, coinbase maturity, and
  **exact value conservation** (1,000,000 BTC issued matches the subsidy schedule).
- **Reorg** — disconnect-block + undo data round-trips to a **digest-exact** UTXO
  set (an order-independent set commitment); reorg restores byte-for-byte.
- **Resumable IBD** — a checkpointed resume produces a UTXO set **byte-identical**
  to a fresh build to the same height.
- **Consensus edge rules** — block weight, sigop limits, BIP30/34 (duplicate
  coinbase / height-in-coinbase), BIP68 relative locktime, BIP113 (MTP for
  IsFinalTx), BIP141 witness commitment — all verified no-false-reject against
  real blocks, and witness-commitment tampering is rejected.
- **Soft-fork activation** — `SCRIPT_VERIFY_*` flags are applied by buried
  activation height (P2SH, DERSIG, CLTV, CSV, segwit+NULLDUMMY, taproot), so
  historical blocks validate under the rules that were actually in force.

> Note on scope: full-verify IBD all the way to the tip is impractical in pure
> Lisp (ECDSA is slow), so the node intentionally validates to a chosen height
> and uses `assumevalid` for the tip — a performance choice, not a correctness gap.

---

## 5. Node interface

- **JSON-RPC** — responses verified **field-for-field** against Core for the
  implemented methods.
- **Mempool acceptance** — `sendrawtransaction` / `testmempoolaccept` validate
  against the UTXO set + mempool (fees, double-spend, check-only), verified with
  a real transaction.
- **Live chain-follow** — the node tracks Core's tip in real time; caught up over
  a range of new blocks with matching hashes.

---

## How to reproduce

```sh
# Standing gates (conformance + block sweep + compiled-Core FFI differential):
inspect/regression.sh

# Just the static conformance suite:
sbcl --load inspect/conformance.lisp --eval '(btc-conf:ci "inspect/vectors/script_tests.json")'

# The compiled-libbitcoinkernel differential (build the shim first):
inspect/build-libkernel.sh
sbcl --load inspect/core-diff.lisp --eval '(core-diff:ci)'

# Cross-check header hashes against a live Core node (needs RPC cookie):
sbcl --load inspect/oracle.lisp --eval '(btc-oracle:check-headers)'
```

The compiled-Core differential needs `libbitcoinkernel` v29.1 built locally
(`inspect/build-libkernel.sh`); without it, `regression.sh` skips that gate and
still runs conformance + the block sweep.

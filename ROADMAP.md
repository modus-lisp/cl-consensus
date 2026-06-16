# bitcoind from scratch, in Common Lisp

A full validating Bitcoin node, built bottom-up in SBCL. Going all the way:
P2P, header chain, block/tx parsing, the Script interpreter, the UTXO set, full
consensus validation, mempool, and a bitcoind-compatible JSON-RPC surface.

## Guiding principle: verify against a real node at every layer

We have a real mainnet bitcoind on `epyc-docker.lan` (192.168.5.135):

- **P2P (8333)** — we peer with it to *sync from*. No auth needed.
- **RPC (8332)** — we use it as a *ground-truth oracle* to check our results
  (`getbestblockhash`, `getblockheader`, `getblock`, `gettxoutsetinfo`, ...).
  Needs credentials (the node's `.cookie` or rpcuser/pass).

Every phase below has a milestone that is *checkable against that node*. We never
trust our own output where we can diff it against Bitcoin Core.

## Environment

- Storage: `/mnt/lisp/bitcoind/` (1.5 TB ZFS). Headers (~80 MB) can live under
  `~/.battle/bitcoind/` until the volume is chown'd writable. Full blocks (~650 GB)
  and the UTXO set need `/mnt/lisp`.
- SBCL 2.2.9. Libs: `usocket`, `bordeaux-threads`, `ironclad`, `sqlite`,
  `com.inuoe.jzon`. Existing reusable crypto in `shared/crypto/`
  (`secp256k1`, `schnorr` — for Phase 4 signature checks).
- Entrypoint (eventual): `bin/bitcoind.lisp` → `shared/bitcoind/node.lisp`,
  control socket for hot-reload, REPL contract on 127.0.0.1.

## Layout

```
shared/bitcoind/
  wire.lisp      Phase 0  serialization, message envelope, net params   [DONE]
  peer.lisp      Phase 1  one P2P connection: handshake, msg loop        [DONE]
  chain.lisp     Phase 2  header parse, PoW, retarget, chain store       [WIP]
  tx.lisp        Phase 3  transaction parse (legacy + segwit)
  block.lisp     Phase 3  block parse, merkle root
  script.lisp    Phase 4  the Script interpreter + sighash
  utxo.lisp      Phase 5  coin DB on /mnt/lisp
  validate.lisp  Phase 5  consensus rules, BIP activations, IBD
  node.lisp      Phase 6  peer manager, mempool, JSON-RPC, daemon
  inspect/       persistent REPL inspectors (--load)
```

Packages: `battle.btc.<layer>`, nicknames `btc-wire`, `btc-peer`, ...

## Phases

| # | Layer | Milestone (verifiable against epyc) | State |
|---|-------|-------------------------------------|-------|
| 0 | Wire format | round-trip encode/decode | ✅ |
| 1 | P2P peer | handshake; read peer height/subver | ✅ (953865, Satoshi 29.2.0) |
| 2 | Header chain | sync ~950k headers; PoW + retarget + MTP valid | ✅ (953865 in 18.7s; all 4 halvings + genesis/100k/170 hashes match public record) |
| 3 | Block + tx | block hash + merkle root self-consistent | ✅ (block 170 = Satoshi→Hal 10 BTC tx; modern 1562-tx segwit block merkle ✓) |
| 4 | Script | verify real mainnet inputs across script types | ✅ **100% on Core's script_tests.json (1217/1217)**; legacy + segwit-v0 (598/598 real sigs) + taproot keypath (7/7 BIP341) + tapscript round-trip |
| 5 | UTXO + validation + IBD | full consensus validation; reorg; ground-truth cross-check | ✅ engine (genesis→20000 full-verify, exact conservation); reorg round-trip digest-exact; weight/sigop/BIP30/BIP34; tapscript round-trip; **header chain 8/8 == Core `getblockhash` via RPC oracle**; resumable IBD (checkpoint == fresh). Per operator: stop at a height (no tip chase); disk-backed UTXO deferred |
| 6 | Mempool + RPC + relay + daemon | `bitcoin-cli`-style calls return correct data | ✅ daemon (`node.lisp`, `bin/bitcoind.lisp`); JSON-RPC matches Core **field-for-field**; control-socket hot-reload; **mempool + sendrawtransaction/testmempoolaccept** (real-tx verified); **live chain-follow** (tip tracks Core in real time). Remaining nicety: serving relay (answering peers' getheaders/getdata) + block-level live validation (needs tip UTXO) |

### Differential testing against Bitcoin Core
- `inspect/conformance.lisp` runs Core's `script_tests.json` (1,217 cases) through
  our interpreter via reconstructed credit/spend txs. **100% agree, 0 FP, 0 FN**
  (up from 62% at the start of the punch-list).
- Bugs found+fixed by the harness: `OP_0` unhandled; CLTV/CSV touching the stack;
  CHECKMULTISIG key/sig comparison order (Core accesses top-of-stack-first);
  hybrid pubkeys (0x06/0x07) unparsed; PUSH_SIZE not checked in dead branches;
  CHECKMULTISIG key count not added to the opcode limit; the secp-init ordering bug.
- Rules now enforced (flag-gated via *FLAGS*, threaded from VERIFY-INPUT):
  always-on stack-underflow / opcode-count / disabled-opcode-scan / push+stack+
  script size / unbalanced-conditional; and MINIMALDATA (minimal scriptnum +
  push), MINIMALIF (witness only), DERSIG/STRICTENC (strict DER, hashtype,
  pubkey encoding), LOW_S, NULLDUMMY, NULLFAIL, WITNESS_PUBKEYTYPE,
  DISCOURAGE_UPGRADABLE_NOPS, SIGPUSHONLY, CLEANSTACK.
- Block-level consensus checks in connect-block: **witness commitment** (BIP141 —
  verified against real block 900000, rejects tampering), **IsFinalTx** (BIP113
  median-time-past), **BIP68** relative sequence-locks (height + time based, via
  UTXO coin height + header-chain MTP). CLTV/CSV opcodes also enforced.
- Remaining: BIP9 versionbits signaling (we use buried activation heights — fine
  for validation), coarse sigop counting, BIP68 time-based path not yet exercised
  against a real time-locked tx. connect-block applies flags by height; zero
  regression on block 900000 + genesis→2000 IBD.
- `inspect/difftest.lisp` — live differential vs the epyc node: pulls Core's
  mempool txs + prevouts (RPC) and verifies each input (incl. real taproot spends).
  Fuzz mode mutates live txs; **0 we-accept-core-rejects**.
- `inspect/core-diff.lisp` — **the hardcore differential: FFI into Core's actual
  compiled `libbitcoinkernel` (v29.1)** via a small C++ shim (`core_shim.cpp`)
  that calls Core's `VerifyScript` directly — so we pass the FULL `SCRIPT_VERIFY_*`
  set (consensus + policy, incl. TAPROOT), beyond the old C API. `(vectors)`
  re-runs all 1217 script_tests through Core's live v29 code (**0 Core-vs-ours,
  0 Core-vs-recorded**); `(fuzz)`/`(fuzz-mutate)` diff random + mutated scripts
  (**0 divergences**). Bugs found+fixed across the libconsensus→libkernel work:
  reader DoS on a huge PUSHDATA4 length; unknown/future witness programs must be
  anyone-can-spend (BIP141) and taproot must be flag-gated; CLTV/CSV must NOT be
  DISCOURAGE_UPGRADABLE_NOPS-discouraged when their flag is off; STRICTENC pubkey
  encoding must be checked even for an empty signature.
- **`inspect/regression.sh` — one-command regression**: fetches Core's vectors,
  runs static conformance + the block-900000 sweep + (if the lib is built) the
  FFI fuzz vs Core's compiled verifier. Exits nonzero on any divergence.
- Latent bug the block-sweep caught: `parse-pubkey` read secp256k1 constants that
  are set lazily by `secp-init` (only called inside `ecdsa-verify`, which runs
  *after* parse-pubkey) — so a verify before any prior ECDSA call silently failed.
  Fixed by initializing secp at script.lisp load. (Order-dependent → also explains
  the earlier "transient" live-mempool divergences.)

### Verification harness now includes the live RPC oracle
`shared/bitcoind/inspect/oracle.lisp` cross-checks our state against the epyc
mainnet node's JSON-RPC (cookie at `/mnt/lisp/bitcoind/.cookie`). `(check-tip)`,
`(check-headers)`. 8/8 sampled heights (genesis, all halvings, recent) match.

### Taproot note (BIP341/342)
The BIP341 sighash commits to **all** of a transaction's spent outputs, so a
taproot input needs the full prevout set. `verify-input` takes `:prevouts` (a
vector of (amount . scriptPubKey) for every input) for this; `connect-block`
supplies it from the UTXO set. Verified: keypath sighash + end-to-end schnorr
for all 7 BIP341 keypath vectors (hashtypes 0/1/2/3 + ANYONECANPAY). Tapscript
(script-path): commitment check + BIP342 interpreter implemented; needs vector
verification + the rarer opcodes.

### Big remaining infra: disk-backed UTXO + full IBD
The in-memory UTXO set won't hold the tip (~180M coins). To validate to the tip
we need a disk-backed coin store (`utxo.lisp` is written behind an abstraction
for exactly this swap) and `assumevalid` (skip script checks below a known-good
hash so IBD finishes in human time; every other rule still runs). Decision
pending: sqlite vs a custom on-disk KV.

### Still pending from operator
- RPC creds for epyc-docker.lan:8332 (the node's `.cookie` or rpcuser/pass) —
  unlocks the `gettxoutsetinfo` cross-check. (/mnt/lisp is now writable ✅.)

## Notes / decisions

- **IBD tractability.** Full script verification of the entire chain in pure Lisp
  is very slow. Plan: support `assumevalid` (skip script checks below a known-good
  block hash, still do everything else) and checkpoints, like Core, so the node
  can actually reach the tip. Full-verify mode stays available for correctness runs.
- **Coin DB.** Start correctness-first (sqlite) for the UTXO set; the set is
  ~100M+ entries so writes during IBD will be the bottleneck — revisit with a
  custom on-disk structure once the rules are proven correct.
- **Hashes** are stored internally little-endian; `hash->hex` reverses for display
  (matches Core's RPC output).

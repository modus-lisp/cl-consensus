# IBD log — blocks that needed fixes

A running record of consensus divergences surfaced by running a **real mainnet
Initial Block Download** against the local full node, and the fixes they drove.

The differential test suite (`inspect/regression.sh`: Core's `script_tests.json`
at 100%, the block-900000 sweep, and 100k+ libbitcoinkernel FFI fuzz rounds) is
green — yet the live chain keeps finding bugs the vectors never exercise.
Historical mainnet has script shapes no test vector bothers to encode. **Each
entry below is a block where we rejected an input Core accepts** (a
false-negative — the dangerous direction: a real node would fork off the chain).

## Run setup

- **Peer / oracle:** local Core node `epyc-docker.lan` — P2P `:8333` (sync blocks
  from), JSON-RPC `:8332` (ground-truth oracle, cookie `/mnt/lisp/bitcoind/.cookie`).
- **Driver:** load `headers.dat` → `connect-peer` → `resume-ibd :batch 500
  :save-every 10000`. The UTXO checkpoint (`/mnt/lisp/bitcoind/chainstate.dat`)
  auto-advances every 10k blocks, so a halt resumes from the last checkpoint.
- **Verification:** `connect-block` fans each block's script checks across cores
  (see `verify-block-scripts`); the crypto is `secp256k1-fast`.
- **Repro recipe for a halt at height H, tx T, input I:** pull the raw tx and its
  prevout (scriptPubKey + value) over RPC, then call
  `(cl-consensus.script:verify-input tx I prevout-spk amount :flags
  (cl-consensus.validate:consensus-flags H))` in isolation.

## Incidents

| Height | Tx (txid prefix) | Input | Class | Fix |
|-------:|------------------|:-----:|-------|-----|
| 163,685 | `eb3b82c0…bccb` | 1 | Legacy scriptCode not truncated at executed `OP_CODESEPARATOR` | `e54e764` |
| 290,329 | `5df1375f…232f` | 1 | Legacy `FindAndDelete` of the signature from the scriptCode | `6e1de9b` |

---

### Height 163,685 — `OP_CODESEPARATOR` scriptCode truncation

**Tx** `eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb`, input 1
(spends a bare `<20b> OP_NOP2 OP_DROP` output — at this height `0xb1` is still
`OP_NOP2`, a no-op; CLTV isn't until 388,381).

The scriptSig is `0 <sig> OP_CODESEPARATOR 1 <pubkey> 1 OP_CHECKMULTISIG` — the
`CHECKMULTISIG` executes *inside the scriptSig*, after an `OP_CODESEPARATOR`, so
the signature commits only to the subscript **after** the separator
(`1 <pubkey> 1 OP_CHECKMULTISIG`).

**Bug:** `eval-script` recorded the separator position only for the *tapscript*
sighash (`ctx-codesep-pos`) and always handed the **full script** to legacy
CHECKSIG/CHECKMULTISIG. We signed over the whole scriptSig → wrong sighash →
rejected a valid input.

**Fix:** track each op's byte offset (`op-byte-length`) and, on an executed
`OP_CODESEPARATOR`, set the legacy scriptCode to the bytes after it — Core's
`pbegincodehash`.

### Height 290,329 — legacy `FindAndDelete` of signatures

**Tx** `5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e379fa513232f`, input 1
(P2SH; flags = `(:p2sh)`, DERSIG not until 363,725).

The P2SH redeemscript is `OP_2 <sig> <pubkey> <pubkey> OP_3 CHECKMULTISIG` — a
2-of-3 with a **signature embedded in a pubkey slot**, and that embedded `<sig>`
is byte-identical to the `SIGHASH_SINGLE` signature the input provides.

**Bug:** legacy CHECKSIG/CHECKMULTISIG must remove each checked signature's push
from the scriptCode before hashing — Core's `FindAndDelete(scriptCode,
CScript() << vchSig)`. We skipped it, so the embedded copy stayed in the
scriptCode → different sighash → rejected. (This is the exact case `FindAndDelete`
exists for, and the reason segwit removed it from BIP143.)

**Fix:** add `serialize-push` (minimal push; empty → `0x00`, matching
`CScript()<<`) and a Core-faithful `find-and-delete` (opcode-boundary walk,
deletes consecutive matches). CHECKSIG strips the one sig; CHECKMULTISIG strips
all provided sigs first, then matches. Gated to the legacy sighash only
(`segwit-version` nil) — segwit v0 / tapscript never call it.

---

*Both bugs are classic pre-segwit legacy-sighash subtleties — historically the
two trickiest corners of the interpreter. After each fix the full regression
stayed at 100% conformance / 0 divergences (incl. the libkernel FFI fuzz).*

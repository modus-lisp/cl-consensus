#!/usr/bin/env bash
# inspect/run-all.sh — run the full OFFLINE gate suite (no network / no Bitcoin Core).
#
#   inspect/run-all.sh
#
# Each gate is a self-contained inspect/<name>.lisp defining (<name>:run) which returns
# T on success.  This runs them all, prints a pass/fail summary, and exits non-zero if
# any gate fails.  For the differential-vs-Core regression (needs Core's vectors + a
# peer), see inspect/regression.sh separately.
set -u
cd "$(dirname "$0")/.."                       # repo root
ROOT="$(pwd -P)"
SBCL="${SBCL:-sbcl}"

# Let ASDF find cl-consensus + its sibling deps (secp256k1-fast, pagetree) whether they
# live beside this repo or wherever the gate files push them.  Sibling layout:
#   <parent>/{cl-consensus,secp256k1-fast,pagetree}
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$ROOT/..\") :inherit-configuration)"

GATES=(
  bip39-test            # BIP39 mnemonics (vs Trezor vectors)
  wallet-test           # encodings + BIP32 + watch/balance + build/sign/verify
  wallet-store-test     # wallet persistence (incl. encrypted)
  rpc-wallet-test       # wallet-backed JSON-RPC
  taproot-script-test   # BIP341 taproot script-path spends
  mempool-test          # policy + RBF + eviction + on-block + persistence
  blockstore-test       # append-only block store + torn-tail recovery
  serve-test            # inbound handshake + serve headers/blocks
  relay-test            # block relay (inv + BIP130 headers announce)
  tx-relay-test         # tx relay (accept + inv + serve + orphans)
  reorg-equiv           # reorg == fresh winning branch
  regtest-test          # real-mined: genesis + mine->send->confirm + reorg
)

pass=0; fail=0; failed=()
echo "== cl-consensus offline gate suite (${#GATES[@]} gates) =="
for g in "${GATES[@]}"; do
  printf '  %-22s ' "$g"
  start=$SECONDS
  if "$SBCL" --non-interactive --load "inspect/$g.lisp" \
        --eval "(unless ($g:run) (sb-ext:exit :code 1))" >/tmp/gate-$g.log 2>&1; then
    printf 'PASS  (%ds)\n' $((SECONDS-start)); pass=$((pass+1))
  else
    printf 'FAIL  (%ds)  -> /tmp/gate-%s.log\n' $((SECONDS-start)) "$g"; fail=$((fail+1)); failed+=("$g")
  fi
done
echo "== $pass passed, $fail failed =="
if [ $fail -gt 0 ]; then echo "failed: ${failed[*]}"; exit 1; fi

#!/usr/bin/env bash
# inspect/regression.sh
#
# One-command differential regression vs Bitcoin Core.  Run after any change to
# the script interpreter / validation:
#
#   inspect/regression.sh
#
# 1. Fetches Core's script_tests.json (cached) and compiles it to hex.
# 2. Runs the static conformance harness (vs Core's vectors) — fails if
#    agreement drops below the threshold or false-negatives appear.
# 3. Runs the stable live block sweep (block 900000 self-contained spends) —
#    fails if any real-mainnet input is wrongly rejected.
#
# Exit 0 = no regression; nonzero = regression (prints which gate failed).

set -uo pipefail
cd "$(dirname "$0")/.."                  # repo root (inspect/ is at the top)
VDIR=inspect/vectors
SBCL="sbcl --dynamic-space-size 4096 --non-interactive"
MIN_AGREE=${MIN_AGREE:-0.99}
SWEEP_HEIGHT=${SWEEP_HEIGHT:-900000}

mkdir -p "$VDIR"
if [ ! -s "$VDIR/script_tests.json" ]; then
  echo "[regression] fetching Core script_tests.json ..."
  curl -sL https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/test/data/script_tests.json \
       -o "$VDIR/script_tests.json" || { echo "fetch failed"; exit 2; }
fi
python3 inspect/compile-vectors.py \
        "$VDIR/script_tests.json" "$VDIR/script_tests_hex.json" || exit 2

echo "[regression] (1/2) static conformance vs Core vectors ..."
# max-fn 0: a false-negative means we'd reject a script Core accepts (could
# reject a valid block) — never tolerated.
$SBCL --load inspect/conformance.lisp \
      --eval "(btc-conf:ci \"$VDIR/script_tests_hex.json\" $MIN_AGREE 0)" 2>&1 \
  | grep -E "AGREE total|FALSE-|CONFORMANCE:"
conf=${PIPESTATUS[0]}

echo "[regression] (2/2) stable block-$SWEEP_HEIGHT sweep vs mainnet ..."
$SBCL --load inspect/block-sweep.lisp \
      --eval "(btc-sweep:run $SWEEP_HEIGHT)" 2>&1 \
  | grep -E "self-contained sweep|REGRESSION:"
sweep=${PIPESTATUS[0]}

# (3/3) optional: diff against Core's *compiled* libbitcoinkernel (full flags +
# all 1217 vectors through live v29 code + fuzz).
LIB=/mnt/lisp/bitcoin-kernel/build/lib/core_shim.so
if [ -e "$LIB" ]; then
  echo "[regression] (3/3) FFI diff vs Core's compiled libbitcoinkernel ..."
  $SBCL --load inspect/core-diff.lisp \
        --eval "(core-diff:ci ${COREDIFF_ROUNDS:-50000})" 2>&1 \
    | grep -E "Core vs|core-diff (random|mutation)|DIVERGE|CORE-DIFF:"
  cdiff=${PIPESTATUS[0]}
else
  echo "[regression] (3/3) skipped — libbitcoinkernel not built (inspect/build-libkernel.sh)"
  cdiff=0
fi

echo "----------------------------------------"
if [ "$conf" -eq 0 ] && [ "$sweep" -eq 0 ] && [ "$cdiff" -eq 0 ]; then
  echo "[regression] PASS — no divergence from Core"; exit 0
else
  echo "[regression] FAIL — conformance=$conf sweep=$sweep core-diff=$cdiff"; exit 1
fi

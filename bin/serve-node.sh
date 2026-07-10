#!/bin/bash
# bin/serve-node.sh — respawn supervisor for the consolidated node (HARNESS).
#
# One long-lived process = single-writer validating follower + serve headers/blocks +
# tx relay + JSON-RPC.  Crash-safe: each restart resumes from the UTXO store's committed
# checkpoint.  SINGLE WRITER — no other process may write the same store concurrently.
#
# This file is reusable; ALL node-specific values come from the environment.  Point
# NODE_ENV at a config file (see bin/node.env.example) or export the vars yourself.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"          # repo root

# node-specific config: a file via NODE_ENV, else whatever is already exported
if [ -n "${NODE_ENV:-}" ]; then
  # shellcheck disable=SC1090
  [ -f "$NODE_ENV" ] && source "$NODE_ENV" || { echo "NODE_ENV=$NODE_ENV not found" >&2; exit 1; }
fi

: "${NODE_DATA:=$HOME/.cl-consensus}"
: "${SERVE_LOG:=$NODE_DATA/serve-node.out}"
: "${SUPERVISOR_LOG:=$NODE_DATA/serve-node-supervisor.log}"
: "${SBCL_HEAP_MB:=8192}"
: "${RESTART_DELAY:=15}"
# Where ASDF finds cl-consensus + its deps — default a :tree over the repo and its parent
# (so sibling checkouts and deps/ submodules are both discoverable).
: "${CL_SOURCE_REGISTRY:=(:source-registry (:tree \"$HERE\") (:tree \"$HERE/..\") :inherit-configuration)}"
export CL_SOURCE_REGISTRY

mkdir -p "$NODE_DATA"
: > "$SERVE_LOG"
echo "[serve-node-sup] starting @ $(date '+%F %H:%M:%S') (heap ${SBCL_HEAP_MB}MB)" | tee -a "$SUPERVISOR_LOG"
for attempt in $(seq 1 1000); do
  echo "[serve-node-sup] attempt $attempt @ $(date '+%F %H:%M:%S')" | tee -a "$SUPERVISOR_LOG"
  sbcl --dynamic-space-size "$SBCL_HEAP_MB" --non-interactive --load "$HERE/bin/serve-node.lisp" >> "$SERVE_LOG" 2>&1
  echo "[serve-node-sup] exit; restart in ${RESTART_DELAY}s @ $(date '+%F %H:%M:%S')" | tee -a "$SUPERVISOR_LOG"
  sleep "$RESTART_DELAY"
done

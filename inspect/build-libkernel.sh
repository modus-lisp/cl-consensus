#!/usr/bin/env bash
# inspect/build-libkernel.sh
#
# Build Bitcoin Core's libbitcoinkernel (v29.1) and our C shim over it, for the
# hardcore differential in inspect/core-diff.lisp.  Outputs:
#   /mnt/lisp/bitcoin-kernel/build/lib/libbitcoinkernel.so   (Core's consensus engine)
#   /mnt/lisp/bitcoin-kernel/build/lib/core_shim.so          (our C entry to VerifyScript)
#
# Calling Core's VerifyScript directly (vs the kernel C API, which only exposes a
# consensus flag subset) lets us pass the FULL SCRIPT_VERIFY_* set incl. TAPROOT.

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC=/mnt/lisp/bitcoin-kernel
cd /mnt/lisp

if [ ! -e "$SRC/build/lib/libbitcoinkernel.so" ]; then
  echo "[k] cloning bitcoin v29.1 (shallow)..."
  rm -rf bitcoin-kernel
  git clone --depth 1 --branch v29.1 https://github.com/bitcoin/bitcoin.git bitcoin-kernel
  cd "$SRC"
  echo "[k] cmake configure (kernel lib only)..."
  cmake -B build \
    -DBUILD_KERNEL_LIB=ON -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF -DBUILD_TESTS=OFF \
    -DBUILD_TX=OFF -DBUILD_UTIL=OFF -DENABLE_WALLET=OFF -DBUILD_GUI=OFF \
    -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DWITH_ZMQ=OFF -DCMAKE_BUILD_TYPE=Release
  echo "[k] building bitcoinkernel..."
  cmake --build build --target bitcoinkernel -j"$(nproc)"
fi

echo "[k] compiling core_shim.so against libbitcoinkernel..."
g++ -std=c++20 -fPIC -shared -O1 -I "$SRC/src" -I "$SRC/build/src" \
  "$ROOT/inspect/core_shim.cpp" \
  -L "$SRC/build/lib" -lbitcoinkernel -Wl,-rpath,"$SRC/build/lib" \
  -o "$SRC/build/lib/core_shim.so"
echo "[k] DONE:"
ls -la "$SRC/build/lib/libbitcoinkernel.so" "$SRC/build/lib/core_shim.so"

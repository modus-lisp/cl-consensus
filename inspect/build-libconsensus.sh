#!/usr/bin/env bash
# inspect/build-libconsensus.sh — build Core's libbitcoinconsensus (v26.2) for core-diff.lisp.
# Outputs /mnt/lisp/bitcoin-core/src/.libs/libbitcoinconsensus.so
set -e
cd /mnt/lisp
rm -rf bitcoin-core
echo "[build] cloning bitcoin v26.2 (shallow)..."
git clone --depth 1 --branch v26.2 https://github.com/bitcoin/bitcoin.git bitcoin-core 2>&1 | tail -2
cd bitcoin-core
echo "[build] autogen..."; ./autogen.sh >/tmp/lc-autogen.log 2>&1
echo "[build] configure (lib only, minimal)..."
./configure --disable-wallet --disable-tests --disable-bench --disable-fuzz-binary \
  --without-gui --with-libs=yes --disable-zmq --without-miniupnpc --without-natpmp \
  --disable-hardening --disable-man CC=gcc CXX=g++ >/tmp/lc-configure.log 2>&1 || { echo "CONFIGURE FAILED"; tail -20 /tmp/lc-configure.log; exit 1; }
echo "[build] make libbitcoinconsensus..."
make -C src libbitcoinconsensus.la -j"$(nproc)" >/tmp/lc-make.log 2>&1 || { echo "MAKE FAILED"; tail -30 /tmp/lc-make.log; exit 1; }
echo "[build] DONE"
find /mnt/lisp/bitcoin-core -name 'libbitcoinconsensus*' \( -name '*.so*' -o -name '*.a' \) 2>/dev/null
find /mnt/lisp/bitcoin-core -name 'bitcoinconsensus.h' 2>/dev/null

# bin/ — node deployment harness

Reusable scripts to run the consolidated node (single-writer validating follower +
serve headers/blocks + tx relay + JSON-RPC) as a long-lived, crash-safe, self-respawning
process. **Harness here is version-controlled; per-node config stays out of the repo.**

| File | Role |
|---|---|
| `serve-node.sh` | Respawn supervisor. Sets up dep discovery, sources config, restarts sbcl on exit. |
| `serve-node.lisp` | The launcher sbcl loads: builds hunchentoot FFI-free (`:hunchentoot-no-ssl`), loads `cl-consensus` (+ the optional pure-CL Tor provider when `ONION*`/`PEER_TRANSPORT=tor`), then calls `serve-node` with every parameter taken from the environment. |
| `node.env.example` | Template for the **config** half — copy, edit, and point `NODE_ENV` at it. |

## Run

```sh
cp bin/node.env.example /etc/cl-consensus/node.env    # edit paths, peer, ports, flags
NODE_ENV=/etc/cl-consensus/node.env bin/serve-node.sh
```

Or export the vars yourself and run `bin/serve-node.sh` with no `NODE_ENV`.

## Dependency discovery

The launcher hardcodes no paths — it finds `cl-consensus` and its from-scratch deps
(`cl-tor`, `seal`, `cl-transport`, `pagetree`, `secp256k1-fast`) through the ASDF
source-registry. The supervisor defaults `CL_SOURCE_REGISTRY` to a `:tree` over the repo
and its parent (with `:inherit-configuration`, so any existing ASDF config still applies).
Override it in your config for a non-standard layout.

## FFI-free

With the Tor stack on `seal` (pure-CL TLS) and hunchentoot built `:hunchentoot-no-ssl`
(the RPC is plain HTTP), a node started this way maps **no** `libssl`/`libcrypto` — the
whole node is Common Lisp, no OpenSSL/C-crypto FFI.

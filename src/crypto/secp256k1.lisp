;;;; src/crypto/secp256k1.lisp
;;;;
;;;; secp256k1 / ECDSA for cl-consensus is now provided by the shared
;;;; SECP256K1-FAST system (../secp256k1-fast): a fast, dependency-free,
;;;; differentially-verified implementation (VOP field backend + Jacobian + GLV
;;;; + wNAF on x86-64; portable integer fallback elsewhere).  This file is just a
;;;; re-export shim so the existing CL-CONSENSUS.CRYPTO.SECP256K1 package (and the
;;;; `ec:' nickname in script.lisp etc.) keeps working unchanged — every symbol
;;;; below IS the corresponding secp256k1-fast symbol.
;;;;
;;;; cl-consensus's regression (conformance / block sweep / libbitcoinkernel
;;;; FFI diff) now exercises this fast crypto end to end against Bitcoin Core —
;;;; which is the independent validation that the package is correct.

(defpackage #:cl-consensus.crypto.secp256k1
  (:use)
  (:import-from #:secp256k1-fast
   #:*secp256k1-p* #:*secp256k1-n* #:*secp256k1-gx* #:*secp256k1-gy*
   #:secp-init #:secp-generator #:bytes-to-int #:int-to-bytes32 #:mod-expt
   #:secp-mod #:secp-add #:secp-sub #:secp-mul #:secp-sq #:secp-neg #:secp-inv
   #:secp-double #:secp-add-points #:secp-mul-point #:secp-mul-2
   #:secp-on-curve-p #:secp-pubkey #:secp-inf-p #:secp-x #:secp-y #:secp-inv-mod
   #:ecdsa-sign-raw #:ecdsa-verify #:rfc6979-k)
  (:export
   #:*secp256k1-p* #:*secp256k1-n* #:*secp256k1-gx* #:*secp256k1-gy*
   #:secp-init #:secp-generator #:bytes-to-int #:int-to-bytes32 #:mod-expt
   #:secp-mod #:secp-add #:secp-sub #:secp-mul #:secp-sq #:secp-neg #:secp-inv
   #:secp-double #:secp-add-points #:secp-mul-point #:secp-mul-2
   #:secp-on-curve-p #:secp-pubkey #:secp-inf-p #:secp-x #:secp-y #:secp-inv-mod
   #:ecdsa-sign-raw #:ecdsa-verify #:rfc6979-k))

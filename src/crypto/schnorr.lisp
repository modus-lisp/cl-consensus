;;;; src/crypto/schnorr.lisp
;;;;
;;;; BIP-340 Schnorr is now provided by the shared SECP256K1-FAST system
;;;; (../secp256k1-fast).  Re-export shim so CL-CONSENSUS.CRYPTO.SCHNORR (the
;;;; `sch:' nickname in script.lisp's taproot code) keeps working unchanged.

(defpackage #:cl-consensus.crypto.schnorr
  (:use)
  (:import-from #:secp256k1-fast.schnorr
   #:schnorr-verify #:schnorr-sign #:tagged-hash #:pubkey-xonly #:lift-x)
  (:export
   #:schnorr-verify #:schnorr-sign #:tagged-hash #:pubkey-xonly #:lift-x))

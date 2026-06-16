;;;; shared/bitcoind/script.lisp
;;;;
;;;; Phase 4 — the Bitcoin Script interpreter: the consensus heart of the node.
;;;;
;;;; A stack machine over byte-string elements, the full opcode set, the three
;;;; signature-hash schemes (legacy, BIP143 segwit-v0, BIP341 taproot — the last
;;;; lands in a follow-up), and the standard spend paths: P2PK, P2PKH, P2SH,
;;;; P2WPKH, P2WSH.  Signature checks reuse shared/crypto: ECDSA via
;;;; cl-consensus.crypto.secp256k1, Schnorr (taproot) via cl-consensus.crypto.schnorr.
;;;;
;;;; Verification entry point is VERIFY-INPUT (tx, index, prevout-script, amount,
;;;; flags).  We prove it by re-verifying real mainnet spends end to end.


;; secp256k1 constants are set lazily by secp-init; PARSE-PUBKEY and the taproot
;; helpers read *secp256k1-p* directly, so make sure they're initialized as soon
;; as this file is loaded (otherwise the first verify before any ECDSA call sees
;; nil constants and silently fails).
(eval-when (:load-toplevel :execute)
  (cl-consensus.crypto.secp256k1:secp-init))

(defpackage #:cl-consensus.script
  (:use #:cl)
  (:nicknames #:btc-script)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:tx #:cl-consensus.tx)
                    (#:ec #:cl-consensus.crypto.secp256k1) (#:sch #:cl-consensus.crypto.schnorr))
  (:export
   #:eval-script #:verify-input #:script-error #:parse-script #:disassemble-script
   #:legacy-sighash #:bip143-sighash #:taproot-sighash #:parse-der-sig #:parse-pubkey
   #:verify-taproot #:tapleaf-hash
   #:+sighash-all+ #:+sighash-none+ #:+sighash-single+ #:+sighash-anyonecanpay+))

(in-package #:cl-consensus.script)

(define-condition script-error (error)
  ((msg :initarg :msg :reader script-error-msg))
  (:report (lambda (c s) (format s "script error: ~a" (script-error-msg c)))))

(defun serr (fmt &rest args) (error 'script-error :msg (apply #'format nil fmt args)))

;; forward references (run-op / check-multisig are defined after eval-script)
(declaim (ftype function run-op check-multisig))

(defun bytes (&rest seqs)
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) seqs))

(defun empty-bytes () (make-array 0 :element-type '(unsigned-byte 8)))

;;; ----------------------------------------------------------------------------
;;; SCRIPT_VERIFY flags — the soft-fork / policy rules enforced during a verify.
;;; *FLAGS* is a list of keywords bound by VERIFY-INPUT.  Each rule checks its
;;; flag with FLAG?.  Modelled on Core's script verification flags so we can
;;; diff against script_tests.json.
;;; ----------------------------------------------------------------------------

(defparameter *flags* nil)
(defvar *opcount* 0 "Non-push opcode count for the script being evaluated (limit 201).")
(declaim (inline flag?))
(defun flag? (f) (and (member f *flags*) t))

;; opcodes disabled forever (CVE-2010-5137) — fail even in an unexecuted branch,
;; as do OP_VERIF/OP_VERNOTIF (101,102).
(defparameter +disabled-ops+ '(126 127 128 129 131 132 133 134 141 142 149 150 151 152 153))
(defun disabled-op-p (op)
  (and (integerp op) (or (member op +disabled-ops+) (= op 101) (= op 102))))

;;; ----------------------------------------------------------------------------
;;; Opcodes
;;; ----------------------------------------------------------------------------

(defmacro defops (&rest pairs)
  `(progn ,@(loop for (name val) on pairs by #'cddr
                  collect `(defconstant ,name ,val))))

(defops
  +op-0+ 0 +op-pushdata1+ 76 +op-pushdata2+ 77 +op-pushdata4+ 78
  +op-1negate+ 79 +op-reserved+ 80 +op-1+ 81 +op-16+ 96
  +op-nop+ 97 +op-ver+ 98 +op-if+ 99 +op-notif+ 100
  +op-else+ 103 +op-endif+ 104 +op-verify+ 105 +op-return+ 106
  +op-toaltstack+ 107 +op-fromaltstack+ 108
  +op-2drop+ 109 +op-2dup+ 110 +op-3dup+ 111 +op-2over+ 112 +op-2rot+ 113 +op-2swap+ 114
  +op-ifdup+ 115 +op-depth+ 116 +op-drop+ 117 +op-dup+ 118 +op-nip+ 119
  +op-over+ 120 +op-pick+ 121 +op-roll+ 122 +op-rot+ 123 +op-swap+ 124 +op-tuck+ 125
  +op-cat+ 126 +op-substr+ 127 +op-left+ 128 +op-right+ 129 +op-size+ 130
  +op-invert+ 131 +op-and+ 132 +op-or+ 133 +op-xor+ 134
  +op-equal+ 135 +op-equalverify+ 136
  +op-1add+ 139 +op-1sub+ 140 +op-2mul+ 141 +op-2div+ 142
  +op-negate+ 143 +op-abs+ 144 +op-not+ 145 +op-0notequal+ 146
  +op-add+ 147 +op-sub+ 148 +op-mul+ 149 +op-div+ 150 +op-mod+ 151
  +op-lshift+ 152 +op-rshift+ 153
  +op-booland+ 154 +op-boolor+ 155 +op-numequal+ 156 +op-numequalverify+ 157
  +op-numnotequal+ 158 +op-lessthan+ 159 +op-greaterthan+ 160
  +op-lessthanorequal+ 161 +op-greaterthanorequal+ 162 +op-min+ 163 +op-max+ 164
  +op-within+ 165
  +op-ripemd160+ 166 +op-sha1+ 167 +op-sha256+ 168 +op-hash160+ 169 +op-hash256+ 170
  +op-codeseparator+ 171 +op-checksig+ 172 +op-checksigverify+ 173
  +op-checkmultisig+ 174 +op-checkmultisigverify+ 175
  +op-nop1+ 176 +op-checklocktimeverify+ 177 +op-checksequenceverify+ 178
  +op-nop4+ 179 +op-nop10+ 185 +op-checksigadd+ 186)

;;; sighash type flags
(defconstant +sighash-all+ #x01)
(defconstant +sighash-none+ #x02)
(defconstant +sighash-single+ #x03)
(defconstant +sighash-anyonecanpay+ #x80)

;;; ----------------------------------------------------------------------------
;;; Script parsing -> list of (opcode . data) entries
;;; ----------------------------------------------------------------------------

(defun parse-script (script)
  "Decode SCRIPT bytes into a list of ops.  A push is (:push . <bytes>);
   any other opcode is the integer opcode."
  (let ((r (w:make-reader script)) (ops '()))
    (loop until (w:reader-eof-p r) do
      (let ((op (w:r-u8 r)))
        ;; keep the opcode with the push: (:push opcode . data).  The minimal-push
        ;; check is done at EXECUTION time (Core only checks executed pushes), so
        ;; a non-minimal push in a dead IF branch is fine — but the element-SIZE
        ;; limit (520) is checked at scan time, even in dead branches, like Core.
        (cond
          ((<= 1 op 75) (push (list* :push op (size-checked (w:r-bytes r op))) ops))
          ((= op +op-pushdata1+) (push (list* :push op (size-checked (w:r-bytes r (w:r-u8 r)))) ops))
          ((= op +op-pushdata2+) (push (list* :push op (size-checked (w:r-bytes r (w:r-u16 r)))) ops))
          ((= op +op-pushdata4+) (push (list* :push op (size-checked (w:r-bytes r (w:r-u32 r)))) ops))
          (t (push op ops)))))
    (nreverse ops)))

(defun size-checked (data)
  (when (> (length data) 520) (serr "PUSH_SIZE"))
  data)

(defun push-opcode (op) (cadr op))    ; for a (:push opcode . data) entry
(defun push-data (op) (cddr op))

(defun check-minimal-push (data op)
  "Under MINIMALDATA, an executed push must use the smallest encoding (Core's
   CheckMinimalPush).  Returns DATA (signals on violation)."
  (when (flag? :minimaldata)
    (let ((n (length data)))
      (unless (cond ((zerop n) nil)                        ; should be OP_0
                    ((and (= n 1) (<= 1 (aref data 0) 16)) nil)   ; should be OP_1..16
                    ((and (= n 1) (= (aref data 0) #x81)) nil)    ; should be OP_1NEGATE
                    ((<= n 75) (= op n))
                    ((<= n 255) (= op +op-pushdata1+))
                    ((<= n 65535) (= op +op-pushdata2+))
                    (t t))
        (serr "MINIMALDATA non-minimal push"))))
  data)

(defun disassemble-script (script)
  (with-output-to-string (s)
    (dolist (op (parse-script script))
      (if (and (consp op) (eq (car op) :push))
          (format s "~a " (if (zerop (length (push-data op))) "OP_0"
                              (w:bytes->hex (push-data op))))
          (format s "OP_~d " op)))))

;;; ----------------------------------------------------------------------------
;;; Script numbers (CScriptNum): little-endian, sign-magnitude, minimal
;;; ----------------------------------------------------------------------------

(defun num->bytes (n)
  (if (zerop n) (empty-bytes)
      (let ((neg (minusp n)) (abs (abs n)) (out '()))
        (loop while (plusp abs) do (push (logand abs #xff) out) (setf abs (ash abs -8)))
        (setf out (nreverse out))
        (if (/= 0 (logand (car (last out)) #x80))
            (setf out (append out (list (if neg #x80 0))))
            (when neg (setf (car (last out)) (logior (car (last out)) #x80))))
        (coerce out '(simple-array (unsigned-byte 8) (*))))))

(defun minimal-scriptnum-p (b)
  "Core's fRequireMinimal check on a CScriptNum byte vector."
  (let ((n (length b)))
    (cond ((zerop n) t)
          ((/= 0 (logand (aref b (1- n)) #x7f)) t)        ; top byte carries magnitude
          ((= n 1) nil)                                    ; lone 0x00/0x80 -> non-minimal
          (t (/= 0 (logand (aref b (- n 2)) #x80))))))     ; ok only if needed for sign

(defun bytes->num (b &optional (max-len 4) require-minimal)
  (when (> (length b) max-len) (serr "SCRIPTNUM too long (~d)" (length b)))
  (when (and require-minimal (not (minimal-scriptnum-p b))) (serr "SCRIPTNUM non-minimal"))
  (if (zerop (length b)) 0
      (let ((acc 0) (n (length b)))
        (dotimes (i n) (setf acc (logior acc (ash (aref b i) (* 8 i)))))
        (if (/= 0 (logand (aref b (1- n)) #x80))
            (- (logxor acc (ash #x80 (* 8 (1- n)))))
            acc))))

(defun truthy (b)
  "Cast a stack element to boolean (negative zero is false)."
  (let ((n (length b)))
    (dotimes (i n nil)
      (when (/= 0 (aref b i))
        (return (not (and (= i (1- n)) (= (aref b i) #x80))))))))

(defun bool->bytes (x) (if x (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1)
                          (empty-bytes)))

;;; ----------------------------------------------------------------------------
;;; Crypto helpers: DER sigs, SEC pubkeys
;;; ----------------------------------------------------------------------------

(defun be->int (b &optional (start 0) (end (length b)))
  (let ((acc 0)) (loop for i from start below end do (setf acc (logior (ash acc 8) (aref b i)))) acc))

(defun parse-der-sig (sig)
  "Parse DER-encoded ECDSA sig (without the trailing sighash byte) -> (r . s)."
  (let ((r (w:make-reader sig)))
    (unless (= #x30 (w:r-u8 r)) (serr "bad DER: no SEQUENCE"))
    (w:r-u8 r)                                    ; total length
    (unless (= #x02 (w:r-u8 r)) (serr "bad DER: no INTEGER r"))
    (let* ((rlen (w:r-u8 r)) (rb (w:r-bytes r rlen)))
      (unless (= #x02 (w:r-u8 r)) (serr "bad DER: no INTEGER s"))
      (let* ((slen (w:r-u8 r)) (sb (w:r-bytes r slen)))
        (cons (be->int rb) (be->int sb))))))

(defun expt-mod (base exp m)
  (let ((result 1) (base (mod base m)))
    (loop while (plusp exp) do
      (when (oddp exp) (setf result (mod (* result base) m)))
      (setf exp (ash exp -1) base (mod (* base base) m)))
    result))

(defun parse-pubkey (pk)
  "SEC public key bytes -> curve point (x . y).  Handles compressed (33B,
   0x02/0x03) and uncompressed (65B, 0x04)."
  (let ((p ec:*secp256k1-p*) (prefix (aref pk 0)))
    (cond
      ;; uncompressed (0x04) and hybrid (0x06/0x07) both carry full x,y.  Hybrid
      ;; keys are valid pre-STRICTENC; STRICTENC rejects them via
      ;; VALID-PUBKEY-ENCODING-P, so we just need to parse the point here.
      ((and (= (length pk) 65) (member prefix '(4 6 7)))
       (cons (be->int pk 1 33) (be->int pk 33 65)))
      ((and (= (length pk) 33) (or (= prefix 2) (= prefix 3)))
       (let* ((x (be->int pk 1 33))
              (y2 (mod (+ (expt-mod x 3 p) 7) p))
              (y (expt-mod y2 (/ (1+ p) 4) p)))
         (when (/= (logand y 1) (logand prefix 1)) (setf y (- p y)))
         (cons x y)))
      (t (serr "bad pubkey (len ~d prefix ~d)" (length pk) prefix)))))

(defun valid-der-sig-p (sig)
  "Strict DER encoding check (BIP66 / Core IsValidSignatureEncoding).  SIG
   includes the trailing sighash byte."
  (let ((len (length sig)))
    (block nil
      (when (or (< len 9) (> len 73)) (return nil))
      (when (/= (aref sig 0) #x30) (return nil))
      (when (/= (aref sig 1) (- len 3)) (return nil))
      (let ((len-r (aref sig 3)))
        (when (>= (+ 5 len-r) len) (return nil))
        (let ((len-s (aref sig (+ 5 len-r))))
          (when (/= (+ len-r len-s 7) len) (return nil))
          (when (/= (aref sig 2) #x02) (return nil))
          (when (zerop len-r) (return nil))
          (when (/= 0 (logand (aref sig 4) #x80)) (return nil))
          (when (and (> len-r 1) (= (aref sig 4) 0) (zerop (logand (aref sig 5) #x80))) (return nil))
          (when (/= (aref sig (+ len-r 4)) #x02) (return nil))
          (when (zerop len-s) (return nil))
          (when (/= 0 (logand (aref sig (+ len-r 6)) #x80)) (return nil))
          (when (and (> len-s 1) (= (aref sig (+ len-r 6)) 0)
                     (zerop (logand (aref sig (+ len-r 7)) #x80)))
            (return nil))
          t)))))

(defun valid-hashtype-p (ht) (<= +sighash-all+ (logandc2 ht #x80) +sighash-single+))
(defun compressed-pubkey-p (pk) (and (= (length pk) 33) (member (aref pk 0) '(2 3))))
(defun valid-pubkey-encoding-p (pk)
  (or (compressed-pubkey-p pk) (and (= (length pk) 65) (= (aref pk 0) 4))))

(defun ecdsa-check (pubkey-bytes sig sighash-fn ctx)
  "Verify an ECDSA signature element under the active *FLAGS*.  Encoding
   violations (SIG_DER/HASHTYPE/PUBKEYTYPE/HIGH_S/WITNESS_PUBKEYTYPE) HARD-FAIL
   the script; a cryptographically-invalid-but-well-formed sig just returns NIL."
  (when (zerop (length sig)) (return-from ecdsa-check nil))
  (when (and (or (flag? :dersig) (flag? :low-s) (flag? :strictenc))
             (not (valid-der-sig-p sig)))
    (serr "SIG_DER"))
  (when (flag? :strictenc)
    (unless (valid-hashtype-p (aref sig (1- (length sig)))) (serr "SIG_HASHTYPE"))
    (unless (valid-pubkey-encoding-p pubkey-bytes) (serr "PUBKEYTYPE")))
  (when (and (flag? :witness-pubkeytype) (ctx-segwit-version ctx)
             (not (compressed-pubkey-p pubkey-bytes)))
    (serr "WITNESS_PUBKEYTYPE"))
  (let ((rs (handler-case (parse-der-sig (subseq sig 0 (1- (length sig)))) (error () nil))))
    (when (and rs (flag? :low-s) (> (cdr rs) (floor ec:*secp256k1-n* 2))) (serr "SIG_HIGH_S"))
    (if (null rs) nil
        (handler-case
            (let ((digest (funcall sighash-fn (aref sig (1- (length sig)))))
                  (point (parse-pubkey pubkey-bytes)))
              (ec:ecdsa-verify point digest (car rs) (cdr rs)))
          (error () nil)))))

;;; ----------------------------------------------------------------------------
;;; Sighash — legacy
;;; ----------------------------------------------------------------------------

(defun remove-codeseparators (script)
  "Strip OP_CODESEPARATOR bytes from a scriptCode (legacy sighash subscript)."
  (let ((wr (w:make-writer)) (r (w:make-reader script)))
    (loop until (w:reader-eof-p r) do
      (let ((op (w:r-u8 r)))
        (cond
          ((<= 1 op 75) (w:w-u8 wr op) (w:w-bytes wr (w:r-bytes r op)))
          ((= op +op-pushdata1+) (let ((n (w:r-u8 r))) (w:w-u8 wr op) (w:w-u8 wr n) (w:w-bytes wr (w:r-bytes r n))))
          ((= op +op-pushdata2+) (let ((n (w:r-u16 r))) (w:w-u8 wr op) (w:w-u16 wr n) (w:w-bytes wr (w:r-bytes r n))))
          ((= op +op-pushdata4+) (let ((n (w:r-u32 r))) (w:w-u8 wr op) (w:w-u32 wr n) (w:w-bytes wr (w:r-bytes r n))))
          ((= op +op-codeseparator+) nil)        ; drop it
          (t (w:w-u8 wr op)))))
    (w:writer-bytes wr)))

(defun legacy-sighash (transaction in-index script-code hashtype)
  "BIP-less legacy signature hash.  SCRIPT-CODE is the subscript (prevout
   scriptPubKey with code-separators removed)."
  (let* ((base (logand hashtype #x1f))
         (anyonecanpay (/= 0 (logand hashtype +sighash-anyonecanpay+)))
         (inputs (tx:tx-inputs transaction))
         (outputs (tx:tx-outputs transaction))
         (subscript (remove-codeseparators script-code)))
    ;; SIGHASH_SINGLE with no matching output -> the famous "return 1" bug
    (when (and (= base +sighash-single+) (>= in-index (length outputs)))
      (return-from legacy-sighash
        (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
          (setf (aref h 0) 1) h)))
    (let ((wr (w:make-writer)))
      (w:w-i32 wr (tx:tx-version transaction))
      ;; inputs
      (let ((ins (if anyonecanpay (list (nth in-index inputs)) inputs)))
        (w:w-varint wr (length ins))
        (loop for in in ins
              for idx from 0
              for real-idx = (if anyonecanpay in-index idx) do
          (w:w-hash wr (tx:txin-prev-hash in))
          (w:w-u32 wr (tx:txin-prev-index in))
          (cond
            ((= real-idx in-index)
             (w:w-varint wr (length subscript)) (w:w-bytes wr subscript))
            (t (w:w-varint wr 0)))
          ;; sequences: zero for other inputs under NONE/SINGLE
          (if (and (/= real-idx in-index)
                   (member base (list +sighash-none+ +sighash-single+)))
              (w:w-u32 wr 0)
              (w:w-u32 wr (tx:txin-sequence in)))))
      ;; outputs
      (cond
        ((= base +sighash-none+) (w:w-varint wr 0))
        ((= base +sighash-single+)
         (w:w-varint wr (1+ in-index))
         (loop for i from 0 to in-index
               for out = (nth i outputs) do
           (if (= i in-index)
               (progn (w:w-i64 wr (tx:txout-value out))
                      (w:w-varint wr (length (tx:txout-script out)))
                      (w:w-bytes wr (tx:txout-script out)))
               (progn (w:w-i64 wr -1) (w:w-varint wr 0)))))
        (t                              ; SIGHASH_ALL
         (w:w-varint wr (length outputs))
         (dolist (out outputs)
           (w:w-i64 wr (tx:txout-value out))
           (w:w-varint wr (length (tx:txout-script out)))
           (w:w-bytes wr (tx:txout-script out)))))
      (w:w-u32 wr (tx:tx-locktime transaction))
      (w:w-u32 wr hashtype)            ; 4-byte hashtype appended
      (w:hash256 (w:writer-bytes wr)))))

;;; ----------------------------------------------------------------------------
;;; Sighash — BIP143 (segwit v0)
;;; ----------------------------------------------------------------------------

(defun bip143-sighash (transaction in-index script-code amount hashtype)
  (let* ((base (logand hashtype #x1f))
         (anyonecanpay (/= 0 (logand hashtype +sighash-anyonecanpay+)))
         (inputs (tx:tx-inputs transaction))
         (outputs (tx:tx-outputs transaction))
         (this-in (nth in-index inputs))
         (zero32 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (flet ((hash-prevouts ()
             (if anyonecanpay zero32
                 (let ((wr (w:make-writer)))
                   (dolist (in inputs) (w:w-hash wr (tx:txin-prev-hash in)) (w:w-u32 wr (tx:txin-prev-index in)))
                   (w:hash256 (w:writer-bytes wr)))))
           (hash-sequence ()
             (if (or anyonecanpay (= base +sighash-single+) (= base +sighash-none+)) zero32
                 (let ((wr (w:make-writer)))
                   (dolist (in inputs) (w:w-u32 wr (tx:txin-sequence in)))
                   (w:hash256 (w:writer-bytes wr)))))
           (hash-outputs ()
             (cond
               ((and (/= base +sighash-single+) (/= base +sighash-none+))
                (let ((wr (w:make-writer)))
                  (dolist (out outputs)
                    (w:w-i64 wr (tx:txout-value out))
                    (w:w-varint wr (length (tx:txout-script out)))
                    (w:w-bytes wr (tx:txout-script out)))
                  (w:hash256 (w:writer-bytes wr))))
               ((and (= base +sighash-single+) (< in-index (length outputs)))
                (let ((wr (w:make-writer)) (out (nth in-index outputs)))
                  (w:w-i64 wr (tx:txout-value out))
                  (w:w-varint wr (length (tx:txout-script out)))
                  (w:w-bytes wr (tx:txout-script out))
                  (w:hash256 (w:writer-bytes wr))))
               (t zero32))))
      (let ((wr (w:make-writer)))
        (w:w-i32 wr (tx:tx-version transaction))
        (w:w-bytes wr (hash-prevouts))
        (w:w-bytes wr (hash-sequence))
        (w:w-hash wr (tx:txin-prev-hash this-in))
        (w:w-u32 wr (tx:txin-prev-index this-in))
        (w:w-varint wr (length script-code))
        (w:w-bytes wr script-code)
        (w:w-i64 wr amount)
        (w:w-u32 wr (tx:txin-sequence this-in))
        (w:w-bytes wr (hash-outputs))
        (w:w-u32 wr (tx:tx-locktime transaction))
        (w:w-u32 wr hashtype)
        (w:hash256 (w:writer-bytes wr))))))

;;; ----------------------------------------------------------------------------
;;; The interpreter
;;; ----------------------------------------------------------------------------

(defstruct ctx
  transaction in-index amount
  (segwit-version nil)          ; nil legacy, 0 segwit v0, 1 taproot
  (witness-script nil))         ; the scriptCode used for BIP143

(defun checker-sighash (ctx script-code hashtype)
  "Pick the right sighash scheme for the spend being verified."
  (if (eql (ctx-segwit-version ctx) 0)
      (bip143-sighash (ctx-transaction ctx) (ctx-in-index ctx) script-code
                      (ctx-amount ctx) hashtype)
      (legacy-sighash (ctx-transaction ctx) (ctx-in-index ctx) script-code hashtype)))

;;; CLTV (BIP65) / CSV (BIP112) — the script-level absolute/relative timelock checks
(defconstant +locktime-threshold+ 500000000)   ; < => block height, >= => unix time
(defconstant +sequence-final+ #xffffffff)
(defconstant +seq-disable+ #x80000000)          ; SEQUENCE_LOCKTIME_DISABLE_FLAG (1<<31)
(defconstant +seq-type-flag+ #x00400000)        ; SEQUENCE_LOCKTIME_TYPE_FLAG (1<<22)
(defconstant +seq-mask+ #x0000ffff)             ; SEQUENCE_LOCKTIME_MASK

(defun this-input-sequence (ctx)
  (tx:txin-sequence (nth (ctx-in-index ctx) (tx:tx-inputs (ctx-transaction ctx)))))

(defun check-locktime (ctx locktime)
  "BIP65 CheckLockTime: the stack LOCKTIME must be reached by the tx's nLockTime,
   of the same type (height vs time), and the input must not be final."
  (let ((tx-lock (tx:tx-locktime (ctx-transaction ctx))))
    (and (not (or (and (< tx-lock +locktime-threshold+) (>= locktime +locktime-threshold+))
                  (and (>= tx-lock +locktime-threshold+) (< locktime +locktime-threshold+))))
         (<= locktime tx-lock)
         (/= (this-input-sequence ctx) +sequence-final+))))

(defun check-sequence (ctx seq-val)
  "BIP112 CheckSequence: the input's nSequence must encode a relative locktime
   at least the stack value's, same type, with tx version >= 2."
  (let ((txseq (this-input-sequence ctx)))
    (and (>= (tx:tx-version (ctx-transaction ctx)) 2)
         (zerop (logand txseq +seq-disable+))
         (let ((tm (logand txseq (logior +seq-type-flag+ +seq-mask+)))
               (sm (logand seq-val (logior +seq-type-flag+ +seq-mask+))))
           (and (or (and (< tm +seq-type-flag+) (< sm +seq-type-flag+))
                    (and (>= tm +seq-type-flag+) (>= sm +seq-type-flag+)))
                (>= tm sm))))))

(defmacro pop2 (stack) `(progn (pop ,stack) (pop ,stack)))

(defun eval-script (script stack ctx &key (alt '()))
  "Execute SCRIPT over STACK (a list, top = first).  Returns the resulting
   stack.  CTX carries the tx/amount for CHECKSIG.  Signals SCRIPT-ERROR on
   a consensus failure."
  (when (> (length script) 10000) (serr "SCRIPT_SIZE"))
  (let ((*opcount* 0)
        (ops (parse-script script))
        (exec '())                     ; IF/ELSE execution flags (true = executing)
        (codeseparator-script script)) ; subscript after last CODESEPARATOR
    (declare (ignorable codeseparator-script))
    (labels ((executing-p () (every #'identity exec))
             (need (n) (when (< (length stack) n) (serr "INVALID_STACK_OPERATION")))
             (popn () (if stack (pop stack) (serr "INVALID_STACK_OPERATION")))
             (popnum () (bytes->num (popn) 4 (flag? :minimaldata)))
             (push* (x) (push x stack))
             (pop-cond ()                ; pop the IF/NOTIF condition (MINIMALIF)
               (let ((v (popn)))
                 ;; MINIMALIF only applies in witness execution (segwit v0 /
                 ;; tapscript), not in base or P2SH script evaluation.
                 (when (and (flag? :minimalif) (ctx-segwit-version ctx))
                   (unless (or (zerop (length v)) (and (= (length v) 1) (= (aref v 0) 1)))
                     (serr "MINIMALIF")))
                 (truthy v))))
      (dolist (op ops stack)
        (let ((is-push (and (consp op) (eq (car op) :push))))
          ;; always-on (even in unexecuted branches): disabled opcodes fail, and
          ;; the opcode-count limit applies.
          (unless is-push
            (when (disabled-op-p op) (serr "DISABLED_OPCODE ~d" op))
            (when (> op +op-16+)
              (when (> (incf *opcount*) 201) (serr "OP_COUNT"))))
          ;; flow-control opcodes run even when not executing
          (cond
            ((and (not is-push) (= op +op-if+))
             (if (executing-p) (push (pop-cond) exec) (push nil exec)))
            ((and (not is-push) (= op +op-notif+))
             (if (executing-p) (push (not (pop-cond)) exec) (push nil exec)))
            ((and (not is-push) (= op +op-else+))
             (when (null exec) (serr "OP_ELSE with no IF"))
             (setf (car exec) (not (car exec))))
            ((and (not is-push) (= op +op-endif+))
             (when (null exec) (serr "OP_ENDIF with no IF"))
             (pop exec))
            ((not (executing-p)) nil)   ; skip everything else in a dead branch
            (is-push
             (push* (check-minimal-push (push-data op) (push-opcode op))))
            (t (run-op op #'popn #'popnum #'push* #'need ctx
                       (lambda () alt) (lambda (v) (setf alt v))
                       (lambda () stack) (lambda (v) (setf stack v))
                       codeseparator-script)))
          ;; stack-size limit applies after each step (main + alt)
          (when (> (+ (length stack) (length alt)) 1000) (serr "STACK_SIZE"))))
      (when exec (serr "UNBALANCED_CONDITIONAL"))   ; every IF needs an ENDIF
      stack)))

(defun run-op (op popn popnum push* need ctx get-alt set-alt get-stack set-stack scriptcode)
  "Execute one non-push, executing opcode.  The closures give controlled access
   to the stacks held by EVAL-SCRIPT."
  (macrolet ((s () `(funcall get-stack))
             (sets (v) `(funcall set-stack ,v))
             (a () `(funcall get-alt))
             (seta (v) `(funcall set-alt ,v)))
    (flet ((pop! () (funcall popn))
           (popi () (funcall popnum))
           (psh (x) (funcall push* x))
           (req (n) (funcall need n)))
      (cond
        ;; constants
        ((= op +op-0+) (psh (empty-bytes)))      ; OP_0 / OP_FALSE pushes empty
        ((= op +op-1negate+) (psh (num->bytes -1)))
        ((<= +op-1+ op +op-16+) (psh (num->bytes (- op (1- +op-1+)))))
        ((= op +op-nop+) nil)
        ((or (= op +op-nop1+) (<= +op-nop4+ op +op-nop10+))
         (when (flag? :discourage-nops) (serr "DISCOURAGE_UPGRADABLE_NOPS")))
        ;; verify / return
        ((= op +op-verify+) (req 1) (unless (truthy (pop!)) (serr "OP_VERIFY failed")))
        ((= op +op-return+) (serr "OP_RETURN"))
        ;; alt stack
        ((= op +op-toaltstack+) (req 1) (seta (cons (pop!) (a))))
        ((= op +op-fromaltstack+) (when (null (a)) (serr "altstack empty"))
         (psh (car (a))) (seta (cdr (a))))
        ;; stack ops
        ((= op +op-drop+) (req 1) (pop!))
        ((= op +op-2drop+) (req 2) (pop!) (pop!))
        ((= op +op-dup+) (req 1) (let ((x (pop!))) (psh x) (psh x)))
        ((= op +op-2dup+) (req 2) (let ((b (pop!)) (a (pop!))) (psh a) (psh b) (psh a) (psh b)))
        ((= op +op-3dup+) (req 3) (let ((c (pop!)) (b (pop!)) (a (pop!)))
                                    (psh a) (psh b) (psh c) (psh a) (psh b) (psh c)))
        ((= op +op-ifdup+) (req 1) (let ((x (pop!))) (psh x) (when (truthy x) (psh x))))
        ((= op +op-depth+) (psh (num->bytes (length (s)))))
        ((= op +op-nip+) (req 2) (let ((b (pop!))) (pop!) (psh b)))
        ((= op +op-over+) (req 2) (let ((b (pop!)) (a (pop!))) (psh a) (psh b) (psh a)))
        ((= op +op-pick+) (req 1) (let ((n (popi))) (req (1+ n))
                                    (psh (nth n (s)))))
        ((= op +op-roll+) (req 1) (let* ((n (popi)) (lst (s)))
                                    (req (1+ n))
                                    (let ((item (nth n lst)))
                                      (sets (append (subseq lst 0 n) (subseq lst (1+ n))))
                                      (psh item))))
        ((= op +op-rot+) (req 3) (let ((c (pop!)) (b (pop!)) (a (pop!))) (psh b) (psh c) (psh a)))
        ((= op +op-swap+) (req 2) (let ((b (pop!)) (a (pop!))) (psh b) (psh a)))
        ((= op +op-tuck+) (req 2) (let ((b (pop!)) (a (pop!))) (psh b) (psh a) (psh b)))
        ((= op +op-2over+) (req 4) (let ((d (pop!)) (c (pop!)) (b (pop!)) (a (pop!)))
                                     (psh a) (psh b) (psh c) (psh d) (psh a) (psh b)))
        ((= op +op-2swap+) (req 4) (let ((d (pop!)) (c (pop!)) (b (pop!)) (a (pop!)))
                                     (psh c) (psh d) (psh a) (psh b)))
        ((= op +op-2rot+) (req 6) (let ((f (pop!)) (e (pop!)) (d (pop!)) (c (pop!)) (b (pop!)) (a (pop!)))
                                    (psh c) (psh d) (psh e) (psh f) (psh a) (psh b)))
        ;; size
        ((= op +op-size+) (req 1) (let ((x (car (s)))) (psh (num->bytes (length x)))))
        ;; equality
        ((= op +op-equal+) (req 2) (psh (bool->bytes (equalp (pop!) (pop!)))))
        ((= op +op-equalverify+) (req 2) (unless (equalp (pop!) (pop!)) (serr "EQUALVERIFY failed")))
        ;; arithmetic
        ((= op +op-1add+) (psh (num->bytes (1+ (popi)))))
        ((= op +op-1sub+) (psh (num->bytes (1- (popi)))))
        ((= op +op-negate+) (psh (num->bytes (- (popi)))))
        ((= op +op-abs+) (psh (num->bytes (abs (popi)))))
        ((= op +op-not+) (psh (bool->bytes (zerop (popi)))))
        ((= op +op-0notequal+) (psh (bool->bytes (/= 0 (popi)))))
        ((= op +op-add+) (let ((b (popi)) (a (popi))) (psh (num->bytes (+ a b)))))
        ((= op +op-sub+) (let ((b (popi)) (a (popi))) (psh (num->bytes (- a b)))))
        ((= op +op-booland+) (let ((b (popi)) (a (popi))) (psh (bool->bytes (and (/= 0 a) (/= 0 b))))))
        ((= op +op-boolor+) (let ((b (popi)) (a (popi))) (psh (bool->bytes (or (/= 0 a) (/= 0 b))))))
        ((= op +op-numequal+) (let ((b (popi)) (a (popi))) (psh (bool->bytes (= a b)))))
        ((= op +op-numequalverify+) (let ((b (popi)) (a (popi))) (unless (= a b) (serr "NUMEQUALVERIFY"))))
        ((= op +op-numnotequal+) (let ((b (popi)) (a (popi))) (psh (bool->bytes (/= a b)))))
        ((= op +op-lessthan+) (let ((b (popi)) (a (popi))) (psh (bool->bytes (< a b)))))
        ((= op +op-greaterthan+) (let ((b (popi)) (a (popi))) (psh (bool->bytes (> a b)))))
        ((= op +op-lessthanorequal+) (let ((b (popi)) (a (popi))) (psh (bool->bytes (<= a b)))))
        ((= op +op-greaterthanorequal+) (let ((b (popi)) (a (popi))) (psh (bool->bytes (>= a b)))))
        ((= op +op-min+) (let ((b (popi)) (a (popi))) (psh (num->bytes (min a b)))))
        ((= op +op-max+) (let ((b (popi)) (a (popi))) (psh (num->bytes (max a b)))))
        ((= op +op-within+) (let ((mx (popi)) (mn (popi)) (x (popi))) (psh (bool->bytes (and (<= mn x) (< x mx))))))
        ;; crypto hashes
        ((= op +op-ripemd160+) (req 1) (psh (ironclad:digest-sequence :ripemd-160 (pop!))))
        ((= op +op-sha1+) (req 1) (psh (ironclad:digest-sequence :sha1 (pop!))))
        ((= op +op-sha256+) (req 1) (psh (w:sha256 (pop!))))
        ((= op +op-hash160+) (req 1) (psh (w:hash160 (pop!))))
        ((= op +op-hash256+) (req 1) (psh (w:hash256 (pop!))))
        ((= op +op-codeseparator+) nil)
        ;; signature checks
        ((or (= op +op-checksig+) (= op +op-checksigverify+))
         (req 2)
         (let* ((pubkey (pop!)) (sig (pop!))
                (ok (ecdsa-check pubkey sig
                                 (lambda (ht) (checker-sighash ctx scriptcode ht)) ctx)))
           ;; NULLFAIL: a failing signature must be empty
           (when (and (not ok) (flag? :nullfail) (plusp (length sig))) (serr "NULLFAIL"))
           (if (= op +op-checksigverify+)
               (unless ok (serr "CHECKSIGVERIFY failed"))
               (psh (bool->bytes ok)))))
        ((or (= op +op-checkmultisig+) (= op +op-checkmultisigverify+))
         (check-multisig popn popnum push* need ctx scriptcode op))
        ;; absolute timelock (BIP65).  When the flag is off it's a NOP (subject
        ;; to DISCOURAGE_UPGRADABLE_NOPS); on, it enforces the locktime.  VERIFY
        ;; semantics: inspects the top item, does not pop it.
        ((= op +op-checklocktimeverify+)
         (if (flag? :cltv)
             (progn (req 1)
                    (let ((lt (bytes->num (car (s)) 5 (flag? :minimaldata))))
                      (when (< lt 0) (serr "NEGATIVE_LOCKTIME"))
                      (unless (check-locktime ctx lt) (serr "UNSATISFIED_LOCKTIME"))))
             (when (flag? :discourage-nops) (serr "DISCOURAGE_UPGRADABLE_NOPS"))))
        ;; relative timelock (BIP112)
        ((= op +op-checksequenceverify+)
         (if (flag? :csv)
             (progn (req 1)
                    (let ((sq (bytes->num (car (s)) 5 (flag? :minimaldata))))
                      (when (< sq 0) (serr "NEGATIVE_LOCKTIME"))
                      (when (zerop (logand sq +seq-disable+))   ; disable bit -> skip check
                        (unless (check-sequence ctx sq) (serr "UNSATISFIED_LOCKTIME")))))
             (when (flag? :discourage-nops) (serr "DISCOURAGE_UPGRADABLE_NOPS"))))
        ;; disabled opcodes
        ((member op (list +op-cat+ +op-substr+ +op-left+ +op-right+ +op-invert+
                          +op-and+ +op-or+ +op-xor+ +op-2mul+ +op-2div+ +op-mul+
                          +op-div+ +op-mod+ +op-lshift+ +op-rshift+))
         (serr "disabled opcode ~d" op))
        (t (serr "unhandled opcode ~d" op))))))

(defun check-multisig (popn popnum push* need ctx scriptcode op)
  (declare (ignore popnum))
  (flet ((pop! () (funcall popn)) (psh (x) (funcall push* x)) (req (n) (funcall need n)))
    (req 1)
    (let ((nkeys (bytes->num (pop!) 4 (flag? :minimaldata))))
      (when (or (< nkeys 0) (> nkeys 20)) (serr "bad pubkey count ~d" nkeys))
      (when (> (incf *opcount* nkeys) 201) (serr "OP_COUNT"))   ; Core counts the keys

      (req (1+ nkeys))
      ;; keys/sigs are accessed top-of-stack first (Core's order): popping gives
      ;; pkN..pk1 and sigM..sig1, which we match forward.
      (let ((keys (loop repeat nkeys collect (pop!))))
        (let ((nsigs (bytes->num (pop!) 4 (flag? :minimaldata))))
          (when (or (< nsigs 0) (> nsigs nkeys)) (serr "bad sig count ~d" nsigs))
          (req (1+ nsigs))
          (let ((sigs (loop repeat nsigs collect (pop!)))
                (dummy (pop!)))          ; the off-by-one dummy element (consensus quirk)
            (when (and (flag? :nulldummy) (plusp (length dummy))) (serr "SIG_NULLDUMMY"))
            ;; greedily match each sig to keys in order (Core's algorithm)
            (let ((si 0) (ki 0) (ok t)
                  (sigv (coerce sigs 'vector)) (keyv (coerce keys 'vector)))
              (loop while (< si nsigs) do
                (when (< (- nkeys ki) (- nsigs si)) (setf ok nil) (return))
                (if (ecdsa-check (aref keyv ki) (aref sigv si)
                                 (lambda (ht) (checker-sighash ctx scriptcode ht)) ctx)
                    (progn (incf si) (incf ki))
                    (incf ki)))
              ;; NULLFAIL: on failure, every provided signature must be empty
              (when (and (not ok) (flag? :nullfail) (some (lambda (s) (plusp (length s))) sigs))
                (serr "NULLFAIL"))
              (if (= op +op-checkmultisigverify+)
                  (unless ok (serr "CHECKMULTISIGVERIFY failed"))
                  (psh (bool->bytes ok))))))))))

;;; ----------------------------------------------------------------------------
;;; verify-input — the per-input verification entry point
;;; ----------------------------------------------------------------------------

(defun push-bytes (data)
  "Encode DATA as a minimal push, prefixed for use inside a synthesized script."
  (let ((wr (w:make-writer)) (n (length data)))
    (cond ((<= n 75) (w:w-u8 wr n))
          ((<= n 255) (w:w-u8 wr +op-pushdata1+) (w:w-u8 wr n))
          (t (w:w-u8 wr +op-pushdata2+) (w:w-u16 wr n)))
    (w:w-bytes wr data)
    (w:writer-bytes wr)))

(defun witness-program (script)
  "If SCRIPT is a native witness program (OP_0..OP_16 then a 2..40-byte push),
   return (values version program-bytes); else NIL."
  (when (>= (length script) 2)
    (let ((v0 (aref script 0)) (len (aref script 1)))
      (when (and (or (= v0 +op-0+) (<= +op-1+ v0 +op-16+))
                 (= (length script) (+ 2 len))
                 (<= 2 len 40))
        (values (if (= v0 +op-0+) 0 (- v0 (1- +op-1+)))
                (subseq script 2))))))

(defun p2sh-p (script)
  (and (= (length script) 23)
       (= (aref script 0) +op-hash160+)
       (= (aref script 1) 20)
       (= (aref script 22) +op-equal+)))

(defun p2wpkh-script-code (program)
  "The implicit scriptCode for a P2WPKH spend: a standard P2PKH template."
  (bytes (vector +op-dup+ +op-hash160+ 20) program (vector +op-equalverify+ +op-checksig+)))

(defun verify-witness (version program witness amount ctx &optional prevouts)
  "Verify a segwit spend.  v0: P2WPKH / P2WSH.  v1: taproot (needs PREVOUTS)."
  (let ((ctx (make-ctx :transaction (ctx-transaction ctx) :in-index (ctx-in-index ctx)
                       :amount amount :segwit-version version)))
    (cond
      ((and (= version 0) (= (length program) 20))     ; P2WPKH
       (unless (= (length witness) 2) (serr "P2WPKH needs 2 witness items"))
       (let* ((sig (first witness)) (pubkey (second witness))
              (stack (list pubkey sig))
              (result (eval-script (p2wpkh-script-code program) stack ctx)))
         (and result (truthy (car result)))))
      ((and (= version 0) (= (length program) 32))     ; P2WSH
       (when (null witness) (serr "P2WSH empty witness"))
       (let* ((witness-script (car (last witness)))
              (stack (reverse (butlast witness))))
         (unless (equalp (w:sha256 witness-script) program) (serr "P2WSH script hash mismatch"))
         (setf (ctx-witness-script ctx) witness-script)
         (let ((result (eval-script witness-script stack ctx)))
           (and result (truthy (car result))))))
      ((and (= version 1) (= (length program) 32))         ; taproot
       (when (null witness) (serr "taproot empty witness"))
       (unless prevouts (serr "taproot verification requires all prevouts"))
       (verify-taproot program witness prevouts ctx))
      ((>= version 2) t)                                    ; future witness versions: anyone-can-spend
      (t (serr "unknown witness program (v~d len ~d)" version (length program))))))

;;; ----------------------------------------------------------------------------
;;; Sighash — BIP341 taproot (commits to ALL spent outputs; needs every prevout)
;;; ----------------------------------------------------------------------------

(defun taproot-sighash (transaction in-index prevouts hashtype
                        &key (ext-flag 0) annex tapleaf-hash (codesep-pos #xffffffff))
  "BIP341 signature hash.  PREVOUTS is a vector of (amount . scriptPubKey) for
   ALL inputs in order.  EXT-FLAG 0 = key path, 1 = tapscript."
  (let* ((inputs (tx:tx-inputs transaction))
         (outputs (tx:tx-outputs transaction))
         (anyonecanpay (= (logand hashtype #x80) #x80))
         (out-type (logand hashtype 3)))     ; 0=DEFAULT(ALL) 1=ALL 2=NONE 3=SINGLE
    (flet ((sha (bytes) (w:sha256 bytes)))
      (let ((m (w:make-writer)))
        (w:w-u8 m hashtype)
        (w:w-i32 m (tx:tx-version transaction))
        (w:w-u32 m (tx:tx-locktime transaction))
        (unless anyonecanpay
          (let ((wr (w:make-writer)))                       ; sha_prevouts
            (dolist (in inputs) (w:w-hash wr (tx:txin-prev-hash in)) (w:w-u32 wr (tx:txin-prev-index in)))
            (w:w-bytes m (sha (w:writer-bytes wr))))
          (let ((wr (w:make-writer)))                       ; sha_amounts
            (loop for pv across prevouts do (w:w-i64 wr (car pv)))
            (w:w-bytes m (sha (w:writer-bytes wr))))
          (let ((wr (w:make-writer)))                       ; sha_scriptpubkeys
            (loop for pv across prevouts do (w:w-varint wr (length (cdr pv))) (w:w-bytes wr (cdr pv)))
            (w:w-bytes m (sha (w:writer-bytes wr))))
          (let ((wr (w:make-writer)))                       ; sha_sequences
            (dolist (in inputs) (w:w-u32 wr (tx:txin-sequence in)))
            (w:w-bytes m (sha (w:writer-bytes wr)))))
        (when (and (/= out-type +sighash-none+) (/= out-type +sighash-single+))
          (let ((wr (w:make-writer)))                       ; sha_outputs (ALL)
            (dolist (out outputs)
              (w:w-i64 wr (tx:txout-value out))
              (w:w-varint wr (length (tx:txout-script out)))
              (w:w-bytes wr (tx:txout-script out)))
            (w:w-bytes m (sha (w:writer-bytes wr)))))
        (w:w-u8 m (+ (* 2 ext-flag) (if annex 1 0)))        ; spend_type
        (if anyonecanpay
            (let ((in (nth in-index inputs)) (pv (aref prevouts in-index)))
              (w:w-hash m (tx:txin-prev-hash in)) (w:w-u32 m (tx:txin-prev-index in))
              (w:w-i64 m (car pv))
              (w:w-varint m (length (cdr pv))) (w:w-bytes m (cdr pv))
              (w:w-u32 m (tx:txin-sequence in)))
            (w:w-u32 m in-index))
        (when annex
          (let ((wr (w:make-writer))) (w:w-varint wr (length annex)) (w:w-bytes wr annex)
            (w:w-bytes m (sha (w:writer-bytes wr)))))
        (when (= out-type +sighash-single+)
          (let ((wr (w:make-writer)) (out (nth in-index outputs)))
            (w:w-i64 wr (tx:txout-value out))
            (w:w-varint wr (length (tx:txout-script out)))
            (w:w-bytes wr (tx:txout-script out))
            (w:w-bytes m (sha (w:writer-bytes wr)))))
        (when (= ext-flag 1)                                ; tapscript extension
          (w:w-bytes m tapleaf-hash)
          (w:w-u8 m 0)                                      ; key_version
          (w:w-u32 m codesep-pos))
        ;; final: tagged_hash("TapSighash", 0x00 epoch || message)
        (sch:tagged-hash "TapSighash"
                         (bytes (vector 0) (w:writer-bytes m)))))))

(defun schnorr-check (xonly-pubkey sig prevouts ctx ext-flag tapleaf)
  "Verify a BIP340 schnorr signature element under taproot rules.  SIG is 64
   bytes (SIGHASH_DEFAULT) or 65 (last byte explicit hashtype)."
  (let ((len (length sig)))
    (when (or (< len 64) (> len 65)) (return-from schnorr-check nil))
    (let ((hashtype (if (= len 65) (aref sig 64) 0))
          (sig64 (subseq sig 0 64)))
      (when (and (= len 65) (= hashtype 0)) (return-from schnorr-check nil))
      (let ((digest (taproot-sighash (ctx-transaction ctx) (ctx-in-index ctx)
                                     prevouts hashtype
                                     :ext-flag ext-flag :tapleaf-hash tapleaf)))
        (sch:schnorr-verify xonly-pubkey digest sig64)))))

(defun tapleaf-hash (leaf-version script)
  (sch:tagged-hash "TapLeaf"
                   (bytes (vector leaf-version) (push-varint (length script)) script)))

(defun push-varint (n)
  (let ((wr (w:make-writer))) (w:w-varint wr n) (w:writer-bytes wr)))

(defun verify-taproot (program witness prevouts ctx)
  "Verify a segwit-v1 (taproot) spend.  PROGRAM is the 32-byte output key.
   PREVOUTS is the all-inputs (amount . script) vector.  Handles key-path and
   tapscript (script-path); annex (0x50 prefix) is stripped per BIP341."
  (let ((stack (copy-list witness)))
    ;; strip annex if present (>=2 items and last starts with 0x50)
    (let ((annex nil))
      (when (and (>= (length stack) 2)
                 (plusp (length (car (last stack))))
                 (= (aref (car (last stack)) 0) #x50))
        (setf annex (car (last stack)) stack (butlast stack)))
      (cond
        ;; key path: single element = signature
        ((= (length stack) 1)
         (let ((sig (first stack)))
           (when annex
             ;; recompute with annex flag — re-run sighash through schnorr-check path
             (let* ((len (length sig))
                    (hashtype (if (= len 65) (aref sig 64) 0))
                    (digest (taproot-sighash (ctx-transaction ctx) (ctx-in-index ctx)
                                             prevouts hashtype :annex annex)))
               (return-from verify-taproot
                 (sch:schnorr-verify program digest (subseq sig 0 64)))))
           (schnorr-check program sig prevouts ctx 0 nil)))
        ;; script path: [...inputs...] script control-block
        ((>= (length stack) 2)
         (let* ((control (car (last stack)))
                (script (car (last (butlast stack))))
                (inputs (butlast stack 2)))
           (verify-tapscript program script control inputs prevouts ctx annex)))
        (t nil)))))

(defun verify-tapscript (program script control inputs prevouts ctx annex)
  "Verify the taproot commitment for a script-path spend, then run the tapscript."
  (declare (ignore annex))
  (when (< (length control) 33) (serr "taproot control block too short"))
  (let* ((leaf-version (logand (aref control 0) #xfe))
         (internal-key (subseq control 1 33))
         (leaf (tapleaf-hash leaf-version script))
         (k leaf)
         (path-len (floor (- (length control) 33) 32)))
    ;; fold the merkle path
    (dotimes (i path-len)
      (let ((e (subseq control (+ 33 (* i 32)) (+ 33 (* i 32) 32))))
        (setf k (if (lex<= k e)
                    (sch:tagged-hash "TapBranch" (bytes k e))
                    (sch:tagged-hash "TapBranch" (bytes e k))))))
    ;; tweak: Q = P + int(TapTweak(P||k))*G ; check x(Q)=program & parity
    (let* ((tweak (sch:tagged-hash "TapTweak" (bytes internal-key k))))
      (unless (taproot-commit-ok internal-key tweak program (logand (aref control 0) 1))
        (serr "taproot commitment mismatch")))
    ;; run tapscript (BIP342): schnorr CHECKSIG, CHECKSIGADD, no CHECKMULTISIG
    (run-tapscript script inputs prevouts ctx leaf)))

(defun lex<= (a b)
  (let ((n (min (length a) (length b))))
    (dotimes (i n (<= (length a) (length b)))
      (cond ((< (aref a i) (aref b i)) (return t))
            ((> (aref a i) (aref b i)) (return nil))))))

(defun taproot-commit-ok (internal-key tweak program parity)
  "Check Q = lift_x(P) + tweak*G has x == PROGRAM and y-parity == PARITY."
  (handler-case
      (let* ((px (be->int internal-key))
             (p-pt (lift-even-x px))
             (tw (be->int tweak))
             (q (ec:secp-add-points p-pt (ec:secp-mul-point tw (ec:secp-generator)))))
        (and (= (car q) (be->int program))
             (= (logand (cdr q) 1) parity)))
    (error () nil)))

(defun lift-even-x (x)
  "The curve point with even Y and the given X (BIP340 lift_x)."
  (let* ((p ec:*secp256k1-p*)
         (y2 (mod (+ (expt-mod x 3 p) 7) p))
         (y (expt-mod y2 (/ (1+ p) 4) p)))
    (when (oddp y) (setf y (- p y)))
    (cons x y)))

(defun run-tapscript (script inputs prevouts ctx leaf)
  "Execute a BIP342 tapscript.  CHECKSIG/CHECKSIGVERIFY use schnorr + the
   tapscript sighash; CHECKSIGADD is supported; CHECKMULTISIG is disabled."
  (let ((stack (reverse inputs)))
    (labels ((schnorr-tap (pk sig)
               (and (plusp (length pk))
                    (schnorr-check pk sig prevouts ctx 1 leaf))))
      ;; a focused interpreter pass for tapscript's signature opcodes; other
      ;; opcodes reuse the base machine via EVAL-SCRIPT semantics.
      (let ((ops (parse-script script)))
        (dolist (op ops)
          (cond
            ((and (consp op) (eq (car op) :push)) (push (push-data op) stack))
            ((= op +op-checksig+)
             (let ((pk (pop stack)) (sig (pop stack)))
               (push (bool->bytes (and (plusp (length sig)) (schnorr-tap pk sig))) stack)))
            ((= op +op-checksigverify+)
             (let ((pk (pop stack)) (sig (pop stack)))
               (unless (and (plusp (length sig)) (schnorr-tap pk sig)) (serr "tapscript CHECKSIGVERIFY"))))
            ((= op +op-checksigadd+)
             (let ((pk (pop stack)) (nn (bytes->num (pop stack))) (sig (pop stack)))
               (push (num->bytes (if (and (plusp (length sig)) (schnorr-tap pk sig)) (1+ nn) nn)) stack)))
            ((= op +op-checkmultisig+) (serr "CHECKMULTISIG disabled in tapscript"))
            ((= op +op-checkmultisigverify+) (serr "CHECKMULTISIGVERIFY disabled in tapscript"))
            (t
             ;; delegate the rest to a one-off base-script execution
             (setf stack (eval-script (let ((wr (w:make-writer))) (w:w-u8 wr op) (w:writer-bytes wr))
                                      stack ctx)))))
        (and stack (truthy (car stack)))))))

(defun push-only-p (script)
  "True iff SCRIPT contains only push opcodes (every opcode <= OP_16)."
  (let ((r (w:make-reader script)))
    (loop until (w:reader-eof-p r) do
      (let ((op (w:r-u8 r)))
        (cond ((<= 1 op 75) (w:r-bytes r op))
              ((= op +op-pushdata1+) (w:r-bytes r (w:r-u8 r)))
              ((= op +op-pushdata2+) (w:r-bytes r (w:r-u16 r)))
              ((= op +op-pushdata4+) (w:r-bytes r (w:r-u32 r)))
              ((> op +op-16+) (return-from push-only-p nil)))))
    t))

(defun cleanstack-ok (stack) (or (not (flag? :cleanstack)) (= (length stack) 1)))

(defun verify-input (transaction in-index prevout-script amount
                     &key (p2sh t) (segwit t) (flags :default) prevouts)
  "Verify input IN-INDEX of TRANSACTION against its prevout (PREVOUT-SCRIPT +
   AMOUNT).  Returns T on success; signals SCRIPT-ERROR or returns NIL on
   failure.  FLAGS is a list of SCRIPT_VERIFY keywords; :DEFAULT derives a
   minimal set from the P2SH/SEGWIT booleans (what CONNECT-BLOCK uses).  The
   conformance harness passes the exact per-case flag set."
  (let ((*flags* (if (eq flags :default)
                     (append (when p2sh '(:p2sh)) (when segwit '(:witness)))
                     flags)))
    (let* ((p2sh (flag? :p2sh)) (segwit (flag? :witness))
           (in (nth in-index (tx:tx-inputs transaction)))
           (scriptsig (tx:txin-script in))
           (witness (nth in-index (tx:tx-witnesses transaction)))
           (ctx (make-ctx :transaction transaction :in-index in-index :amount amount)))
      (when (and (flag? :sigpushonly) (not (push-only-p scriptsig)))
        (serr "SIG_PUSHONLY"))
      (multiple-value-bind (wv wp) (if segwit (witness-program prevout-script) (values nil nil))
        (cond
          ;; native segwit: scriptSig must be empty (witness is the only input)
          (wv
           (when (plusp (length scriptsig)) (serr "WITNESS_MALLEATED"))
           (verify-witness wv wp witness amount ctx prevouts))
          ;; P2SH (possibly wrapping a witness program)
          ((and p2sh (p2sh-p prevout-script))
           (unless (push-only-p scriptsig) (serr "SIG_PUSHONLY (P2SH scriptSig)"))
           (let ((stack (eval-script scriptsig '() ctx)))
             (when (null stack) (serr "P2SH empty scriptSig"))
             (let ((redeem (car stack)))
               (let ((hash (subseq prevout-script 2 22)))
                 (unless (equalp (w:hash160 redeem) hash) (serr "P2SH redeem hash mismatch")))
               (multiple-value-bind (rv rp) (if segwit (witness-program redeem) (values nil nil))
                 (if rv
                     (verify-witness rv rp witness amount ctx prevouts)  ; P2SH-P2WPKH/WSH
                     (let ((result (eval-script redeem (cdr stack) ctx)))
                       (unless (cleanstack-ok result) (serr "CLEANSTACK"))
                       (and result (truthy (car result)))))))))
          ;; legacy
          (t
           (when (and segwit witness) (serr "WITNESS_UNEXPECTED"))
           (let* ((s1 (eval-script scriptsig '() ctx))
                  (result (eval-script prevout-script s1 ctx)))
             (unless (cleanstack-ok result) (serr "CLEANSTACK"))
             (and result (truthy (car result))))))))))

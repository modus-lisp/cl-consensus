;;;; inspect/bip39-test.lisp
;;;;
;;;; Gate for BIP39 mnemonic seed phrases: entropy -> mnemonic (SHA256 checksum) ->
;;;; 512-bit seed (PBKDF2-HMAC-SHA512, 2048 iters).  Checked against the official
;;;; Trezor BIP39 test vectors (passphrase "TREZOR").
;;;;
;;;;   sbcl --non-interactive --load inspect/bip39-test.lisp --eval '(bip39-test:run)'
(require :asdf)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
;; This worktree's repo root (the checkout these edits live in), discovered at load
;; time so the gate tests the code right here rather than another checkout.
(let* ((here (or *load-truename* *default-pathname-defaults*))
       (root (make-pathname :directory (butlast (pathname-directory here))
                            :name nil :type nil :defaults here)))
  (pushnew (truename root) asdf:*central-registry* :test #'equal))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :bip39-test
  (:use :cl)
  (:local-nicknames (:b39 :cl-consensus.bip39) (:w :cl-consensus.wire)
                    (:wal :cl-consensus.wallet))
  (:export #:run))
(in-package :bip39-test)

(defparameter *ok* t)
(defun check (name got want)
  (if (equal got want)
      (format t "  ok   ~a~%" name)
      (progn (setf *ok* nil)
             (format t "  *** FAIL ~a~%      got  ~a~%      want ~a~%" name got want))))
(defun checkt (name cond)
  (if cond (format t "  ok   ~a~%" name)
      (progn (setf *ok* nil) (format t "  *** FAIL ~a~%" name))))

(defun hx (s) (w:hex->bytes s))
(defun seedhex (mnemonic) (w:bytes->hex (b39:mnemonic->seed mnemonic "TREZOR")))

(defun vector-check (label entropy-hex mnemonic seed-hex)
  "Run the full official-vector battery for one (entropy, mnemonic, seed) triple."
  (let ((entropy (hx entropy-hex)))
    (check (format nil "~a: entropy->mnemonic" label)
           (b39:mnemonic-from-entropy entropy) mnemonic)
    (checkt (format nil "~a: validate-mnemonic" label)
            (b39:validate-mnemonic mnemonic))
    (check (format nil "~a: mnemonic->seed (TREZOR)" label)
           (seedhex mnemonic) seed-hex)))

(defun run ()
  (setf *ok* t)
  (format t "~&BIP39 gate~%")

  ;; wordlist sanity ----------------------------------------------------------
  (checkt "wordlist has 2048 words" (= (length b39:*wordlist*) 2048))
  (check  "wordlist[0]"    (aref b39:*wordlist* 0)    "abandon")
  (check  "wordlist[1]"    (aref b39:*wordlist* 1)    "ability")
  (check  "wordlist[2047]" (aref b39:*wordlist* 2047) "zoo")
  (check  "wordlist[2046]" (aref b39:*wordlist* 2046) "zone")

  ;; official Trezor vectors (passphrase "TREZOR") ----------------------------
  ;; 128-bit, all 0x00
  (vector-check "128/0x00"
    "00000000000000000000000000000000"
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")

  ;; 128-bit, all 0x7f
  (vector-check "128/0x7f"
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
    "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607")

  ;; 256-bit, all 0xff (24 words)
  (vector-check "256/0xff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
    "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad")

  ;; 256-bit mixed (Trezor vector) — exercises a non-degenerate bit layout
  (vector-check "256/mixed"
    "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f"
    "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
    "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998")

  ;; negative checks ----------------------------------------------------------
  (checkt "reject bad checksum"
          (not (b39:validate-mnemonic
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")))
  (checkt "reject unknown word"
          (not (b39:validate-mnemonic
                "zzzz abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")))
  (checkt "reject wrong word count"
          (not (b39:validate-mnemonic "abandon abandon abandon")))

  ;; wallet bridge ------------------------------------------------------------
  (let* ((mn "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
         (wal (b39:make-wallet-from-mnemonic mn :type :p2wpkh :passphrase "TREZOR")))
    (checkt "make-wallet-from-mnemonic yields a wallet" (wal:wallet-p wal))
    (checkt "wallet has a receive address"
            (stringp (wal:wallet-receive-address wal 0))))

  (format t "~&~a~%" (if *ok* "OK   BIP39 gate passed" "FAIL BIP39 gate"))
  *ok*)

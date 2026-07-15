;;;; src/slip39.lisp — SLIP-0039: Shamir backup for a master secret, as word mnemonics.
;;;;
;;;; Layered on cl-consensus.shamir (GF(256) sharing).  This file adds the SLIP-0039
;;;; serialization: the two-level group/member split, the master-secret encryption
;;;; (a 4-round Feistel network keyed by PBKDF2-HMAC-SHA256), the share bit-packing
;;;; (id/ext/e/GI/Gt/g/I/t/value), the RS1024 checksum, and the 1024-word encoding.
;;;;
;;;; Verified against the 45 official SLIP-0039 test vectors (see inspect/).  The package
;;;; and *wordlist* are defined in slip39-wordlist.lisp, which loads first.

(in-package #:cl-consensus.slip39)

(define-condition slip39-error (error)
  ((msg :initarg :msg :reader slip39-error-msg))
  (:report (lambda (c s) (format s "slip39: ~a" (slip39-error-msg c)))))
(defun err (fmt &rest args) (error 'slip39-error :msg (apply #'format nil fmt args)))

(deftype u8vec () '(simple-array (unsigned-byte 8) (*)))
(defun u8vec (n &optional (init 0)) (make-array n :element-type '(unsigned-byte 8) :initial-element init))
(defun as-u8vec (seq) (coerce seq 'u8vec))

;;; ---- small helpers ----------------------------------------------------------------

(defun bytes->int (bytes)
  (let ((v 0)) (loop for b across (as-u8vec bytes) do (setf v (+ (* v 256) b))) v))

(defun int->bytes (int n)
  (let ((b (u8vec n)))
    (loop for i from (1- n) downto 0 do (setf (aref b i) (logand int #xff) int (ash int -8)))
    b))

(defun string->bytes (s)                ; ASCII/Latin-1 passphrase bytes (NFKD assumed)
  (map 'u8vec #'char-code s))

(defun xor-bytes (a b)
  (let ((o (u8vec (length a)))) (dotimes (i (length a) o) (setf (aref o i) (logxor (aref a i) (aref b i))))))

(defun split-words (mnemonic)
  (loop with s = 0 with len = (length mnemonic) with out = '()
        for sp = (position #\Space mnemonic :start s)
        do (let ((w (subseq mnemonic s (or sp len)))) (when (plusp (length w)) (push w out)))
           (if sp (setf s (1+ sp)) (return (nreverse out)))))

;;; ---- 10-bit word <-> index --------------------------------------------------------

(defun words->indices (words)
  (loop for w in words
        for idx = (gethash w *word-index*)
        do (unless idx (err "unknown word ~s" w))
        collect idx))

(defun indices->words (idxs) (mapcar (lambda (i) (aref *wordlist* i)) idxs))

(defun int->words (val total-bits)      ; total-bits a multiple of 10; big-endian
  (loop for shift from (- total-bits 10) downto 0 by 10
        collect (logand (ash val (- shift)) #x3ff)))

(defun words->int (words)               ; each 10-bit, big-endian
  (let ((v 0)) (dolist (w words v) (setf v (logior (ash v 10) w)))))

;;; ---- RS1024 checksum (Reed-Solomon over GF(1024)) --------------------------------

(defparameter +rs1024-gen+
  #(#xe0e040 #x1c1c080 #x3838100 #x7070200 #xe0e0009
    #x1c0c2412 #x38086c24 #x3090fc48 #x21b1f890 #x3f3f120))

(defun rs1024-polymod (values)
  (let ((chk 1))
    (dolist (v values chk)
      (let ((b (ash chk -20)))
        (setf chk (logxor (ash (logand chk #xfffff) 10) v))
        (dotimes (i 10) (when (logbitp i b) (setf chk (logxor chk (aref +rs1024-gen+ i)))))))))

(defun cs-values (ext)                   ; customization string as ASCII code points
  (map 'list #'char-code (if (= ext 1) "shamir_extendable" "shamir")))

(defun rs1024-checksum (data-words ext)
  (let ((pm (logxor (rs1024-polymod (append (cs-values ext) data-words '(0 0 0))) 1)))
    (loop for i below 3 collect (logand (ash pm (* -10 (- 2 i))) #x3ff))))

(defun rs1024-verify (all-words ext)
  (= (rs1024-polymod (append (cs-values ext) all-words)) 1))

;;; ---- master-secret encryption (4-round Feistel, PBKDF2-HMAC-SHA256) --------------

(defparameter +round-count+ 4)
(defparameter +base-iterations+ 10000)

(defun get-salt (id ext)
  (if (= ext 1)
      (u8vec 0)
      (concatenate 'u8vec (string->bytes "shamir") (vector (ash id -8) (logand id #xff)))))

(defun round-function (i passphrase e salt r)
  "F(i,R) = PBKDF2(HMAC-SHA256, i||passphrase, salt||R, (10000<<e)/4, dkLen=|R|)."
  (let ((kdf (ic:make-kdf :pbkdf2 :digest :sha256))
        (pass (concatenate 'u8vec (vector i) (string->bytes passphrase)))
        (iters (ash (floor +base-iterations+ +round-count+) e)))   ; = 2500 << e
    (ic:derive-key kdf pass (concatenate 'u8vec salt (as-u8vec r)) iters (length r))))

(defun encrypt-ms (master passphrase e id ext)
  (let* ((master (as-u8vec master)) (half (ash (length master) -1))
         (l (subseq master 0 half)) (r (subseq master half))
         (salt (get-salt id ext)))
    (dotimes (i +round-count+)
      (psetf l r  r (xor-bytes l (round-function i passphrase e salt r))))
    (concatenate 'u8vec r l)))

(defun decrypt-ms (ems passphrase e id ext)
  (let* ((ems (as-u8vec ems)) (half (ash (length ems) -1))
         (l (subseq ems 0 half)) (r (subseq ems half))
         (salt (get-salt id ext)))
    (loop for i from (1- +round-count+) downto 0
          do (psetf l r  r (xor-bytes l (round-function i passphrase e salt r))))
    (concatenate 'u8vec r l)))

;;; ---- share encode / decode --------------------------------------------------------

(defstruct share id ext e gi gt g mi mt value)

(defparameter +metadata-words+ 4)       ; id/ext/e/GI/Gt/g/I/t = 40 bits
(defparameter +checksum-words+ 3)
(defparameter +min-strength-bits+ 128)
(defparameter +min-words+ (+ +metadata-words+ +checksum-words+
                             (ceiling +min-strength-bits+ 10)))   ; 20

(defun encode-share (id ext e gi gt g mi mt value)
  "Build one share mnemonic string.  GT/G/MT are 1-based; stored as value-1."
  (let* ((value (as-u8vec value))
         (n (length value))
         (value-bits (* 8 n))
         (ps-bits (+ value-bits (mod (- value-bits) 10)))   ; left-pad to a 10-bit boundary
         (meta 0))
    (flet ((put (v bits) (setf meta (logior (ash meta bits) (logand v (1- (ash 1 bits)))))))
      (put id 15) (put ext 1) (put e 4) (put gi 4) (put (1- gt) 4) (put (1- g) 4) (put mi 4) (put (1- mt) 4))
    (let* ((data-int (logior (ash meta ps-bits) (bytes->int value)))
           (data-words (int->words data-int (+ 40 ps-bits)))
           (all (append data-words (rs1024-checksum data-words ext))))
      (format nil "~{~a~^ ~}" (indices->words all)))))

(defun decode-share (mnemonic)
  "Parse and fully validate one share mnemonic; signal SLIP39-ERROR on any defect."
  (let* ((words (split-words mnemonic))
         (nwords (length words)))
    (when (< nwords +min-words+) (err "mnemonic too short (~d words)" nwords))
    (let* ((all (words->indices words))
           (data-words (butlast all +checksum-words+))
           (data-bits (* 10 (length data-words)))
           (data-int (words->int data-words))
           (pos data-bits))
      (flet ((take (bits) (decf pos bits) (logand (ash data-int (- pos)) (1- (ash 1 bits)))))
        (let* ((id (take 15)) (ext (take 1)) (e (take 4)) (gi (take 4))
               (gt (1+ (take 4))) (g (1+ (take 4))) (mi (take 4)) (mt (1+ (take 4)))
               (ps-bits pos)
               (value-int (logand data-int (1- (ash 1 ps-bits))))
               (n (floor ps-bits 8)))
          (unless (rs1024-verify all ext) (err "invalid checksum"))
          (unless (zerop (ash value-int (- (* 8 n)))) (err "invalid padding"))
          (unless (and (evenp n) (>= n (ceiling +min-strength-bits+ 8)))
            (err "invalid master-secret length (~d bytes)" n))
          (make-share :id id :ext ext :e e :gi gi :gt gt :g g :mi mi :mt mt
                      :value (int->bytes (logand value-int (1- (ash 1 (* 8 n)))) n)))))))

(defun mnemonic-words (mnemonic) (split-words mnemonic))

;;; ---- generate / combine (two-level: groups of members) ---------------------------

(defun generate-mnemonics (group-threshold groups master-secret
                           &key (passphrase "") (ext 1) (iteration-exponent 0))
  "GROUPS is a list of (member-threshold . member-count).  Returns a list (one per group)
   of that group's member mnemonic strings.  Any GROUP-THRESHOLD groups, each satisfied
   by its own member-threshold, recover MASTER-SECRET (with the same PASSPHRASE)."
  (let* ((ms (as-u8vec master-secret))
         (n (length ms)))
    (unless (and (evenp n) (>= n (ceiling +min-strength-bits+ 8)))
      (err "master secret must be even-length and >= ~d bits" +min-strength-bits+))
    (unless (<= 1 group-threshold (length groups)) (err "invalid group threshold"))
    (loop for (mt . mc) in groups do
      (unless (<= 1 mt mc) (err "invalid member threshold ~d-of-~d" mt mc))
      (when (and (= mt 1) (> mc 1)) (err "member threshold 1 requires a single member")))
    (let* ((id (logand (bytes->int (sh:random-bytes 2)) #x7fff))
           (e iteration-exponent)
           (ems (encrypt-ms ms passphrase e id ext))
           (group-shares (sh:split-secret group-threshold (length groups) ems)))
      (loop for (gi . gvalue) in group-shares
            for (mt . mc) in groups
            collect (loop for (mi . mvalue) in (sh:split-secret mt mc gvalue)
                          collect (encode-share id ext e gi group-threshold (length groups) mi mt mvalue))))))

(defun combine-mnemonics (mnemonics &key (passphrase ""))
  "Recover the master secret from a sufficient set of SLIP-0039 MNEMONICS."
  (when (null mnemonics) (err "no mnemonics supplied"))
  (let* ((shares (mapcar #'decode-share mnemonics))
         (h (first shares))
         (id (share-id h)) (ext (share-ext h)) (e (share-e h))
         (gt (share-gt h)) (g (share-g h)))
    (dolist (s shares)
      (unless (= (share-id s) id) (err "mnemonics have different identifiers"))
      (unless (= (share-ext s) ext) (err "mnemonics have different extendable flags"))
      (unless (= (share-e s) e) (err "mnemonics have different iteration exponents"))
      (unless (= (share-gt s) gt) (err "mnemonics have mismatching group thresholds"))
      (unless (= (share-g s) g) (err "mnemonics have mismatching group counts")))
    (when (> gt g) (err "group threshold exceeds group count"))
    ;; bucket by group index
    (let ((by-group (make-hash-table)))
      (dolist (s shares) (push s (gethash (share-gi s) by-group)))
      (when (< (hash-table-count by-group) gt) (err "insufficient number of groups"))
      (let ((group-shares '()))
        (maphash
         (lambda (gi members)
           (let ((mt (share-mt (first members)))
                 (mis (mapcar #'share-mi members)))
             (dolist (m members) (unless (= (share-mt m) mt) (err "mismatching member thresholds in group ~d" gi)))
             (unless (= (length mis) (length (remove-duplicates mis))) (err "duplicate member indices in group ~d" gi))
             (when (< (length members) mt) (err "insufficient members in group ~d" gi))
             (push (cons gi (sh:recover-secret
                             mt (mapcar (lambda (m) (cons (share-mi m) (share-value m))) members)))
                   group-shares)))
         by-group)
        (decrypt-ms (sh:recover-secret gt group-shares) passphrase e id ext)))))

;;; ---- wallet bridge ----------------------------------------------------------------

(defun wallet-backup (entropy group-threshold groups &key (passphrase "") (ext 1))
  "SLIP-0039 backup of a wallet's raw BIP39 ENTROPY (16 or 32 bytes).  ENTROPY is what
   regenerates the BIP39 mnemonic, so any recovering set reconstructs the same wallet.
   Returns a list (per group) of member mnemonic strings."
  (generate-mnemonics group-threshold groups (as-u8vec entropy)
                      :passphrase passphrase :ext ext))

(defun wallet-from-mnemonics (mnemonics &key (passphrase "") (type :p2wpkh))
  "Recover the wallet from SLIP-0039 MNEMONICS: shares -> entropy -> BIP39 mnemonic -> wallet."
  (let* ((entropy (combine-mnemonics mnemonics :passphrase passphrase))
         (bip39-mnemonic (b39:mnemonic-from-entropy entropy)))
    (values (b39:make-wallet-from-mnemonic bip39-mnemonic :type type) bip39-mnemonic entropy)))

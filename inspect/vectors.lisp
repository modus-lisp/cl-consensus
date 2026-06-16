;;;; inspect/vectors.lisp
;;;;
;;;; Compile Bitcoin Core's script_tests.json assembly mini-language to bytes,
;;;; in Lisp (no external tooling).  Core's test scripts are written like
;;;;   "DEPTH 0 EQUAL" | "1 0x4c01ff EQUALVERIFY" | "'abc'" | "CHECKSIG"
;;;; — decimal numbers, 0x raw-hex, 'quoted' pushes, and opcode names.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (pushnew (uiop:pathname-parent-directory-pathname
            (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
           asdf:*central-registry* :test #'equal)
  (ql:quickload '(:com.inuoe.jzon) :silent t)
  (asdf:load-system "cl-consensus"))

(defpackage #:btc-vectors
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:jzon #:com.inuoe.jzon))
  (:export #:parse-core-script #:load-script-tests))

(in-package #:btc-vectors)

(defparameter *opnames*
  (let ((h (make-hash-table :test 'equal)))
    (flet ((add (name val) (setf (gethash name h) val)))
      (add "0" 0) (add "FALSE" 0) (add "PUSHDATA1" 76) (add "PUSHDATA2" 77) (add "PUSHDATA4" 78)
      (add "1NEGATE" 79) (add "RESERVED" 80) (add "TRUE" 81)
      (loop for i from 1 to 16 do (add (format nil "~d" i) (+ 80 i)))
      (loop for (n . v) in
            '(("NOP" . 97) ("VER" . 98) ("IF" . 99) ("NOTIF" . 100) ("VERIF" . 101)
              ("VERNOTIF" . 102) ("ELSE" . 103) ("ENDIF" . 104) ("VERIFY" . 105) ("RETURN" . 106)
              ("TOALTSTACK" . 107) ("FROMALTSTACK" . 108) ("2DROP" . 109) ("2DUP" . 110)
              ("3DUP" . 111) ("2OVER" . 112) ("2ROT" . 113) ("2SWAP" . 114) ("IFDUP" . 115)
              ("DEPTH" . 116) ("DROP" . 117) ("DUP" . 118) ("NIP" . 119) ("OVER" . 120)
              ("PICK" . 121) ("ROLL" . 122) ("ROT" . 123) ("SWAP" . 124) ("TUCK" . 125)
              ("CAT" . 126) ("SUBSTR" . 127) ("LEFT" . 128) ("RIGHT" . 129) ("SIZE" . 130)
              ("INVERT" . 131) ("AND" . 132) ("OR" . 133) ("XOR" . 134) ("EQUAL" . 135)
              ("EQUALVERIFY" . 136) ("RESERVED1" . 137) ("RESERVED2" . 138) ("1ADD" . 139)
              ("1SUB" . 140) ("2MUL" . 141) ("2DIV" . 142) ("NEGATE" . 143) ("ABS" . 144)
              ("NOT" . 145) ("0NOTEQUAL" . 146) ("ADD" . 147) ("SUB" . 148) ("MUL" . 149)
              ("DIV" . 150) ("MOD" . 151) ("LSHIFT" . 152) ("RSHIFT" . 153) ("BOOLAND" . 154)
              ("BOOLOR" . 155) ("NUMEQUAL" . 156) ("NUMEQUALVERIFY" . 157) ("NUMNOTEQUAL" . 158)
              ("LESSTHAN" . 159) ("GREATERTHAN" . 160) ("LESSTHANOREQUAL" . 161)
              ("GREATERTHANOREQUAL" . 162) ("MIN" . 163) ("MAX" . 164) ("WITHIN" . 165)
              ("RIPEMD160" . 166) ("SHA1" . 167) ("SHA256" . 168) ("HASH160" . 169)
              ("HASH256" . 170) ("CODESEPARATOR" . 171) ("CHECKSIG" . 172) ("CHECKSIGVERIFY" . 173)
              ("CHECKMULTISIG" . 174) ("CHECKMULTISIGVERIFY" . 175) ("NOP1" . 176)
              ("CHECKLOCKTIMEVERIFY" . 177) ("NOP2" . 177) ("CHECKSEQUENCEVERIFY" . 178)
              ("NOP3" . 178) ("NOP4" . 179) ("NOP5" . 180) ("NOP6" . 181) ("NOP7" . 182)
              ("NOP8" . 183) ("NOP9" . 184) ("NOP10" . 185) ("CHECKSIGADD" . 186))
            do (add n v)))
    h))

(defun decimalp (s)
  (and (plusp (length s))
       (let ((start (if (char= (char s 0) #\-) 1 0)))
         (and (< start (length s))
              (every #'digit-char-p (subseq s start))))))

(defun scriptnum-bytes (n)
  (if (zerop n) #()
      (let ((neg (minusp n)) (a (abs n)) (out '()))
        (loop while (plusp a) do (push (logand a #xff) out) (setf a (ash a -8)))
        (setf out (nreverse out))
        (if (/= 0 (logand (car (last out)) #x80))
            (setf out (append out (list (if neg #x80 0))))
            (when neg (setf (car (last out)) (logior (car (last out)) #x80))))
        (coerce out 'vector))))

(defun emit-push (wr data)
  (let ((n (length data)))
    (cond ((<= n 75) (w:w-u8 wr n))
          ((<= n 255) (w:w-u8 wr 76) (w:w-u8 wr n))
          ((<= n 65535) (w:w-u8 wr 77) (w:w-u16 wr n))
          (t (w:w-u8 wr 78) (w:w-u32 wr n)))
    (w:w-bytes wr data)))

(defun parse-core-script (asm)
  "Compile one Core script_tests assembly string to bytes (or signal on an
   unknown token)."
  (let ((wr (w:make-writer)))
    (dolist (tok (remove "" (uiop:split-string asm :separator '(#\Space #\Tab #\Newline)) :test #'string=))
      (cond
        ((decimalp tok)
         (let ((n (parse-integer tok)))
           (cond ((= n -1) (w:w-u8 wr 79))
                 ((= n 0) (w:w-u8 wr 0))
                 ((<= 1 n 16) (w:w-u8 wr (+ 80 n)))
                 (t (emit-push wr (scriptnum-bytes n))))))
        ((and (> (length tok) 2) (string= (subseq tok 0 2) "0x"))
         (w:w-bytes wr (w:hex->bytes (subseq tok 2))))
        ((and (>= (length tok) 2) (char= (char tok 0) #\') (char= (char tok (1- (length tok))) #\'))
         (emit-push wr (ironclad:ascii-string-to-byte-array (subseq tok 1 (1- (length tok))))))
        (t (let ((b (gethash (let ((u (string-upcase tok)))
                               (if (and (> (length u) 3) (string= (subseq u 0 3) "OP_"))
                                   (subseq u 3) u))
                             *opnames*)))
             (unless b (error "unknown token ~s" tok))
             (w:w-u8 wr b)))))
    (w:writer-bytes wr)))

(defun load-script-tests (path)
  "Read Core's raw script_tests.json and compile each case.  Returns a vector of
   (sig-bytes pk-bytes flags expected witness-bytes-list amount); skips comment
   rows and any case with an untokenizable script."
  (let ((rows (with-open-file (f path) (jzon:parse f))) (out '()))
    (loop for row across rows do
      (when (> (length row) 1)
        (handler-case
            (let ((i 0) (wit '()) (amount 0))
              (when (and (vectorp (aref row 0)) (not (stringp (aref row 0))))  ; [ [wit-hex.. , amount], sig, pk, flags, expected ]
                (let ((wa (aref row 0)))
                  (setf wit (loop for k below (1- (length wa)) collect (w:hex->bytes (aref wa k)))
                        amount (round (* (aref wa (1- (length wa))) 1d8))
                        i 1)))
              (push (list (parse-core-script (aref row i))
                          (parse-core-script (aref row (+ i 1)))
                          (aref row (+ i 2)) (aref row (+ i 3)) wit amount)
                    out))
          (error () nil))))            ; skip untokenizable / templated case
    (coerce (nreverse out) 'vector)))

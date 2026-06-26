;;;; shared/bitcoind/wire.lisp
;;;;
;;;; Phase 0 — Bitcoin P2P wire serialization, message framing, network params.
;;;;
;;;; The whole node is built bottom-up on this file: every higher layer encodes
;;;; and decodes through these readers/writers.  Nothing here knows about
;;;; sockets — a WRITER accumulates into a byte vector, a READER walks a byte
;;;; vector with a cursor.  The peer layer reads a 24-byte envelope off the
;;;; socket, then hands the payload bytes to a READER.
;;;;
;;;; Reference: https://en.bitcoin.it/wiki/Protocol_documentation


(defpackage #:cl-consensus.wire
  (:use #:cl)
  (:nicknames #:btc-wire)
  (:export
   ;; hashing / hex
   #:sha256 #:hash256 #:hash160 #:bytes->hex #:hex->bytes #:rev #:hash->hex #:hex->hash
   ;; writer
   #:make-writer #:writer-bytes #:w-u8 #:w-u16 #:w-u32 #:w-u64 #:w-i32 #:w-i64
   #:w-bytes #:w-varint #:w-varstr #:w-hash #:w-bool #:w-netaddr #:w-port-be
   ;; reader
   #:make-reader #:reader-eof-p #:reader-pos #:reader-remaining
   #:r-u8 #:r-u16 #:r-u32 #:r-u64 #:r-i32 #:r-i64
   #:r-bytes #:r-varint #:r-varstr #:r-hash #:r-bool #:r-rest
   #:r-port-be #:r-netaddr #:ip16->ipv4
   ;; message envelope
   #:encode-message #:checksum
   ;; network params
   #:*network* #:select-network #:net-name #:net-magic #:net-port
   #:net-default-version #:net-genesis-hash
   #:net-genesis-hex #:net-pow-limit-bits #:net-no-retarget #:net-heights
   #:+services-none+ #:+services-network+ #:+services-witness+))

(in-package #:cl-consensus.wire)

;;; ----------------------------------------------------------------------------
;;; Hashing & hex helpers (self-contained; bitcoind is a large new subsystem and
;;; we keep its primitives local rather than coupling to the wallet code).
;;; ----------------------------------------------------------------------------

(declaim (inline sha256 hash256))
(defun sha256 (bytes)
  (ironclad:digest-sequence :sha256 bytes))

(defun hash256 (bytes)
  "Bitcoin HASH256 — double SHA-256.  Used for txids, block hashes, merkle, checksums."
  (sha256 (sha256 bytes)))

(defun hash160 (bytes)
  "RIPEMD160(SHA256(x)) — used by P2PKH/P2WPKH."
  (ironclad:digest-sequence :ripemd-160 (sha256 bytes)))

(defun bytes->hex (b)
  (string-downcase (ironclad:byte-array-to-hex-string b)))

(defun hex->bytes (s)
  (ironclad:hex-string-to-byte-array s))

(defun rev (b)
  "Return a reversed copy of byte vector B (display-endianness flip)."
  (reverse b))

(defun hash->hex (h)
  "Bitcoin hashes are shown big-endian (reversed from internal little-endian)."
  (bytes->hex (rev h)))

(defun hex->hash (s)
  "Parse a display hash string (big-endian hex) into an internal little-endian
   32-byte vector."
  (rev (hex->bytes s)))

;;; ----------------------------------------------------------------------------
;;; Network parameters
;;; ----------------------------------------------------------------------------

(defstruct net
  name magic port default-version genesis-hash
  genesis-hex            ; the 80-byte genesis header, hex
  pow-limit-bits         ; compact nBits of the easiest allowed target
  (no-retarget nil)      ; t = difficulty never changes (regtest)
  heights)               ; plist of soft-fork activation heights

;; mainnet genesis header (Jan 3 2009)
(defparameter *mainnet-genesis-hex*
  (concatenate 'string
    "01000000"                                                          ; version
    "0000000000000000000000000000000000000000000000000000000000000000"  ; prev
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"  ; merkle
    "29ab5f49" "ffff001d" "1dac2b7c"))                                  ; time bits nonce
;; regtest genesis: same coinbase/merkle, nBits 0x207fffff (powLimit), nonce 2
(defparameter *regtest-genesis-hex*
  (concatenate 'string
    "01000000" "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "dae5494d" "ffff7f20" "02000000"))                                  ; time bits nonce
;; testnet3 genesis
(defparameter *testnet-genesis-hex*
  (concatenate 'string
    "01000000" "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "dae5494d" "ffff001d" "1aa4ae18"))

(defparameter *mainnet-heights*                ; real BIP activation heights
  '(:p2sh 173805 :dersig 363725 :cltv 388381 :csv 419328
    :bip34 227931 :segwit 481824 :taproot 709632))
(defparameter *early-heights*                  ; regtest/testnet: everything from block 1
  '(:p2sh 1 :dersig 1 :cltv 1 :csv 1 :bip34 1 :segwit 1 :taproot 1))

(defparameter *networks*
  (list
   (make-net :name :mainnet
             :magic #xD9B4BEF9            ; wire order F9 BE B4 D9, stored as LE u32
             :port 8333 :default-version 70016
             :genesis-hash "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
             :genesis-hex *mainnet-genesis-hex* :pow-limit-bits #x1d00ffff
             :no-retarget nil :heights *mainnet-heights*)
   (make-net :name :testnet
             :magic #x0709110B
             :port 18333 :default-version 70016
             :genesis-hash "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
             :genesis-hex *testnet-genesis-hex* :pow-limit-bits #x1d00ffff
             :no-retarget nil :heights *mainnet-heights*)
   (make-net :name :regtest
             :magic #xDAB5BFFA
             :port 18444 :default-version 70016
             :genesis-hash "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
             :genesis-hex *regtest-genesis-hex* :pow-limit-bits #x207fffff
             :no-retarget t :heights *early-heights*)))

(defparameter *network* (first *networks*) "The active network (default mainnet).")

(defun select-network (name)
  (let ((n (find name *networks* :key #'net-name)))
    (unless n (error "unknown network ~s" name))
    (setf *network* n)))

;; Callers read params straight off the struct: (net-magic *network*), etc.

;;; service bit flags (uint64)
(defconstant +services-none+    0)
(defconstant +services-network+ 1)       ; NODE_NETWORK
(defconstant +services-witness+ #x08)    ; NODE_WITNESS

;;; ----------------------------------------------------------------------------
;;; Writer — accumulates little-endian bytes into an adjustable vector
;;; ----------------------------------------------------------------------------

(defun make-writer ()
  (make-array 0 :element-type '(unsigned-byte 8)
                :adjustable t :fill-pointer 0))

(declaim (inline writer-bytes))
(defun writer-bytes (w)
  "Return the accumulated bytes as a simple-array."
  (coerce w '(simple-array (unsigned-byte 8) (*))))

(defun w-u8 (w n)
  (vector-push-extend (logand n #xff) w) w)

(defun w-le (w n nbytes)
  (dotimes (i nbytes w)
    (vector-push-extend (logand (ash n (* -8 i)) #xff) w)))

(defun w-u16 (w n) (w-le w n 2))
(defun w-u32 (w n) (w-le w n 4))
(defun w-u64 (w n) (w-le w n 8))
(defun w-i32 (w n) (w-le w (logand n #xffffffff) 4))
(defun w-i64 (w n) (w-le w (logand n #xffffffffffffffff) 8))

(defun w-bytes (w bytes)
  (loop for b across bytes do (vector-push-extend b w)) w)

(defun w-hash (w h)
  "Write a 32-byte hash as-is (internal little-endian order)."
  (w-bytes w h))

(defun w-bool (w x) (w-u8 w (if x 1 0)))

(defun w-varint (w n)
  "CompactSize unsigned int."
  (cond ((< n #xfd) (w-u8 w n))
        ((<= n #xffff) (w-u8 w #xfd) (w-u16 w n))
        ((<= n #xffffffff) (w-u8 w #xfe) (w-u32 w n))
        (t (w-u8 w #xff) (w-u64 w n)))
  w)

(defun w-varstr (w s)
  "var_str: CompactSize length + UTF-8 bytes."
  (let ((bytes (ironclad:ascii-string-to-byte-array s)))
    (w-varint w (length bytes))
    (w-bytes w bytes))
  w)

(defun w-port-be (w port)
  "Ports on the wire are big-endian (the one BE field in net_addr)."
  (vector-push-extend (logand (ash port -8) #xff) w)
  (vector-push-extend (logand port #xff) w)
  w)

(defun w-netaddr (w services ip4 port &key with-time)
  "net_addr.  In version messages WITH-TIME is nil; in addr messages it's t.
   IP4 is a list/vector of 4 octets (IPv4), mapped into IPv6."
  (when with-time (w-u32 w 0))
  (w-u64 w services)
  ;; IPv4-mapped IPv6: 10 zero bytes, 0xFF 0xFF, then 4 IPv4 octets
  (dotimes (i 10) (w-u8 w 0))
  (w-u8 w #xff) (w-u8 w #xff)
  (map nil (lambda (o) (w-u8 w o)) ip4)
  (w-port-be w port)
  w)

;;; ----------------------------------------------------------------------------
;;; Reader — walks a byte vector with a cursor
;;; ----------------------------------------------------------------------------

(defstruct (reader (:constructor %make-reader))
  (buf #() :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type fixnum))

(defun make-reader (bytes)
  (%make-reader :buf (coerce bytes '(simple-array (unsigned-byte 8) (*))) :pos 0))

(defun reader-eof-p (r) (>= (reader-pos r) (length (reader-buf r))))
(defun reader-remaining (r) (- (length (reader-buf r)) (reader-pos r)))

(defun r-u8 (r)
  (let ((b (aref (reader-buf r) (reader-pos r))))
    (incf (reader-pos r)) b))

(defun r-le (r nbytes)
  (let ((acc 0))
    (dotimes (i nbytes acc)
      (setf acc (logior acc (ash (r-u8 r) (* 8 i)))))))

(defun r-u16 (r) (r-le r 2))
(defun r-u32 (r) (r-le r 4))
(defun r-u64 (r) (r-le r 8))

(defun unsigned->signed (n bits)
  (if (>= n (ash 1 (1- bits))) (- n (ash 1 bits)) n))

(defun r-i32 (r) (unsigned->signed (r-le r 4) 32))
(defun r-i64 (r) (unsigned->signed (r-le r 8) 64))

(defun r-bytes (r n)
  ;; Bound the read to what's actually left — a malformed length (e.g. a bogus
  ;; PUSHDATA4 claiming gigabytes) must error, not try to allocate it (DoS).
  (when (> n (reader-remaining r))
    (error "read of ~d bytes exceeds ~d remaining" n (reader-remaining r)))
  (let ((out (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n out)
      (setf (aref out i) (r-u8 r)))))

(defun r-hash (r) (r-bytes r 32))
(defun r-bool (r) (/= 0 (r-u8 r)))
(defun r-rest (r) (r-bytes r (reader-remaining r)))

(defun r-varint (r)
  (let ((b (r-u8 r)))
    (cond ((< b #xfd) b)
          ((= b #xfd) (r-le r 2))
          ((= b #xfe) (r-le r 4))
          (t (r-le r 8)))))

(defun r-varstr (r)
  (let* ((n (r-varint r))
         (bytes (r-bytes r n)))
    (map 'string #'code-char bytes)))

(defun r-port-be (r)
  "Read a big-endian u16 port (the one BE field in net_addr)."
  (let ((hi (r-u8 r)) (lo (r-u8 r))) (logior (ash hi 8) lo)))

(defun ip16->ipv4 (bytes)
  "If BYTES (16) is an IPv4-mapped IPv6 (10x00, ff ff, a.b.c.d) return the dotted
   string; else NIL (native IPv6/Tor/I2P — skipped in v1)."
  (when (and (loop for i below 10 always (zerop (aref bytes i)))
             (= #xff (aref bytes 10)) (= #xff (aref bytes 11)))
    (format nil "~d.~d.~d.~d" (aref bytes 12) (aref bytes 13) (aref bytes 14) (aref bytes 15))))

(defun r-netaddr (r &key with-time)
  "Read one net_addr entry (addr-message form has WITH-TIME).  Returns
   (host . port) for an IPv4 entry, else NIL (skipped address family)."
  (when with-time (r-u32 r))
  (r-u64 r)                              ; services
  (let* ((ip (r-bytes r 16)) (port (r-port-be r)) (host (ip16->ipv4 ip)))
    (when host (cons host port))))

;;; ----------------------------------------------------------------------------
;;; Message envelope:  magic(4) command(12) length(4) checksum(4) payload
;;; ----------------------------------------------------------------------------

(defun checksum (payload)
  "First 4 bytes of HASH256(payload)."
  (subseq (hash256 payload) 0 4))

(defun encode-message (command payload)
  "Frame a full P2P message.  COMMAND is a string like \"version\";
   PAYLOAD is any byte sequence (coerced to a typed vector)."
  (let ((payload (coerce payload '(simple-array (unsigned-byte 8) (*))))
        (w (make-writer)))
    (w-u32 w (net-magic *network*))
    ;; command: 12 bytes, ascii, null padded
    (let ((cb (ironclad:ascii-string-to-byte-array command)))
      (dotimes (i 12)
        (w-u8 w (if (< i (length cb)) (aref cb i) 0))))
    (w-u32 w (length payload))
    (w-bytes w (checksum payload))
    (w-bytes w payload)
    (writer-bytes w)))

;;;; src/onion.lisp
;;;;
;;;; Tor v3 onion addresses + a persistent "tor peer directory".
;;;;
;;;; Peers gossip Tor v3 addresses in addrv2 (BIP155, netID 4) as the raw 32-byte
;;;; Ed25519 master pubkey.  We can't DIAL a .onion yet (that needs the onion-service
;;;; client — descriptor fetch / intro / rendezvous — which cl-tor doesn't have), but
;;;; we collect and persist them here so the moment dialing lands there's a stocked
;;;; directory.  Kept SEPARATE from the clearnet addrman so the IPv4/Tor dialers never
;;;; try to connect to an undialable .onion.
;;;;
;;;; v3 address encoding (rend-spec-v3 §6):
;;;;   checksum      = SHA3-256(".onion checksum" || PUBKEY || VERSION)[:2]
;;;;   onion_address = base32(PUBKEY || CHECKSUM || VERSION) + ".onion"   (VERSION = 3)
;;;; base32 is RFC4648 lowercase, no padding.

(defpackage #:cl-consensus.onion
  (:use #:cl)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:bt #:bordeaux-threads))
  (:export #:pubkey->onion #:onion->pubkey #:onion-valid-p #:parse-addrv2-onions
           #:*tor-directory* #:tordir-add #:tordir-count #:tordir-list
           #:save-tor-directory #:load-tor-directory))

(in-package #:cl-consensus.onion)

;;; --- base32 (RFC4648, lowercase, no padding) --------------------------------

(defparameter +b32-alphabet+ "abcdefghijklmnopqrstuvwxyz234567")

(defun base32-encode (bytes)
  (let ((bits 0) (nbits 0) (out (make-string-output-stream)))
    (loop for b across bytes do
      (setf bits (logior (ash bits 8) b) nbits (+ nbits 8))
      (loop while (>= nbits 5) do
        (decf nbits 5)
        (write-char (char +b32-alphabet+ (logand (ash bits (- nbits)) 31)) out)))
    (when (plusp nbits)
      (write-char (char +b32-alphabet+ (logand (ash bits (- 5 nbits)) 31)) out))
    (get-output-stream-string out)))

(defun base32-decode (string)
  (let ((bits 0) (nbits 0) (out (make-array 0 :element-type '(unsigned-byte 8)
                                              :adjustable t :fill-pointer 0)))
    (loop for ch across (string-downcase string)
          for v = (position ch +b32-alphabet+)
          do (unless v (error "base32: bad char ~s" ch))
             (setf bits (logior (ash bits 5) v) nbits (+ nbits 5))
             (when (>= nbits 8)
               (decf nbits 8)
               (vector-push-extend (logand (ash bits (- nbits)) #xff) out)))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

;;; --- v3 onion encode / decode / validate ------------------------------------

(defun %v3-checksum (pubkey)
  (subseq (ironclad:digest-sequence
           :sha3/256
           (concatenate '(simple-array (unsigned-byte 8) (*))
                        (map '(simple-array (unsigned-byte 8) (*)) #'char-code ".onion checksum")
                        pubkey #(3)))
          0 2))

(defun pubkey->onion (pubkey)
  "Encode a 32-byte Ed25519 master pubkey as a v3 .onion address string."
  (unless (= (length pubkey) 32) (error "onion: pubkey must be 32 bytes"))
  (concatenate 'string
               (base32-encode (concatenate '(simple-array (unsigned-byte 8) (*))
                                           pubkey (%v3-checksum pubkey) #(3)))
               ".onion"))

(defun onion->pubkey (onion)
  "Decode a v3 .onion address string to (values pubkey32 valid-p)."
  (let* ((label (string-downcase (subseq onion 0 (or (search ".onion" onion) (length onion)))))
         (raw (ignore-errors (base32-decode label))))
    (if (and raw (= (length raw) 35) (= (aref raw 34) 3))
        (let ((pk (subseq raw 0 32)) (cksum (subseq raw 32 34)))
          (values pk (equalp cksum (%v3-checksum pk))))
        (values nil nil))))

(defun onion-valid-p (onion)
  "True iff ONION is a well-formed v3 .onion address with a correct checksum."
  (multiple-value-bind (pk ok) (onion->pubkey onion) (and pk ok)))

;;; --- addrv2 tor entries -----------------------------------------------------

(defun parse-addrv2-onions (payload)
  "Extract Tor v3 (netID 4, 32-byte pubkey) entries from an addrv2 message as a list
   of (onion-address . port).  Ignores every other address type."
  (handler-case
      (let ((r (w:make-reader payload)) (out '()))
        (let ((n (w:r-varint r)))
          (dotimes (i n)
            (w:r-u32 r)                 ; time
            (w:r-varint r)              ; services
            (let* ((netid (w:r-u8 r)) (len (w:r-varint r))
                   (addr (w:r-bytes r len)) (port (w:r-port-be r)))
              (when (and (= netid 4) (= len 32))   ; TORV3
                (push (cons (pubkey->onion addr) port) out)))))
        out)
    (serious-condition () nil)))         ; truncated / malformed -> what we parsed so far is lost, fine

;;; --- persistent tor peer directory ------------------------------------------

(defvar *tor-directory* (make-hash-table :test 'equal)
  "onion-address (string) -> port.  Collected from addrv2 gossip; not yet dialable.")
(defvar *tor-dir-lock* (bt:make-lock "tor-directory"))

(defun tordir-add (onion port)
  "Add a v3 .onion peer to the directory (deduped).  Returns T if newly added."
  (when (and (stringp onion) (onion-valid-p onion))
    (bt:with-lock-held (*tor-dir-lock*)
      (unless (gethash onion *tor-directory*)
        (setf (gethash onion *tor-directory*) port) t))))

(defun tordir-count ()
  (bt:with-lock-held (*tor-dir-lock*) (hash-table-count *tor-directory*)))

(defun tordir-list (&optional limit)
  "Snapshot of (onion . port) entries, up to LIMIT."
  (bt:with-lock-held (*tor-dir-lock*)
    (let ((out '()) (n 0))
      (maphash (lambda (o p) (when (or (null limit) (< n limit)) (push (cons o p) out) (incf n)))
               *tor-directory*)
      out)))

(defun save-tor-directory (path)
  "Persist the directory as lines of \"<onion> <port>\"."
  (bt:with-lock-held (*tor-dir-lock*)
    (with-open-file (s path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (maphash (lambda (o p) (format s "~a ~d~%" o p)) *tor-directory*)))
  (tordir-count))

(defun load-tor-directory (path)
  "Load a directory file (if present); returns the number of entries loaded."
  (when (probe-file path)
    (with-open-file (s path :direction :input :if-does-not-exist nil)
      (when s
        (loop for line = (read-line s nil nil) while line do
          (let ((sp (position #\Space line)))
            (when sp
              (let ((onion (subseq line 0 sp))
                    (port (ignore-errors (parse-integer line :start (1+ sp) :junk-allowed t))))
                (when (and port (onion-valid-p onion))
                  (bt:with-lock-held (*tor-dir-lock*)
                    (setf (gethash onion *tor-directory*) port))))))))))
  (tordir-count))

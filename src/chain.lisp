;;;; shared/bitcoind/chain.lisp
;;;;
;;;; Phase 2 — the header chain.  Parse 80-byte block headers, validate
;;;; proof-of-work (compact nBits -> 256-bit target, blockhash <= target),
;;;; enforce the difficulty-retarget rule every 2016 blocks, track cumulative
;;;; chainwork, and drive headers-first sync over the P2P getheaders/headers
;;;; protocol.
;;;;
;;;; This is where the node first *validates consensus*: a peer can send us any
;;;; bytes, but a header only joins the chain if it links to a known parent, its
;;;; PoW is genuine, and (at period boundaries) its difficulty matches what the
;;;; retarget formula demands.  We cross-check the synced tip against the epyc
;;;; node's RPC `getbestblockhash`.


(defpackage #:cl-consensus.chain
  (:use #:cl)
  (:nicknames #:btc-chain)
  (:local-nicknames (#:w #:cl-consensus.wire) (#:p #:cl-consensus.peer)
                    (#:bt #:bordeaux-threads))
  (:export
   #:header #:header-hash #:header-height #:header-prev #:header-merkle
   #:header-time #:header-bits #:header-nonce #:header-version #:header-chainwork
   #:parse-header #:serialize-header #:header-hash-hex
   #:compact->target #:target->compact #:check-pow #:next-work-required
   ;; store
   #:*genesis* #:init-chain #:add-header #:tip #:tip-height #:header-at-height
   #:get-header #:chain-height #:build-locator #:median-time-past
   ;; reorg / best-chain activation
   #:best-header #:fork-point #:active-header-p #:activate-headers!
   ;; sync + persistence
   #:sync-headers #:*pow-limit*
   #:save-headers #:load-headers #:data-dir #:headers-file))

(in-package #:cl-consensus.chain)

;; forward references (store accessors used by the retarget/MTP code above them)
(declaim (ftype (function (t) t) header-at-height get-header))

;;; ----------------------------------------------------------------------------
;;; Header structure & (de)serialization (80 bytes on the wire)
;;; ----------------------------------------------------------------------------

(defstruct header
  version              ; int32
  prev                 ; 32-byte parent hash (internal LE)
  merkle               ; 32-byte merkle root
  time                 ; uint32 unix time
  bits                 ; uint32 compact target (nBits)
  nonce                ; uint32
  hash                 ; 32-byte HASH256 of the 80-byte header (computed)
  (height -1)          ; position in the active chain
  (chainwork 0))       ; cumulative work up to and including this header

(defun serialize-header (h)
  "The canonical 80-byte header serialization (also what we HASH256)."
  (let ((wr (w:make-writer)))
    (w:w-i32 wr (header-version h))
    (w:w-hash wr (header-prev h))
    (w:w-hash wr (header-merkle h))
    (w:w-u32 wr (header-time h))
    (w:w-u32 wr (header-bits h))
    (w:w-u32 wr (header-nonce h))
    (w:writer-bytes wr)))

(defun parse-header (r)
  "Read an 80-byte header from reader R, computing its hash."
  (let* ((start (w:reader-pos r))
         (version (w:r-i32 r))
         (prev (w:r-hash r))
         (merkle (w:r-hash r))
         (time (w:r-u32 r))
         (bits (w:r-u32 r))
         (nonce (w:r-u32 r))
         (end (w:reader-pos r))
         (raw (subseq (cl-consensus.wire::reader-buf r) start end)))
    (make-header :version version :prev prev :merkle merkle :time time
                 :bits bits :nonce nonce :hash (w:hash256 raw))))

(defun header-hash-hex (h) (w:hash->hex (header-hash h)))

;;; ----------------------------------------------------------------------------
;;; Compact target (nBits) <-> 256-bit target, proof-of-work, chainwork
;;; ----------------------------------------------------------------------------

(defparameter *pow-limit*
  #x00000000FFFF0000000000000000000000000000000000000000000000000000
  "Mainnet maximum target (easiest difficulty).  Compact form 0x1d00ffff.")

(defparameter *pow-limit-bits* #x1d00ffff)

(defun compact->target (bits)
  "Decode compact nBits to a full target integer (Core's SetCompact)."
  (let ((size (ash bits -24))
        (word (logand bits #x007fffff)))
    (if (<= size 3)
        (ash word (* -8 (- 3 size)))
        (ash word (* 8 (- size 3))))))

(defun target->compact (target)
  "Encode a target integer to compact nBits (Core's GetCompact)."
  (let* ((nbits (integer-length target))
         (size (floor (+ nbits 7) 8))
         (compact (if (<= size 3)
                      (ash target (* 8 (- 3 size)))
                      (ash target (* -8 (- size 3))))))
    (when (/= 0 (logand compact #x00800000))   ; would look negative -> bump
      (setf compact (ash compact -8))
      (incf size))
    (logior compact (ash size 24))))

(defun hash->int-le (hash)
  "Interpret a 32-byte hash as a little-endian integer (for PoW comparison)."
  (let ((acc 0))
    (loop for i from 0 below (length hash)
          do (setf acc (logior acc (ash (aref hash i) (* 8 i)))))
    acc))

(defun check-pow (h)
  "True iff header H's hash meets its own claimed difficulty, and that
   difficulty is no easier than the network minimum."
  (let ((target (compact->target (header-bits h))))
    (and (plusp target)
         (<= target *pow-limit*)
         (<= (hash->int-le (header-hash h)) target))))

(defun block-work (bits)
  "Work contributed by a block at difficulty BITS = 2^256 / (target+1)."
  (let ((target (compact->target bits)))
    (if (plusp target)
        (floor (ash 1 256) (1+ target))
        0)))

;;; ----------------------------------------------------------------------------
;;; Difficulty retarget (Core's GetNextWorkRequired / CalculateNextWorkRequired)
;;; ----------------------------------------------------------------------------

(defconstant +retarget-interval+ 2016)            ; blocks
(defconstant +target-timespan+ (* 14 24 60 60))   ; 1209600 s (two weeks)

(defun next-work-required (prev-header)
  "The nBits that the block *following* PREV-HEADER must carry."
  (let ((next-height (1+ (header-height prev-header))))
    (if (/= 0 (mod next-height +retarget-interval+))
        ;; not a boundary: difficulty unchanged
        (header-bits prev-header)
        ;; boundary: recompute from the timespan of the last 2016-block period.
        ;; pindexFirst = ancestor at next-height - 2016 (Core's off-by-one: the
        ;; span covers 2015 intervals, measured first->last of the period).
        (let* ((first (header-at-height (- next-height +retarget-interval+)))
               (timespan (- (header-time prev-header) (header-time first))))
          (setf timespan (max (floor +target-timespan+ 4)
                              (min (* +target-timespan+ 4) timespan)))
          (let ((new-target (floor (* (compact->target (header-bits prev-header))
                                      timespan)
                                   +target-timespan+)))
            (target->compact (min new-target *pow-limit*)))))))

;;; ----------------------------------------------------------------------------
;;; Median time past — median of the last 11 headers' timestamps (BIP113)
;;; ----------------------------------------------------------------------------

(defun median-time-past (header)
  (let ((times '()) (h header))
    (dotimes (i 11)
      (when (null h) (return))
      (push (header-time h) times)
      (setf h (get-header (header-prev h))))
    (let ((sorted (sort times #'<)))
      (nth (floor (length sorted) 2) sorted))))

;;; ----------------------------------------------------------------------------
;;; Chain store — all headers by hash, plus the active chain by height
;;; ----------------------------------------------------------------------------

(defvar *by-hash* (make-hash-table :test 'equal) "hex hash -> header (all known).")
(defvar *by-height* (make-array 0 :adjustable t :fill-pointer 0)
  "Active best chain: index = height -> header.")
(defvar *tip* nil)

(defparameter *genesis-header-hex*
  (concatenate 'string
    "01000000"                                                          ; version
    "0000000000000000000000000000000000000000000000000000000000000000"  ; prev
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"  ; merkle
    "29ab5f49"                                                          ; time
    "ffff001d"                                                          ; bits
    "1dac2b7c")                                                         ; nonce
  "The mainnet genesis block header (Jan 3 2009).")

(defvar *genesis* nil)

(defun get-header (hash-or-hex)
  (gethash (if (stringp hash-or-hex) hash-or-hex (w:hash->hex hash-or-hex))
           *by-hash*))

(defun header-at-height (height)
  (when (< -1 height (fill-pointer *by-height*))
    (aref *by-height* height)))

(defun tip () *tip*)
(defun tip-height () (if *tip* (header-height *tip*) -1))
(defun chain-height () (tip-height))

(defun init-chain ()
  "Reset the store and seed it with the validated genesis header."
  (setf *by-hash* (make-hash-table :test 'equal)
        *by-height* (make-array 0 :adjustable t :fill-pointer 0)
        *tip* nil)
  (let ((g (parse-header (w:make-reader (w:hex->bytes *genesis-header-hex*)))))
    (setf (header-height g) 0
          (header-chainwork g) (block-work (header-bits g))
          *genesis* g)
    (assert (string= (header-hash-hex g) (w:net-genesis-hash w:*network*))
            () "genesis hash mismatch: ~a" (header-hash-hex g))
    (setf (gethash (header-hash-hex g) *by-hash*) g)
    (vector-push-extend g *by-height*)
    (setf *tip* g)
    g))

(define-condition header-rejected (error)
  ((header :initarg :header :reader rejected-header)
   (reason :initarg :reason :reader rejected-reason))
  (:report (lambda (c s) (format s "header rejected: ~a" (rejected-reason c)))))

(defun add-header (h &key (validate t))
  "Validate H against its parent and append it to the chain.  Returns the
   header on success (or the existing one if already known); signals
   HEADER-REJECTED otherwise.  Headers-first: we extend the single active chain."
  (let ((hex (header-hash-hex h)))
    (let ((existing (gethash hex *by-hash*)))
      (when existing (return-from add-header existing)))
    (let ((parent (get-header (header-prev h))))
      (unless parent
        (error 'header-rejected :header h
               :reason (format nil "unknown parent ~a" (w:hash->hex (header-prev h)))))
      (let ((height (1+ (header-height parent))))
        (when validate
          ;; 1. genuine proof-of-work
          (unless (check-pow h)
            (error 'header-rejected :header h :reason "insufficient proof-of-work"))
          ;; 2. difficulty must match the retarget rule
          (let ((expected (next-work-required parent)))
            (unless (= (header-bits h) expected)
              (error 'header-rejected :header h
                     :reason (format nil "bad nBits at height ~d: got ~8,'0x expected ~8,'0x"
                                     height (header-bits h) expected))))
          ;; 3. timestamp must beat the median of the last 11 (BIP113)
          (let ((mtp (median-time-past parent)))
            (when (<= (header-time h) mtp)
              (error 'header-rejected :header h
                     :reason (format nil "time ~d <= median-time-past ~d"
                                     (header-time h) mtp)))))
        (setf (header-height h) height
              (header-chainwork h) (+ (header-chainwork parent) (block-work (header-bits h))))
        (setf (gethash hex *by-hash*) h)
        ;; extend active chain (headers-first; assumes mostly-linear growth)
        (when (and *tip* (equalp (header-prev h) (header-hash *tip*)))
          (if (< height (fill-pointer *by-height*))
              (setf (aref *by-height* height) h)
              (vector-push-extend h *by-height*))
          (when (> (header-chainwork h) (header-chainwork *tip*))
            (setf *tip* h)))
        h))))

;;; ----------------------------------------------------------------------------
;;; Reorg / best-chain activation helpers
;;; ----------------------------------------------------------------------------
;;;
;;; ADD-HEADER already stores competing-fork headers in *by-hash* with correct
;;; cumulative chainwork, but only ever ACTIVATES (extends *by-height*/*tip*) a
;;; header whose parent IS the current tip.  These helpers expose the best-work
;;; header across all known branches, the common ancestor of two branches, and an
;;; explicit "activate this branch" mutation — so the reorg layer can switch the
;;; active chain to a heavier competing branch.

(defun best-header ()
  "The known header (incl. competing forks in *by-hash*) with the greatest
   cumulative chainwork.  Starts from *tip* so an equal-work tip is never displaced;
   first-seen wins ties among forks (a residual gap vs Core's lowest-hash rule)."
  (let ((best *tip*))
    (maphash (lambda (hex h)
               (declare (ignore hex))
               (when (or (null best) (> (header-chainwork h) (header-chainwork best)))
                 (setf best h)))
             *by-hash*)
    best))

(defun fork-point (a b)
  "The lowest common ancestor header of A and B: walk the deeper one up to equal
   height, then both back in lockstep until the SAME header object (headers are
   interned in *by-hash*, so EQ identifies the common ancestor)."
  (loop while (> (header-height a) (header-height b))
        do (setf a (get-header (header-prev a))))
  (loop while (> (header-height b) (header-height a))
        do (setf b (get-header (header-prev b))))
  (loop until (eq a b)
        do (setf a (get-header (header-prev a))
                 b (get-header (header-prev b))))
  a)

(defun active-header-p (h)
  "T iff H is the header currently active at its height on *by-height*."
  (eq h (header-at-height (header-height h))))

(defun activate-headers! (branch-headers)
  "Splice BRANCH-HEADERS (ascending by height, contiguous from some fork+1) into the
   active chain *by-height*, overwriting any headers previously active at those
   heights, truncate any now-stale higher tail, and set *tip* to the last.  Pure
   header-store mutation — the UTXO reorg is the caller's job.  Returns the new tip."
  (dolist (h branch-headers)
    (let ((ht (header-height h)))
      (if (< ht (fill-pointer *by-height*))
          (setf (aref *by-height* ht) h)
          (vector-push-extend h *by-height*))))
  (when branch-headers
    (let ((new-tip (car (last branch-headers))))
      (setf (fill-pointer *by-height*) (1+ (header-height new-tip))
            *tip* new-tip)))
  *tip*)

;;; ----------------------------------------------------------------------------
;;; Block locator (dense near tip, exponential back-off, ending at genesis)
;;; ----------------------------------------------------------------------------

(defun build-locator (&optional (from *tip*))
  "List of block hashes describing our chain to a peer, newest first."
  (let ((locator '()) (height (header-height from)) (step 1) (count 0))
    (loop while (> height 0) do
      (let ((h (header-at-height height)))
        (when h (push (header-hash h) locator) (incf count)))
      (when (>= count 10) (setf step (* step 2)))
      (decf height step))
    (push (header-hash *genesis*) locator)
    (nreverse locator)))

;;; ----------------------------------------------------------------------------
;;; getheaders / headers protocol
;;; ----------------------------------------------------------------------------

(defun build-getheaders-payload (locator)
  (let ((wr (w:make-writer)))
    (w:w-u32 wr p:*protocol-version*)
    (w:w-varint wr (length locator))
    (dolist (h locator) (w:w-hash wr h))
    (w:w-hash wr (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)) ; hash_stop=0
    (w:writer-bytes wr)))

(defun parse-headers-message (payload)
  "Parse a 'headers' message into a list of HEADER structs (in order)."
  (let* ((r (w:make-reader payload))
         (count (w:r-varint r))
         (out '()))
    (dotimes (i count (nreverse out))
      (push (parse-header r) out)
      (w:r-varint r))))    ; tx_count, always 0 in a headers message

;;; ----------------------------------------------------------------------------
;;; Sync driver
;;; ----------------------------------------------------------------------------

(defun sync-headers (peer &key (max-batches most-positive-fixnum)
                               (progress-every 20000) (validate t))
  "Drive headers-first sync from PEER until caught up (a batch < 2000) or
   MAX-BATCHES is hit.  Returns the number of headers added."
  (unless *tip* (init-chain))
  (let ((added 0)
        (done (bt:make-semaphore))
        (batches 0)
        (last-error nil))
    (p:on peer "headers"
          (lambda (pr payload)
            (handler-case
                (let ((headers (parse-headers-message payload)))
                  (dolist (h headers)
                    (handler-case
                        (progn (add-header h :validate validate) (incf added))
                      (header-rejected (c)
                        ;; a header that doesn't extend our tip (e.g. a stale
                        ;; locator overlap) is fine to skip; a PoW/difficulty
                        ;; failure is a real problem.
                        (unless (search "unknown parent" (rejected-reason c))
                          (setf last-error c)
                          (bt:signal-semaphore done)
                          (return)))))
                  (when (and (> added 0) (zerop (mod added progress-every)))
                    (format t "~&[sync] height ~d  tip ~a~%"
                            (tip-height) (header-hash-hex (tip)))
                    (force-output))
                  (incf batches)
                  (cond
                    ((or (< (length headers) 2000) (>= batches max-batches))
                     (bt:signal-semaphore done))
                    (t (p:send pr "getheaders"
                               (build-getheaders-payload (build-locator))))))
              (serious-condition (c)
                (setf last-error c)
                (bt:signal-semaphore done)))))
    ;; kick it off
    (p:send peer "getheaders" (build-getheaders-payload (build-locator)))
    (bt:wait-on-semaphore done)
    (when last-error (error last-error))
    added))

;;; ----------------------------------------------------------------------------
;;; Persistence — the active chain as a flat file of 80-byte headers in height
;;; order (genesis is reseeded by INIT-CHAIN, so we store heights 1..tip).
;;; ----------------------------------------------------------------------------

(defun writable-dir-p (dir)
  (handler-case
      (progn (ensure-directories-exist dir)
             (let ((probe (merge-pathnames ".wtest" dir)))
               (with-open-file (s probe :direction :output :if-exists :supersede
                                        :if-does-not-exist :create)
                 (write-char #\x s))
               (delete-file probe) t))
    (serious-condition () nil)))

(defun data-dir ()
  "Prefer the big volume; fall back to ~/.cl-consensus until it's writable."
  (let ((env #+sbcl (sb-ext:posix-getenv "BITCOIND_DATADIR") #-sbcl nil))
    (cond (env (pathname (if (char= #\/ (char env (1- (length env)))) env
                             (concatenate 'string env "/"))))
          ((writable-dir-p #p"/mnt/lisp/bitcoind/") #p"/mnt/lisp/bitcoind/")
          (t (merge-pathnames ".cl-consensus/bitcoind/" (user-homedir-pathname))))))

(defun headers-file () (merge-pathnames "headers.dat" (data-dir)))

(defun save-headers (&optional (path (headers-file)))
  "Write the active chain (heights 1..tip) as concatenated 80-byte headers."
  (ensure-directories-exist path)
  (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                          :if-exists :supersede :if-does-not-exist :create)
    (loop for height from 1 to (tip-height)
          for h = (header-at-height height)
          do (write-sequence (serialize-header h) s)))
  (format t "~&[chain] saved ~d headers to ~a~%" (tip-height) path)
  (tip-height))

(defun load-headers (&key (path (headers-file)) (validate t))
  "Reseed genesis, then replay the on-disk headers back into the chain."
  (init-chain)
  (unless (probe-file path) (return-from load-headers 0))
  (let ((n 0))
    (with-open-file (s path :element-type '(unsigned-byte 8))
      (let ((buf (make-array 80 :element-type '(unsigned-byte 8))))
        (loop while (= 80 (read-sequence buf s))
              do (add-header (parse-header (w:make-reader (copy-seq buf)))
                             :validate validate)
                 (incf n))))
    (format t "~&[chain] loaded ~d headers from ~a (tip height ~d)~%" n path (tip-height))
    n))

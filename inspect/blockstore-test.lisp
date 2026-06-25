;;;; inspect/blockstore-test.lisp
;;;;
;;;; Gate for the append-only raw-block store: round-trip (store->get exact bytes),
;;;; persistence across reopen (index rebuilt by scan), duplicate suppression, and
;;;; torn-tail recovery (a partial trailing append is truncated, earlier records
;;;; survive).  Fully offline; uses a temp file under /tmp.
;;;;
;;;;   sbcl --load inspect/blockstore-test.lisp --eval '(blockstore-test:run)'
(require :asdf)
(require :sb-posix)
(pushnew #p"/home/claude/pagetree/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/secp256k1-fast/" asdf:*central-registry* :test #'equal)
(pushnew #p"/home/claude/cl-consensus/" asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-consensus"))

(defpackage :blockstore-test
  (:use :cl)
  (:local-nicknames (:bs :cl-consensus.blockstore) (:w :cl-consensus.wire))
  (:export #:run))
(in-package :blockstore-test)

(defun fake-block (tag body-len)
  "A fake raw block: an 80-byte header (byte 0 = TAG so blocks differ) + BODY-LEN
   body bytes.  The store only needs the 80-byte header to derive the hash."
  (let ((raw (make-array (+ 80 body-len) :element-type '(unsigned-byte 8))))
    (dotimes (i (length raw)) (setf (aref raw i) (logand (+ tag i) 255)))
    (setf (aref raw 0) tag)
    raw))

(defun hx (raw) (w:hash->hex (w:hash256 (subseq raw 0 80))))

(defun run ()
  (let* ((path "/tmp/bs-test.dat") (ok t)
         (blocks (loop for i from 1 to 5 collect (fake-block i (* i 7)))))
    (ignore-errors (delete-file path))
    ;; --- store + round-trip ---
    (let ((s (bs:open-block-store path)))
      (dolist (b blocks) (bs:store-block s b))
      (unless (= (bs:block-store-count s) 5)
        (setf ok nil) (format t "  *** expected 5 stored, got ~d~%" (bs:block-store-count s)))
      (dolist (b blocks)
        (let ((got (bs:get-block-bytes s (hx b))))
          (unless (and got (equalp got b))
            (setf ok nil) (format t "  *** round-trip mismatch for block tag ~d~%" (aref b 0)))))
      ;; duplicate suppression
      (when (bs:store-block s (first blocks))
        (setf ok nil) (format t "  *** duplicate store should be a no-op~%"))
      (unless (= (bs:block-store-count s) 5)
        (setf ok nil) (format t "  *** count changed after dup store~%"))
      (bs:close-block-store s))
    (format t "[blockstore-test] store+round-trip+dup: ~a~%" ok)
    ;; --- persistence across reopen (index rebuilt by scan) ---
    (let ((s (bs:open-block-store path)))
      (unless (= (bs:block-store-count s) 5)
        (setf ok nil) (format t "  *** reopen: expected 5, got ~d~%" (bs:block-store-count s)))
      (dolist (b blocks)
        (unless (equalp (bs:get-block-bytes s (hx b)) b)
          (setf ok nil) (format t "  *** reopen round-trip mismatch tag ~d~%" (aref b 0))))
      ;; append one more after reopen, ensure it persists
      (let ((b6 (fake-block 6 40)))
        (bs:store-block s b6)
        (unless (equalp (bs:get-block-bytes s (hx b6)) b6)
          (setf ok nil) (format t "  *** post-reopen append round-trip failed~%")))
      (bs:close-block-store s))
    (format t "[blockstore-test] persistence+append: ~a~%" ok)
    ;; --- torn-tail recovery: corrupt the file by appending a partial record ---
    (with-open-file (f path :direction :output :element-type '(unsigned-byte 8)
                            :if-exists :append)
      ;; write a length header claiming 9999 bytes but only 3 body bytes -> torn
      (write-byte #x0f f) (write-byte #x27 f) (write-byte 0 f) (write-byte 0 f) ; len=9999 LE
      (write-byte 1 f) (write-byte 2 f) (write-byte 3 f))
    (let ((s (bs:open-block-store path)))
      ;; the 6 whole records must survive; the torn tail is dropped
      (unless (= (bs:block-store-count s) 6)
        (setf ok nil) (format t "  *** torn-tail: expected 6 survivors, got ~d~%" (bs:block-store-count s)))
      ;; and we can still append cleanly after recovery
      (let ((b7 (fake-block 7 12)))
        (bs:store-block s b7)
        (unless (equalp (bs:get-block-bytes s (hx b7)) b7)
          (setf ok nil) (format t "  *** post-recovery append failed~%")))
      (bs:close-block-store s))
    ;; reopen once more to confirm the recovered+appended file is consistent
    (let ((s (bs:open-block-store path)))
      (unless (= (bs:block-store-count s) 7)
        (setf ok nil) (format t "  *** final reopen: expected 7, got ~d~%" (bs:block-store-count s)))
      (bs:close-block-store s))
    (format t "[blockstore-test] torn-tail recovery: ~a~%" ok)
    (ignore-errors (delete-file path))
    (format t "~&blockstore-test: ~a~%" (if ok "OK" "FAILED"))
    ok))

;;;; inspect/introspect.lisp — observability for long-running, --non-interactive SBCL
;;;; jobs that go quiet (the "what is this 5-days-at-100%-CPU process actually doing?"
;;;; problem — e.g. the block-sweep jobs that hung for days with ZERO output, on a
;;;; box where ptrace_scope=2 blocks gdb).
;;;;
;;;; Two tools, and the hard-won lesson about which actually works:
;;;;
;;;;   (introspect:beat "label" status-fn)   ; MAIN-THREAD progress log — RELIABLE
;;;;       Call it from your job's main loop.  Appends a timestamped
;;;;       "[hb] label: <status>" line to /tmp/label.hb.  A stale mtime => stuck, and
;;;;       the last line names exactly where.  This is the single most important
;;;;       thing the sweeps lacked: with no progress trail, a quiet process is a
;;;;       black box.
;;;;
;;;;   (introspect:dump-all-threads stream)   ; deep "what is each thread BLOCKED on"
;;;;       Backtraces every thread (via interrupt-thread, which unwinds even a thread
;;;;       blocked in a futex/syscall — PROVEN to print SB-THREAD::FUTEX-WAIT frames).
;;;;       Invoke it from a context that runs: the node's control-loop
;;;;       (echo '(introspect:dump-all-threads *standard-output*)' | nc 127.0.0.1 4008)
;;;;       or a daemon's already-running thread.
;;;;
;;;; SBCL GOTCHA (measured): a BACKGROUND watcher thread that polls/sleeps does NOT
;;;; reliably get scheduled once the main thread enters an infinite (loop (sleep ...))
;;;; under `--non-interactive --load` — it can be starved before it ever starts.
;;;; Only a thread already blocked in a SYSCALL (e.g. socket accept, as in
;;;; serve-daemon's listener) stays runnable.  So: prefer main-thread `beat` logging;
;;;; reach for dump-all-threads through an existing live listener, not a new poller.

(defpackage #:introspect
  (:use #:cl)
  (:export #:dump-all-threads #:beat))
(in-package #:introspect)

(defun dump-all-threads (&optional (stream *error-output*))
  "Print a backtrace of every live thread to STREAM.  Each non-current thread is
   interrupted to print its OWN stack, so threads blocked in a syscall/futex reveal
   exactly where they wait."
  (let ((me sb-thread:*current-thread*))
    (format stream "~&==== thread dump (pid ~d) ====~%" (sb-unix:unix-getpid))
    (dolist (th (sb-thread:list-all-threads))
      (format stream "~&-- thread ~s --~%" (sb-thread:thread-name th))
      (cond
        ((eq th me) (sb-debug:print-backtrace :stream stream :count 25))
        ((sb-thread:thread-alive-p th)
         (let ((done (sb-thread:make-semaphore)))
           (handler-case
               (progn
                 (sb-thread:interrupt-thread
                  th (lambda ()
                       (ignore-errors (sb-debug:print-backtrace :stream stream :count 25))
                       (sb-thread:signal-semaphore done)))
                 (unless (sb-thread:wait-on-semaphore done :timeout 5)
                   (format stream "  (no response in 5s — in an uninterruptible foreign call)~%")))
             (serious-condition (e) (format stream "  (could not introspect: ~a)~%" e)))))
        (t (format stream "  (dead)~%"))))
    (format stream "~&==== end thread dump ====~%")
    (force-output stream)))

(defun beat (label status &key (path (format nil "/tmp/~a.hb" label)))
  "Append a timestamped progress line for LABEL to PATH from the CURRENT (main)
   thread.  STATUS is a string or a thunk (called now).  Call this from your job's
   main loop every so often — a stale file mtime then means the job is stuck, and the
   last line names the phase/height it stalled in.  Reliable (no background thread)."
  (let ((s (if (functionp status)
               (handler-case (funcall status) (serious-condition (e) (format nil "status-err: ~a" e)))
               status)))
    (ignore-errors
     (with-open-file (f path :direction :output :if-exists :append :if-does-not-exist :create)
       (multiple-value-bind (sec min hr da mo yr) (decode-universal-time (get-universal-time))
         (format f "~&~d-~2,'0d-~2,'0d ~2,'0d:~2,'0d:~2,'0d [hb] ~a: ~a~%" yr mo da hr min sec label s)
         (force-output f))))
    s))

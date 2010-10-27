;;; vim:set fileencoding=utf-8:

;;;
;;; Test rfc.pop3
;;;

(use gauche.test)
(use gauche.process)
(use gauche.net)
(use srfi-13)
(use util.list)

(test-start "rfc.pop3")
(use rfc.pop3)
(test-module 'rfc.pop3)

(define *pop-port* 7011)
(define *users* '(("user" . "pass")))
(define *stamp-base* #`",(sys-getpid).,(sys-time)@localhost")

(define *simple-popd*
  `(
    (use gauche.net)
    (use rfc.md5)
    (use util.digest)
    (use util.list)

    (define *pop-port* ,*pop-port*)
    (define *users* ',*users*)
    (define *stamp-base* ,*stamp-base*)
    (define *user* #f)

    (define (%read-line iport)
      (let loop ((c (read-char iport))
                 (r '()))
        (cond ((eof-object? c)
               (list->string (reverse r)))
              ((eqv? c #\newline)
               (list->string (reverse (cons c r))))
              (else
                (loop (read-char iport)
                      (cons c r))))))

    (define %mkdigest
      (compose digest-hexify (pa$ digest-string <md5>)))

    (define (pop-server socket apop)
      (let* ((client (socket-accept socket))
             (in (socket-input-port client))
             (out (socket-output-port client)))
        (if apop
          (display #`"+OK ready <,|apop|>\r\n" out)
          (display "OK+ ready\r\n" out))
        (let loop ((line (%read-line in)))
          (cond [(#/^USER (.+)\r\n/ line)
                 => (lambda (m)
                      (let1 user (m 1)
                        (if (assoc user *users*)
                          (begin (display "+OK\r\n" out)
                                 (set! *user* user))
                          (display "-ERR unknown user\r\n" out))
                        (loop (%read-line in))))]
                [(#/^PASS (.+)\r\n/ line)
                 => (lambda (m)
                      (let1 pass (m 1)
                        (if (equal? pass (assoc-ref *users* *user*))
                          (display "+OK\r\n" out)
                          (display "-ERR invalid password\r\n" out))
                        (loop (%read-line in))))]
                [(#/^APOP (.+) (.+)\r\n/ line)
                 => (lambda (m)
                      (let ((user (m 1))
                            (digest (m 2)))
                        (or (and-let*
                              ([ apop ]
                               [pass (assoc-ref *users* user)]
                               [digest~ (%mkdigest #`"<,|apop|>,|pass|")]
                               [ (equal? digest digest~) ])
                              (display "+OK\r\n" out))
                            (display "-ERR authentication failed\r\n" out))
                        (loop (%read-line in))))]
                [(#/^QUIT\r\n/ line)
                 (display "+OK bye\r\n" out)
                 (socket-close client)
                 (sys-exit 0)]
                [else
                  (display "-ERR command not recognized\r\n" out)
                  (socket-close client)
                  (sys-exit 1)]))))

    (define (main args)
      (let ((apop *stamp-base*)
            (socket (make-server-socket 'inet *pop-port* :reuse-addr? #t)))
        (print "ready") (flush) ;handshake
        (pop-server socket apop)
        0))
    ))

;; Start test server
(with-output-to-file "./testsrv.o" (lambda () (for-each write *simple-popd*)))
(let1 pc (run-process '("gosh" "./testsrv.o") :output :pipe)
  (read-line (process-output pc)) ;handshake
  )

(define conn (make-pop3-connection "localhost" *pop-port*))

(test* "greeting" "+OK" (and-let* ((res (get-response conn))
                                   (m (#/^(\+OK).*$/ res)))
                          (m 1)))
(pop3-quit conn)

(sys-waitpid -1)

;; epilogue
(test-end)




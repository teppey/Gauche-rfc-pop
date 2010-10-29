;;; vim:set fileencoding=utf-8:

;;;
;;; Test rfc.pop3
;;;

(use gauche.test)
(use gauche.process)
(use gauche.net)
(use srfi-1)
(use srfi-13)
(use util.list)
(use rfc.md5)
(use util.digest)

(test-start "rfc.pop3")
(use rfc.pop3)
(test-module 'rfc.pop3)

(define *pop-port* 7011)
(define *users* '(("user" . "pass")))
(define *stamp* #`"<,(sys-getpid).,(sys-time)@localhost>")
(define *retr-response* '("From: postmaster"
                          "Content-Type: text/plain"
                          "MIME-Version: 1.0"
                          "Subject: Dummy"
                          ""
                          "line1"
                          "line2"
                          "line3"
                          ".\r\n"))

(define *simple-popd*
  `(
    (use gauche.net)
    (use rfc.md5)
    (use util.digest)
    (use util.list)

    (define *pop-port* ,*pop-port*)
    (define *users* ',*users*)
    (define *stamp* ,*stamp*)
    (define *user* #f)
    (define *list-response* "1 1\r\n2 2\r\n3 3\r\n4 4\r\n5 5\r\n.\r\n")
    (define *retr-response* ',*retr-response*)

    (define %mkdigest
      (compose digest-hexify (pa$ digest-string <md5>)))

    (define (pop-server socket)
      (let* ((client (socket-accept socket))
             (in (socket-input-port client))
             (out (socket-output-port client)))
        (display #`"+OK ready ,|*stamp*|\r\n" out)
        (let loop ((line (read-line in)))
          (cond [(#/^USER (.+)/ line)
                 => (lambda (m)
                      (let1 user (m 1)
                        (if (assoc user *users*)
                          (begin (display "+OK\r\n" out)
                                 (set! *user* user))
                          (display "-ERR unknown user\r\n" out))
                        (loop (read-line in))))]
                [(#/^PASS (.+)/ line)
                 => (lambda (m)
                      (let1 pass (m 1)
                        (if (equal? pass (assoc-ref *users* *user*))
                          (display "+OK\r\n" out)
                          (display "-ERR invalid password\r\n" out))
                        (loop (read-line in))))]
                [(#/^APOP (.+) (.+)/ line)
                 => (lambda (m)
                      (let ((user (m 1))
                            (digest (m 2)))
                        (or (and-let*
                              ([ *stamp* ]
                               [pass (assoc-ref *users* user)]
                               [digest~ (%mkdigest #`",|*stamp*|,|pass|")]
                               [ (equal? digest digest~) ])
                              (display "+OK\r\n" out))
                            (display "-ERR authentication failed\r\n" out))
                        (loop (read-line in))))]
                [(#/^LIST\s*(.*)$/ line)
                 => (lambda (m)
                      (if (string->number (m 1))
                        (display #`"+OK ,(m 1) ,(m 1)\r\n" out)
                        (begin
                          (display "+OK\r\n" out)
                          (display *list-response* out)))
                      (loop (read-line in)))]
                [(#/^STAT/ line)
                 (display "+OK 10 100\r\n" out)
                 (loop (read-line in))]
                [(#/^DELE\s*\d+$/ line)
                 (display "+OK message marked for deletion\r\n" out)
                 (loop (read-line in))]
                [(#/^NOOP$/ line)
                 (display "+OK done nothing\r\n" out)
                 (loop (read-line in))]
                [(or (#/^RETR\s*\d+$/ line)
                     (#/^TOP\s*\d+\s*\d+$/ line))
                 (let1 res (string-join *retr-response* "\r\n")
                   (format out "+OK ~d bytes\r\n" (string-size res))
                   (display res out))
                 (loop (read-line in))]
                [(#/^UIDL\s*(.*)$/ line)
                 => (lambda (m)
                      (if (string->number (m 1))
                        (format out "+OK ~a ~a\r\n" (m 1) (%mkdigest "foo"))
                        (begin
                          (display "+OK\r\n" out)
                          (format out "1 ~a\r\n" (%mkdigest "foo"))
                          (format out "2 ~a\r\n" (%mkdigest "bar"))
                          (display ".\r\n" out)))
                      (loop (read-line in)))]
                [(#/^QUIT/ line)
                 (display "+OK bye\r\n" out)
                 (socket-close client)
                 (sys-exit 0)]
                [else
                  (display "-ERR command not recognized\r\n" out)
                  (socket-close client)
                  (sys-exit 1)]))))

    (define (main args)
      (let1 socket (make-server-socket 'inet *pop-port* :reuse-addr? #t)
        (print "ready") (flush) ;handshake
        (pop-server socket)
        0))
    ))

(with-output-to-file "./testsrv.scm" (lambda () (for-each write *simple-popd*)))

(define (start-test-server)
  (let1 pc (run-process '("gosh" "./testsrv.scm") :output :pipe)
    (read-line (process-output pc)) ;handshake
    ))

(start-test-server)
(define conn (pop3-connect "localhost" *pop-port*))

(define (test-ok comment response)
  (test* comment "+OK" response string-prefix?))

(test* "timestamp" *stamp* (ref conn 'stamp))

(test-ok "login ok" (pop3-login conn "user" "pass"))

(test* "login ng" (test-error <pop3-authentication-error>)
       (pop3-login conn "user" "bad password"))

(test-ok "apop ok" (pop3-login-apop conn "user" "pass"))

(test* "apop ng" (test-error <pop3-authentication-error>)
       (pop3-login-apop conn "user" "bad password"))

(test* "list with arg" '(1 . 1)
       (receive (num size) (pop3-list conn 1)
         (cons num size)))

(test* "list without arg" '((1 . 1) (2 . 2) (3 . 3) (4 . 4) (5 . 5))
       (pop3-list conn))

(test* "stat" '(10 . 100)
       (receive (num size) (pop3-stat conn)
         (cons num size)))

(test-ok "dele" (pop3-dele conn 1))

(test-ok "noop" (pop3-noop conn))

(test* "retr" (string-append
                (string-join (drop-right *retr-response* 1) "\r\n")
                "\r\n")
       (pop3-retr conn 1))

(test* "top" (string-append
                (string-join (drop-right *retr-response* 1) "\r\n")
                "\r\n")
       (pop3-top conn 1 1))

(test* "uidl with arg" (cons 1 (digest-hexify (digest-string <md5> "foo")))
       (receive (num unique-id) (pop3-uidl conn 1)
         (cons num unique-id)))

(test* "uidl without arg"
       `((1 . ,(digest-hexify (digest-string <md5> "foo")))
         (2 . ,(digest-hexify (digest-string <md5> "bar"))))
       (pop3-uidl conn))

(test-ok "quit" (pop3-quit conn))
(sys-waitpid -1)


(start-test-server)
(test-ok "call-with-pop3-connection"
         (call-with-pop3-connection "localhost"
           (lambda (conn)
             (pop3-login conn "user" "pass"))
           :port *pop-port*))
(sys-waitpid -1)



;; epilogue
(test-end)




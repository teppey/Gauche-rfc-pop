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
(define *apop-stamp* #`"<,(sys-getpid).,(sys-time)@localhost>")

(define *simple-popd*
  `(
    (use gauche.net)
    (use rfc.md5)
    (use util.digest)
    (use util.list)

    (define *pop-port* ,*pop-port*)
    (define *users* ',*users*)
    (define *apop-stamp* ,*apop-stamp*)
    (define *user* #f)
    (define *list-response* "1 1\r\n2 2\r\n3 3\r\n4 4\r\n5 5\r\n.\r\n")

    (define %mkdigest
      (compose digest-hexify (pa$ digest-string <md5>)))

    (define (pop-server socket apop)
      (let* ((client (socket-accept socket))
             (in (socket-input-port client))
             (out (socket-output-port client)))
        (if apop
          (display #`"+OK ready ,|apop|\r\n" out)
          (display "OK+ ready\r\n" out))
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
                              ([ apop ]
                               [pass (assoc-ref *users* user)]
                               [digest~ (%mkdigest #`",|apop|,|pass|")]
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
                [(#/^QUIT/ line)
                 (display "+OK bye\r\n" out)
                 (socket-close client)
                 (sys-exit 0)]
                [else
                  (display "-ERR command not recognized\r\n" out)
                  (socket-close client)
                  (sys-exit 1)]))))

    (define (main args)
      (let ((apop *apop-stamp*)
            (socket (make-server-socket 'inet *pop-port* :reuse-addr? #t)))
        (print "ready") (flush) ;handshake
        (pop-server socket apop)
        0))
    ))

;; Start test server
(with-output-to-file "./testsrv.scm" (lambda () (for-each write *simple-popd*)))
(let1 pc (run-process '("gosh" "./testsrv.scm") :output :pipe)
  (read-line (process-output pc)) ;handshake
  )

(define conn (pop3-connect "localhost" *pop-port*))

(define (test-ok comment response)
  (test* comment "+OK" response string-prefix?))

(test-ok "auth ok" (pop3-login conn "user" "pass"))
(test* "auth ng" (test-error <pop3-authentication-error>)
       (pop3-login conn "user" "bad password"))
(test-ok "apop ok" (pop3-login-apop conn "user" "pass"))
(test* "apop ng" (test-error <pop3-authentication-error>)
       (pop3-login-apop conn "user" "bad password"))
(test* "list with arg" '((1 . 1)) (pop3-list conn 1))
(test* "list without arg" '((1 . 1) (2 . 2) (3 . 3) (4 . 4) (5 . 5))
       (pop3-list conn))
(test-ok "quit" (pop3-quit conn))

(sys-waitpid -1)

;; epilogue
(test-end)




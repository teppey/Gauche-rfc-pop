(use gauche.net)
(use rfc.md5)
(use util.digest)
(use util.list)

;; Simple pop3 server
(define *pop-port* 7011)
(define *users* '(("user" . "pass")))

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

(define %mkdigest (compose digest-hexify (pa$ digest-string <md5>)))

(define (pop-server socket apop)
  (let* ((client (socket-accept socket))
         (in (socket-input-port client :buffering :none))
         (out (socket-output-port client :buffering :none)))
    (if apop
      (display #`"OK+ ready <,|apop|>\r\n" out)
      (display "OK+ ready\r\n" out))
    (let loop ((line (%read-line in)))
      (cond [(#/^USER (.+)\r\n/ line)
             => (lambda (m)
                  (let1 user (m 1)
                    (if (assoc user *users*)
                      (display "+OK\r\n" out)
                      (display "-ERR unknown user\r\n" out))
                    (loop (%read-line in))))]
            [(#/^PASS (.+)\r\n/ line)
             => (lambda (m)
                  (let1 pass (m 1)
                    (if (equal? pass (assoc-ref *users* user))
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
  (let ((apop #`",(sys-getpid).,(sys-time)@localhost")
        (socket (make-server-socket 'inet *pop-port* :reuse-addr? #t)))
    (pop-server socket apop)
    0))


; coding: utf-8

(use file.util)
(use rfc.pop3)
(use gauche.parseopt)
(use gauche.process)

(define *server* "pop.example.com")
(define *username* "your-username")
(define *password* "your-password")
(define *mda* "/usr/bin/procmail")

(define (main args)
  (let-args (cdr args)
    ((help  "h|help" => usage)
     (check "c|check")
     (keep  "k|keep")
     (else rest (usage)))

    (unless (file-is-executable? *mda*)
      (error "cannot execute:" *mda*))

    (call-with-pop3-connection *server* *username* *password*
      (lambda (conn)
        (receive (count size) (pop3-stat conn)
          (format #t "~d messags for ~a at ~a (~d octets).\n"
                  count *username* *server* size)
          (unless check
            (for-each
              (lambda (p)
                (let* ((num (car p))
                       (size (cdr p))
                       (tr (run-process '("tr" "-d" "\\r")
                                        :input :pipe :output :pipe)) ;strip CR
                       (mda (run-process `(,*mda*) :input (process-output tr))))
                  (pop3-retr conn num
                             :sink (process-input tr)
                             :flusher close-output-port)
                  (process-wait tr)
                  (process-wait mda)
                  (format #t "reading message ~a@~a:~d of ~d (~d octets) ~a\n"
                          *username* *server* num count size
                          (if keep "not flushed" "flushed"))
                  (unless keep (pop3-dele conn num))))
              (pop3-list conn))))))

    (exit 0)))

(define (usage)
  (print #`"Usage: ,(sys-basename *program-name*) [options]")
  (for-each print
            '("options:"
              "    -h, --help   print this message"
              "    -c, --check  check for messages without fetching"
              "    -k, --keep   save new messages after retrieval"))
  (exit 0))


;;;
;;; rfc.pop3
;;;

(define-module rfc.pop3
  (use gauche.net)
  (use srfi-13)
  (export-all)
  )
(select-module rfc.pop3)

(define-constant *default-pop3-port* 110)
(define-constant *open-timeout* 30)

(define-condition-type <pop3-error> <error> #f)

(define (pop3-error res . args)
  (apply error <pop3-error> res args))

(define-class <pop3-connection> ()
  ((socket :init-keyword :socket :init-value #f)
   (apop :init-keyword :apop :init-value #f)))

;; http://d.hatena.ne.jp/rui314/20070322/p1
(define (with-timeout proc sec default)
  (let/cc k
    (with-signal-handlers
      ((SIGALRM (k default)))
      (lambda ()
        (dynamic-wind
          (lambda () (sys-alarm sec))
          (lambda () (proc))
          (lambda () (sys-alarm 0)))))))

;; TODO
(define (%logging message)
  (display message (current-error-port))
  (newline (current-error-port)))

(define (make-pop3-connection host port . apop)
  (let1 apop (get-optional apop #f)
    (make <pop3-connection>
      :apop apop
      :socket (make-client-socket 'inet host port))))

(define (call-with-pop3-connection proc host username password . options)
  (let-keywords options ((port *default-pop3-port*)
                         (apop #f))
    (let1 conn (with-timeout
                  (lambda ()
                    (make <pop3-connection>
                      :apop apop
                      :socket (make-client-socket 'inet host port)))
                  *open-timeout* #f)
      (unless conn (pop3-error "timeout"))
      (%logging #`"POP session started: ,|host|:,|port|")
      (read-line (socket-input-port (ref conn 'socket))) ;read greeting
      (unwind-protect (proc conn)
        (pop3-quit conn)))))

(define (send-command conn fmt . args)
  (let1 out (socket-output-port (ref conn 'socket))
    (apply format out #`",|fmt|\r\n" args)
    (get-response conn)))

(define (get-response conn)
  (read-line (socket-input-port (ref conn 'socket))))

(define (pop3-quit conn)
  (unwind-protect
    (send-command conn "QUIT")
    (if-let1 s (ref conn 'socket)
      (begin (socket-close s)
             (set! (ref conn 'socket) #f)))))

(define (check-response res)
  (if (string-prefix? "+OK" res)
    res
    (pop3-error res)))

(define (pop3-user conn username)
  (send-command conn "USER ~a" username))

(define (pop3-pass conn password)
  (send-command conn "PASS ~a" password))

(define (pop3-auth conn username password)
  (check-response (pop3-user conn username))
  (check-response (pop3-pass conn password)))

(define (pop3-stat conn))
(define (pop3-list conn))
(define (pop3-retr conn))
(define (pop3-dele conn))
(define (pop3-noop conn))
(define (pop3-rset conn))
(define (pop3-top conn))
(define (pop3-uidl conn))
(define (pop3-apop conn))

(provide "rfc/pop3")

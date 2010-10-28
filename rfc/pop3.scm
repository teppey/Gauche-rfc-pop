;;;
;;; rfc.pop3
;;;

(define-module rfc.pop3
  (use gauche.net)
  (use gauche.logger)
  (use srfi-13)
  (use rfc.md5)
  (use util.digest)
  (export-all)
  )
(select-module rfc.pop3)

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

(define (%logging message)
  (display message (current-error-port))
  (newline (current-error-port)))

(define-constant *default-pop3-port* 110)
(define-constant *open-timeout* 30)

(define-condition-type <pop3-error> <error> #f)
(define-condition-type <pop3-authentication-error> <pop3-error> #f)
(define-condition-type <pop3-bad-response-error> <pop3-error> #f)

(define (pop3-error condition message . args)
  (apply error condition message args))

(define-class <pop3-connection> ()
  ((host   :init-keyword :host   :init-value #f)
   (port   :init-keyword :port   :init-value *default-pop3-port*)
   (socket :init-keyword :socket :init-value #f)
   (apop   :init-keyword :apop   :init-value #f)
   (stamp  :init-value #f)))


(define (make-pop3-connection host . options)
  (let-keywords options ((port *default-pop3-port*)
                         (apop #f))
    (make <pop3-connection> :host host :port port :apop apop)))

(define (pop3-connect conn)
  (let ((host (ref conn 'host))
        (port (ref conn 'port)))
    (set! (ref conn 'socket) (make-client-socket 'inet host port))
    (let1 res (check-response (get-response conn))
      (and-let* ((m (#/<.*>/ res)))
        (set! (ref conn 'stamp) (m)))
      conn)))


;(define (call-with-pop3-connection proc host username password . options)
;  (let-keywords options ((port *default-pop3-port*)
;                         (apop #f))
;    (let1 conn (with-timeout
;                  (lambda ()
;                    (make <pop3-connection>
;                      :apop apop
;                      :socket (make-client-socket 'inet host port)))
;                  *open-timeout* #f)
;      (unless conn (pop3-error "timeout"))
;      (%logging #`"POP session started: ,|host|:,|port|")
;      (read-line (socket-input-port (ref conn 'socket))) ;read greeting
;      (unwind-protect (proc conn)
;        (pop3-quit conn)))))

(define (send-command conn fmt . args)
  (let1 out (socket-output-port (ref conn 'socket))
    (apply format out #`",|fmt|\r\n" args)
    (get-response conn)))

(define (get-response conn)
  (read-line (socket-input-port (ref conn 'socket))))

(define response-ok? (pa$ string-prefix? "+OK"))

(define (check-response res)
  (if (response-ok? res)
    res
    (pop3-error <pop3-bad-response-error> res)))

(define (check-response-auth res)
  (if (response-ok? res)
    res
    (pop3-error <pop3-authentication-error> res)))

(define (pop3-quit conn)
  (unwind-protect
    (send-command conn "QUIT")
    (if-let1 s (ref conn 'socket)
      (begin (socket-close s)
             (set! (ref conn 'socket) #f)))))

(define (pop3-auth conn username password)
  (check-response-auth (send-command conn "USER ~a" username))
  (check-response-auth (send-command conn "PASS ~a" password)))

(define (pop3-apop conn username password)
  (unless (ref conn 'stamp)
    (pop3-error <pop3-authentication-error> "not APOP server; cannot login"))
  raise
  (let1 digest (digest-hexify
                 (digest-string <md5> #`",(ref conn 'stamp),|password|"))
    (check-response-auth (send-command conn "APOP ~a ~a" username digest))))

;(define (pop3-stat conn))
;(define (pop3-list conn))
;(define (pop3-retr conn))
;(define (pop3-dele conn))
;(define (pop3-noop conn))
;(define (pop3-rset conn))
;(define (pop3-top conn))
;(define (pop3-uidl conn))
;(define (pop3-apop conn))

(provide "rfc/pop3")

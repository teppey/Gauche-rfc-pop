;;;
;;; rfc.pop3 - POP3 client library
;;;
;;;  Copyright (c) 2010  Teppei Hamada  <temada@gmail.com>
;;;
;;;  Redistribution and use in source and binary forms, with or without
;;;  modification, are permitted provided that the following conditions
;;;  are met:
;;;
;;;  1. Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.
;;;
;;;  2. Redistributions in binary form must reproduce the above copyright
;;;     notice, this list of conditions and the following disclaimer in the
;;;     documentation and/or other materials provided with the distribution.
;;;
;;;  3. Neither the name of the authors nor the names of its contributors
;;;     may be used to endorse or promote products derived from this
;;;     software without specific prior written permission.
;;;
;;;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;

;;; RFC 1939    Post Office Protocol - Version 3
;;; http://tools.ietf.org/html/rfc1939

(define-module rfc.pop3
  (use gauche.net)
  (use gauche.threads)
  (use srfi-1)
  (use srfi-13)
  (use rfc.md5)
  (use util.digest)
  (export <pop3-error>
          <pop3-timeout-error>
          <pop3-authentication-error>
          <pop3-bad-response-error>
          <pop3-connection>

          ; High level API
          call-with-pop3-connection

          ; Low level API
          pop3-connect
          pop3-quit
          pop3-login
          pop3-login-apop
          pop3-stat
          pop3-retr
          pop3-top
          pop3-dele
          pop3-noop
          pop3-rset
          pop3-list
          pop3-uidl
          )
  ;(export-all)
  )
(select-module rfc.pop3)

;; from lib/net/client.scm
(define (with-timeout timeout thunk . opt-handler)
  (let1 handler (get-optional opt-handler (lambda () #f))
    (if (and timeout (> timeout 0))
      (let1 thread (make-thread thunk)
        (thread-start! thread)
        (guard (exc [(join-timeout-exception? exc)
                     (thread-terminate! thread)
                     (handler)]
                    [else (raise exc)])
          (thread-join! thread timeout)))
      (thunk))))

(define-constant *default-pop3-port* 110)
(define-constant *default-connection-timeout* 30)

;;----------------------------------------------------------
;; Conditions
;;
(define-condition-type <pop3-error> <error> #f)
(define-condition-type <pop3-timeout-error> <pop3-error> #f)
(define-condition-type <pop3-authentication-error> <pop3-error> #f)
(define-condition-type <pop3-bad-response-error> <pop3-error> #f)

;;----------------------------------------------------------
;; POP3 connection context
;;
(define-class <pop3-connection> ()
  ((host   :init-keyword :host   :init-value #f :accessor host-of)
   (port   :init-keyword :port   :init-value *default-pop3-port*
           :accessor port-of)
   (socket :init-keyword :socket :init-value #f :accessor socket-of)
   (timeout :init-keyword :timeout :init-value *default-connection-timeout*)
   (stamp  :init-value #f)))

(define-method pop3-connect ((conn <pop3-connection>))
  (with-timeout (ref conn 'timeout)
    (lambda ()
      (set! (socket-of conn) (make-client-socket
                               'inet (host-of conn) (port-of conn)))
        (rlet1 res (check-response (get-response conn))
          (and-let* ((m (#/<.*>/ res)))
            (set! (ref conn 'stamp) (m)))))
    (lambda ()
      (error <pop3-timeout-error>
             "cannot connect server; connection timeout"))))

(define-method send-command ((conn <pop3-connection>) fmt . args)
  (let1 out (socket-output-port (socket-of conn))
    (apply format out #`",|fmt|\r\n" args)
    (get-response conn)))

(define-method get-response ((conn <pop3-connection>))
  (read-line (socket-input-port (socket-of conn))))

(define-values (check-response check-response-auth)
  (let-syntax
    ([checker (syntax-rules ()
                [(_ condition)
                 (lambda (res)
                   (or (and (string-prefix? "+OK" res) res)
                       (error condition res)))])])
    (values (checker <pop3-bad-response-error>)
            (checker <pop3-authentication-error>))))

(define-method pop3-quit ((conn <pop3-connection>))
  (unwind-protect
    (rlet1 res (check-response (send-command conn "QUIT"))
      (socket-shutdown (socket-of conn) SHUT_WR))
    (begin (socket-close (socket-of conn))
           (set! (socket-of conn) #f))))

(define-method pop3-login ((conn <pop3-connection>) username password)
  (check-response-auth (send-command conn "USER ~a" username))
  (check-response-auth (send-command conn "PASS ~a" password)))

(define-method pop3-login-apop ((conn <pop3-connection>) username password)
  (unless (ref conn 'stamp)
    (error <pop3-authentication-error> "not APOP server; cannot login"))
  (let1 digest (digest-hexify
                 (digest-string <md5> #`",(ref conn 'stamp),|password|"))
    (check-response-auth (send-command conn "APOP ~a ~a" username digest))))

(define-method pop3-stat ((conn <pop3-connection>))
  (let1 res (check-response (send-command conn "STAT"))
    (if-let1 m (#/^\+OK\s+(\d+)\s+(\d+)/ res)
      (values (string->number (m 1)) (string->number (m 2)))
      (error <pop3-bad-response-error> "wrong response format:" res))))

;; Return response a line includes CRLF
(define (read-response-line iport)
  (let loop ([c (read-char iport)]
             [r '()])
    (cond [(eof-object? c) c]
          [(and (eqv? c #\return)
                (eqv? (peek-char iport) #\newline))
           (list->string (reverse! (list* (read-char iport) c r)))]
          [else
            (loop (read-char iport)
                  (cons c r))])))

(define (read-response-lines iport oport flusher)
  (let loop ([line (read-response-line iport)]
             [size 0])
    (cond [(eof-object? line)
           (error <pop3-bad-response-error> "unexpected EOF")]
          [(#/^\.\r\n/ line)
           (flusher oport size)]
          [else
            (display (regexp-replace #/^\./ line "") oport)
            (loop (read-response-line iport)
                  (+ size (string-size line)))])))

(define (sink&flusher . args)
  (let-keywords args ([sink (open-output-string)]
                      [flusher (lambda (sink size) (get-output-string sink))])
    (values sink flusher)))

(define-method pop3-retr ((conn <pop3-connection>) msgnum)
  (rlet1 res (check-response (send-command conn "RETR ~d" msgnum))
    (read-response-lines
      (socket-input-port (socket-of conn))
      (current-output-port)
      (lambda _ ))))

(define-method pop3-top ((conn <pop3-connection>) msgnum nlines)
  (rlet1 res (check-response (send-command conn "TOP ~d ~d" msgnum nlines))
    (read-response-lines
      (socket-input-port (socket-of conn))
      (current-output-port)
      (lambda _ ))))

(define-method pop3-dele ((conn <pop3-connection>) msgnum)
  (check-response (send-command conn "DELE ~d" msgnum)))

(define-method pop3-noop ((conn <pop3-connection>))
  (check-response (send-command conn "NOOP")))

(define-method pop3-rset ((conn <pop3-connection>))
  (check-response (send-command conn "RSET")))

(define-method pop3-list ((conn <pop3-connection>) . args)
  (define (single msgnum)
    (let1 res (check-response (send-command conn "LIST ~d" msgnum))
      (if-let1 m (#/^\+OK\s+(\d+)\s+(\d+)$/ res)
        (values (string->number (m 1)) (string->number (m 2)))
        (error <pop3-bad-response-error> "bad response:" res))))
  (define (multi)
    (check-response (send-command conn "LIST"))
    (receive (sink flusher) (sink&flusher)
      (let* ([iport (socket-input-port (socket-of conn))]
             [lines (read-response-lines iport sink flusher)])
        (filter-map (lambda (line)
                      (and-let* ([(not (string-null? line))]
                                 [m (#/^(\d+)\s+(\d+)$/ line)])
                        (cons (string->number (m 1)) (string->number (m 2)))))
                    (string-split lines #/\r?\n/)))))
  (let1 msgnum (get-optional args #f)
    (if msgnum (single msgnum) (multi))))

(define-method pop3-uidl ((conn <pop3-connection>) . args)
  (define (single msgnum)
    (let1 res (check-response (send-command conn "UIDL ~d" msgnum))
      (if-let1 m (#/^\+OK\s+(\d)+\s+(.+)$/ res)
        (values (string->number (m 1)) (m 2))
        (error <pop3-bad-response-error> "bad response:" res))))
  (define (multi)
    (check-response (send-command conn "UIDL"))
    (receive (sink flusher) (sink&flusher)
      (let* ([iport (socket-input-port (socket-of conn))]
             [lines (read-response-lines iport sink flusher)])
        (filter-map (lambda (line)
                      (and-let* ([(not (string-null? line))]
                                 [m (#/^(\d+)\s+(.+)$/ line)])
                        (cons (string->number (m 1)) (m 2))))
                    (string-split lines #/\r?\n/)))))
  (let1 msgnum (get-optional args #f)
    (if msgnum (single msgnum) (multi))))


;;----------------------------------------------------------
;; High Level API
;;

;; Port number
;;  if `host' argument is "host:port", use host and port
;;  if not above form, use :port keyword argument
;;  if :port keyword argument not given, use *default-pop3-port*
(define (call-with-pop3-connection host username password proc . options)
  (define (ensure-host&port host port)
    (receive (host* port*) (string-scan host #\: 'both)
      (if (and host* port*)
        (values host* (string->number port*))
        (values host port))))
  (let-keywords options ([port *default-pop3-port*]
                         [apop #f])
    (receive (host port) (ensure-host&port host port)
      (let1 conn (make <pop3-connection> :host host :port port)
        (pop3-connect conn)
        (unwind-protect
          (begin (if apop
                   (pop3-login-apop conn username password)
                   (pop3-login conn username password))
                 (proc conn))
          (pop3-quit conn))))))


(provide "rfc/pop3")

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

;;; RFC 1939 - Post Office Protocol - Version 3
;;; http://tools.ietf.org/html/rfc1939

(define-module rfc.pop3
  (use gauche.net)
  (use gauche.logger)
  (use gauche.threads)
  (use srfi-13)
  (use rfc.md5)
  (use util.digest)
  (export-all)
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
(define-constant *connection-timeout* 30)

(define-condition-type <pop3-error> <error> #f)
(define-condition-type <pop3-authentication-error> <pop3-error> #f)
(define-condition-type <pop3-bad-response-error> <pop3-error> #f)

(define-class <pop3-connection> ()
  ((host   :init-keyword :host   :init-value #f)
   (port   :init-keyword :port   :init-value #f)
   (socket :init-keyword :socket :init-value #f)
   (stamp  :init-value #f)))

(define (pop3-connect host :optional (port *default-pop3-port*))
  (with-timeout *connection-timeout*
    (lambda ()
      (rlet1 conn (make <pop3-connection>
                    :host host
                    :port port
                    :socket (make-client-socket 'inet host port))
        (let1 res (check-response (get-response conn))
          (and-let* ((m (#/<.*>/ res)))
            (set! (ref conn 'stamp) (m))))))))

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
    (error <pop3-bad-response-error> res)))

(define (check-response-auth res)
  (if (response-ok? res)
    res
    (error <pop3-authentication-error> res)))

(define (pop3-quit conn)
  (unwind-protect
    (rlet1 res (check-response (send-command conn "QUIT"))
      (socket-shutdown (ref conn 'socket) SHUT_WR))
    (begin (socket-close (ref conn 'socket))
           (set! (ref conn 'socket) #f))))

(define (pop3-login conn username password)
  (check-response-auth (send-command conn "USER ~a" username))
  (check-response-auth (send-command conn "PASS ~a" password)))

(define (pop3-login-apop conn username password)
  (unless (ref conn 'stamp)
    (error <pop3-authentication-error> "not APOP server; cannot login"))
  (let1 digest (digest-hexify
                 (digest-string <md5> #`",(ref conn 'stamp),|password|"))
    (check-response-auth (send-command conn "APOP ~a ~a" username digest))))

(define (pop3-stat conn)
  (let1 res (check-response (send-command conn "STAT"))
    (if-let1 m (#/^\+OK\s+(\d+)\s+(\d+)/ res)
      (values (string->number (m 1)) (string->number (m 2)))
      (error <pop3-bad-response-error> "wrong response format:" res))))

(define (pop3-list conn :optional (msgnum #f))
  (define (single msgnum)
    (let1 res (check-response (send-command conn "LIST ~d" msgnum))
      (if-let1 m (#/^\+OK\s+(\d+)\s+(\d+)$/ res)
        (values (string->number (m 1)) (string->number (m 2)))
        (error <pop3-bad-response-error> "bad response:" res))))
  (define (all)
    (let1 res (check-response (send-command conn "LIST"))
      (let loop ((line (read-line (socket-input-port (ref conn 'socket))))
                 (r '()))
        (cond
          ((equal? line ".")
           (reverse! r))
          ((#/^(\d+)\s+(\d+)$/ line)
           => (lambda (m)
                (loop (read-line (socket-input-port (ref conn 'socket)))
                      (acons (string->number (m 1))
                             (string->number (m 2))
                             r))))
          (else
            (error <pop3-bad-response-error> "bad response:" res))))))
  (if msgnum
    (single msgnum)
    (all)))

;; Return response line includes CRLF
(define (read-message-chunk iport)
  (let loop ((c (read-char iport))
             (r '()))
    (cond ((eof-object? c) c)
          ((and (eqv? c #\return)
                (eqv? (peek-char iport) #\newline))
           (read-char iport) ;consume #\newline
           (list->string (reverse! (list* #\newline #\return r))))
          (else
            (loop (read-char iport)
                  (cons c r))))))

(define (read-message proc iport)
  (let loop ([line (read-message-chunk iport)]
             [size 0])
    (cond [(eof-object? line)
           (error <pop3-error> "unexpected EOF")]
          [(#/^\.\r\n/ line)
           (undefined)]
          [else
            (proc (regexp-replace #/^\./ line ""))
            (loop (read-message-chunk iport)
                  (+ size (string-size line)))])))

(define (pop3-retr conn msgnum :optional (proc #f))
  (let ([res (check-response (send-command conn "RETR ~d" msgnum))]
        [iport (socket-input-port (ref conn 'socket))]
        [sp #f])
    (if proc
      (read-message proc iport)
      (begin
        (set! sp (open-output-string))
        (read-message (lambda (chunk) (display chunk sp)) iport)
        (get-output-string sp)))))

(define (pop3-dele conn msgnum)
  (check-response (send-command conn "DELE ~d" msgnum)))

(define (pop3-noop conn)
  (check-response (send-command conn "NOOP")))

(define (pop3-rset conn)
  (check-response (send-command conn "RSET")))

(define (pop3-top conn msgnum n :optional (proc #f))
  (let ([res (check-response (send-command conn "TOP ~d ~d" msgnum n))]
        [iport (socket-input-port (ref conn 'socket))]
        [sp #f])
    (if proc
      (read-message proc iport)
      (begin
        (set! sp (open-output-string))
        (read-message (lambda (chunk) (display chunk sp)) iport)
        (get-output-string sp)))))

(define (pop3-uidl conn :optional (msgnum #f))
  (define (single msgnum)
    (let1 res (check-response (send-command conn "UIDL ~d" msgnum))
      (if-let1 m (#/^\+OK\s+(\d)+\s+(.+)$/ res)
        (values (string->number (m 1)) (m 2))
        (error <pop3-bad-response-error> "bad response:" res))))
  (define (all)
    (let1 res (check-response (send-command conn "UIDL"))
      (let loop ((line (read-line (socket-input-port (ref conn 'socket))))
                 (r '()))
        (cond
          ((equal? line ".")
           (reverse! r))
          ((#/^(\d+)\s+(.+)$/ line)
           => (lambda (m)
                (loop (read-line (socket-input-port (ref conn 'socket)))
                      (acons (string->number (m 1))
                             (m 2)
                             r))))
          (else
            (error <pop3-bad-response-error> "bad response:" res))))))
  (if msgnum
    (single msgnum)
    (all)))

(provide "rfc/pop3")

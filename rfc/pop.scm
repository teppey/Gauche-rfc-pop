;;;
;;; rfc.pop - POP3 client library
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

(define-module rfc.pop
  (use gauche.net)
  (use gauche.threads)
  (use gauche.vport)
  (use srfi-1)
  (use srfi-13)
  (export <pop3-error>
          <pop3-timeout-error>
          <pop3-authentication-error>
          <pop3-bad-response-error>
          <pop3-connection>
          pop3-connect
          pop3-quit
          pop3-user
          pop3-pass
          pop3-login
          pop3-apop
          pop3-stat
          pop3-retr
          pop3-top
          pop3-dele
          pop3-noop
          pop3-rset
          pop3-list
          pop3-uidl
          call-with-pop3-connection
          )
  )
(select-module rfc.pop)

(autoload rfc.md5 <md5>)
(autoload util.digest digest-hexify digest-string)

;; CRLF
(define-constant *line-terminator* (string #\x0d #\x0a))

;;----------------------------------------------------------------------
;; Conditions
;;

(define-condition-type <pop3-error> <error> #f)
(define-condition-type <pop3-timeout-error> <pop3-error> #f)
(define-condition-type <pop3-authentication-error> <pop3-error> #f)
(define-condition-type <pop3-bad-response-error> <pop3-error> #f)

;;----------------------------------------------------------------------
;; POP3 connection context
;;

(define-constant *default-pop3-port* 110)
(define-constant *default-connection-timeout* 30)

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
      (set! (socket-of conn)
        (make-client-socket 'inet (host-of conn) (port-of conn)))
        (rlet1 res (check-response (get-response conn))
          (and-let* ((m (#/<.*>/ res)))
            (set! (ref conn 'stamp) (m)))))
    (lambda ()
      (error <pop3-timeout-error>
             "cannot connect server; connection timeout"))))

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

;;----------------------------------------------------------------------
;; POP3 commands
;;

(define-method send-command ((conn <pop3-connection>) fmt . args)
  (let1 out (socket-output-port (socket-of conn))
    (with-signal-handlers ((SIGPIPE => #f))
      (lambda ()
        (apply format out #`",|fmt|,|*line-terminator*|" args)))))

(define-method send&recv ((conn <pop3-connection>) fmt . args)
  (with-timeout (ref conn 'timeout)
    (lambda ()
      (apply send-command conn fmt args)
      (get-response conn))
    (lambda ()
      (error <pop3-timeout-error> "connection timeout"))))

;; QUIT <CRLF>
(define-method pop3-quit ((conn <pop3-connection>))
  (unwind-protect
    (begin (send-command conn "QUIT")
           (socket-shutdown (socket-of conn) SHUT_WR)
           (check-response (get-response conn)))
    (begin (socket-close (socket-of conn))
           (set! (socket-of conn) #f))))

(define-syntax define-simple-command
  (syntax-rules (auth)
    [(_ auth name command args ...)
     (define-method name ((conn <pop3-connection>) args ...)
       (check-response-auth (send&recv conn command args ...)))]
    [(_ name command args ...)
     (define-method name ((conn <pop3-connection>) args ...)
       (check-response (send&recv conn command args ...)))]))

;; USER <SP> <username> <CRLF>
(define-simple-command auth pop3-user "USER ~a" username)

;; PASS <SP> <password> <CRLF>
(define-simple-command auth pop3-pass "PASS ~a" password)

;; DELE <SP> <number> <CRLF>
(define-simple-command pop3-dele "DELE ~d" msgnum)

;; NOOP <CRLF>
(define-simple-command pop3-noop "NOOP")

;; RSET <CRLF>
(define-simple-command pop3-rset "RSET")

(define-method pop3-login ((conn <pop3-connection>) username password)
  (pop3-user conn username)
  (pop3-pass conn password))

;; APOP <SP> <username> <SP> <digest> <CRLF>
(define-method pop3-apop ((conn <pop3-connection>) username password)
  (unless (ref conn 'stamp)
    (error <pop3-authentication-error> "not APOP server; cannot login"))
  (let1 digest (digest-hexify
                 (digest-string <md5> #`",(ref conn 'stamp),|password|"))
    (check-response-auth (send&recv conn "APOP ~a ~a" username digest))))

;; STAT <CRLF>
(define-method pop3-stat ((conn <pop3-connection>))
  (let1 res (check-response (send&recv conn "STAT"))
    (if-let1 m (#/^\+OK\s+(\d+)\s+(\d+)/ res)
      (values (string->number (m 1)) (string->number (m 2)))
      (error <pop3-bad-response-error> "wrong response format:" res))))

(define-syntax define-fetche-method
  (syntax-rules ()
    [(_ name command args ...)
     (define-method name ((conn <pop3-connection>) args ... . options)
       (let-keywords options ((sink (open-output-string))
                              (flusher get-output-string))
         (check-response (send&recv conn command args ...))
         (with-output-to-port sink
           (lambda () (%read-long-response conn)))
         (flusher sink)))]))

;; RETR <SP> <number> <CRLF>
(define-fetche-method pop3-retr "RETR ~d" msgnum)

;; TOP <SP> <number> <SP> <lines> <CRLF>
(define-fetche-method pop3-top "TOP ~d ~d" msgnum nlines)

;; LIST [<SP> <number>] <CRLF>
(define-method pop3-list ((conn <pop3-connection>) . args)
  (define (single msgnum)
    (let1 res (check-response (send&recv conn "LIST ~d" msgnum))
      (if-let1 m (#/^\+OK\s+\d+\s+(\d+)$/ res)
        (string->number (m 1))
        (error <pop3-bad-response-error> "bad response:" res))))
  (define (multi)
    (check-response (send&recv conn "LIST"))
    (let1 lines (%long-response-to-string conn)
      (filter-map (lambda (line)
                    (and-let* ([(not (string-null? line))]
                               [m (#/^(\d+)\s+(\d+)$/ line)])
                      (cons (string->number (m 1)) (string->number (m 2)))))
                  (string-split lines *line-terminator*))))
  (let1 msgnum (get-optional args #f)
    (if msgnum (single msgnum) (multi))))

;; UIDL [<SP> <number>] <CRLF>
(define-method pop3-uidl ((conn <pop3-connection>) . args)
  (define (single msgnum)
    (let1 res (check-response (send&recv conn "UIDL ~d" msgnum))
      (if-let1 m (#/^\+OK\s+\d+\s+(.+)$/ res)
        (m 1)
        (error <pop3-bad-response-error> "bad response:" res))))
  (define (multi)
    (check-response (send&recv conn "UIDL"))
    (let1 lines (%long-response-to-string conn)
      (filter-map (lambda (line)
                    (and-let* ([(not (string-null? line))]
                               [m (#/^(\d+)\s+(.+)$/ line)])
                      (cons (string->number (m 1)) (m 2))))
                  (string-split lines *line-terminator*))))
  (let1 msgnum (get-optional args #f)
    (if msgnum (single msgnum) (multi))))

;;----------------------------------------------------------------------
;; Convenient procedure
;;

(define (call-with-pop3-connection host username password proc . options)
  (define (ensure-host&port host)
    (receive (h p) (string-scan host #\: 'both)
      (if (and h p)
        (values h (string->number p))
        (values host *default-pop3-port*))))
  (let-keywords options ([apop #f])
    (receive (host port) (ensure-host&port host)
      (let1 conn (make <pop3-connection> :host host :port port)
        (pop3-connect conn)
        (unwind-protect
          (begin (if apop
                   (pop3-apop conn username password)
                   (pop3-login conn username password))
                 (proc conn))
          (pop3-quit conn))))))

;;----------------------------------------------------------------------
;; Utility functions
;;

;; from trunk/lib/net/client.scm
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

(define-method %read-long-response ((conn <pop3-connection>))
  (let* ((in (make <buffered-input-port>
               :fill (pa$ socket-recv! (socket-of conn))))
         (reader (lambda ()
                   (let1 line (read-line in #t)
                     (cond
                       [(eof-object? line)
                        (error <pop3-bad-response-error> "unexpected EOF")]
                       [(string-prefix? ".." line)
                        (string-drop line 1)]
                       [(equal? line ".") (eof-object)]
                       [else line])))))
    (port-for-each (lambda (line)
                     (display line)
                     (display *line-terminator*))
                   reader)))

(define-method %long-response-to-string ((conn <pop3-connection>))
  (with-output-to-string (lambda () (%read-long-response conn))))

(provide "rfc/pop")

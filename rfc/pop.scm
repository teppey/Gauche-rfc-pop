;;;
;;; rfc.pop - POP3 client library
;;;
;;;  Copyright (c) 2011  Teppei Hamada  <temada@gmail.com>
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
  (use gauche.uvector :only (read-block!))
  (use gauche.vport :only (<buffered-input-port>))
  (use srfi-1 :only (filter-map))
  (use srfi-13)
  (export <pop3-error>
          <pop3-connection>
          make-pop3-connection
          pop3-user
          pop3-pass
          pop3-stat
          pop3-list
          pop3-dele
          pop3-retr
          pop3-noop
          pop3-rset
          pop3-quit
          pop3-apop
          pop3-top
          pop3-uidl
          call-with-pop3-connection
          ))
(select-module rfc.pop)

(autoload rfc.md5 <md5>)
(autoload util.digest digest-hexify digest-string)

;; CRLF
(define-constant *line-terminator* (string #\cr #\lf))

;; This condition is thrown when error response is received.
(define-condition-type <pop3-error> <error> #f)

;;----------------------------------------------------------------------
;; POP3 connection context
;;
(define-constant *default-pop3-port* 110)

(define-class <pop3-connection> ()
  ((socket :init-value #f)
   (greeting :init-value #f)))

(define (make-pop3-connection host :optional (port *default-pop3-port*))
  (rlet1 conn (make <pop3-connection>)
    (set! (~ conn'socket) (make-client-socket 'inet host port))
    (set! (~ conn'greeting) (check-response (get-response conn)))))


;;----------------------------------------------------------------------
;; Utility functions and macros
;;
(define (get-response conn)
  (read-line (socket-input-port (~ conn'socket))))

(define (check-response res)
  (or (and (string? res) (string-prefix? "+OK" res) res)
      (error <pop3-error> res)))

(define (send-command conn fmt . args)
  (let1 out (socket-output-port (~ conn'socket))
    (with-signal-handlers ((SIGPIPE => #f))
      (lambda ()
        (apply format out #`",|fmt|,|*line-terminator*|" args)))))

(define (send&recv conn fmt . args)
  (apply send-command conn fmt args)
  (get-response conn))

(define-syntax define-simple-command
  (syntax-rules ()
    [(_ name command args ...)
     (define-method name ((conn <pop3-connection>) args ...)
       (check-response (send&recv conn command args ...)))]))

(define-syntax define-fetch-method
  (syntax-rules ()
    [(_ name command args ...)
     (define-method name ((conn <pop3-connection>) args ... . options)
       (let-keywords options ((sink (open-output-string))
                              (flusher get-output-string))
         (check-response (send&recv conn command args ...))
         (with-ports (socket-input-port (~ conn'socket)) sink #f %read-long-response)
         (flusher sink)))]))

(define (%read-long-response)
  (let* ((in (make <buffered-input-port> :fill read-block!))
         (reader (lambda ()
                   (let1 line (read-line in #t)
                     (cond
                       [(eof-object? line)
                        (error "unexpected EOF")]
                       [(string-prefix? ".." line)
                        (string-drop line 1)]
                       [(equal? line ".") (eof-object)]
                       [else line])))))
    (port-for-each (lambda (line)
                     (display line)
                     (display *line-terminator*))
                   reader)))

(define (%long-response-to-string conn)
  (with-output-to-string
    (lambda ()
      (with-input-from-port (socket-input-port (~ conn'socket))
        %read-long-response))))


;;----------------------------------------------------------------------
;; POP3 commands
;;
;;
;;  Minimal POP3 commands:
;;    USER name
;;    PASS string
;;    STAT
;;    LIST [msg]
;;    RETR [msg]
;;    DELE [msg]
;;    NOOP
;;    RSET
;;    QUIT
;;
;;  Optional POP3 commands:
;;    APOP name digest
;;    TOP msg n
;;    UIDL [msg]
;;

;; USER <SP> <username> <CRLF>
(define-simple-command pop3-user "USER ~a" username)

;; PASS <SP> <password> <CRLF>
(define-simple-command pop3-pass "PASS ~a" password)

;; STAT <CRLF>
(define-method pop3-stat ((conn <pop3-connection>))
  (let1 res (check-response (send&recv conn "STAT"))
    (if-let1 m (#/^\+OK\s+(\d+)\s+(\d+)/ res)
      (values (string->number (m 1)) (string->number (m 2)))
      (error <pop3-error> "wrong response format:" res))))

;; LIST [<SP> <number>] <CRLF>
(define-method pop3-list ((conn <pop3-connection>) . args)
  (define (single msgnum)
    (let1 res (check-response (send&recv conn "LIST ~d" msgnum))
      (if-let1 m (#/^\+OK\s+\d+\s+(\d+)$/ res)
        (string->number (m 1))
        (error <pop3-error> "wrong response format:" res))))
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

;; RETR <SP> <number> <CRLF>
(define-fetch-method pop3-retr "RETR ~d" msgnum)

;; DELE <SP> <number> <CRLF>
(define-simple-command pop3-dele "DELE ~d" msgnum)

;; NOOP <CRLF>
(define-simple-command pop3-noop "NOOP")

;; RSET <CRLF>
(define-simple-command pop3-rset "RSET")

;; QUIT <CRLF>
(define-method pop3-quit ((conn <pop3-connection>))
  (unwind-protect
    (check-response (send&recv conn "QUIT"))
    (begin (socket-shutdown (~ conn'socket) SHUT_RDWR)
           (socket-close (~ conn'socket))
           (set! (~ conn'socket) #f))))

;; APOP <SP> <username> <SP> <digest> <CRLF>
(define-method pop3-apop ((conn <pop3-connection>) username password)
  (or (and-let* ([s (~ conn'greeting)]
                 [m (#/<.*>/ s)])
        (let1 digest (string-downcase
                       (digest-hexify
                         (digest-string <md5> #`",(m),|password|")))
          (check-response (send&recv conn "APOP ~a ~a" username digest))))
      (error <pop3-error> "not APOP server; cannot login")))

;; TOP <SP> <number> <SP> <lines> <CRLF>
(define-fetch-method pop3-top "TOP ~d ~d" msgnum nlines)

;; UIDL [<SP> <number>] <CRLF>
(define-method pop3-uidl ((conn <pop3-connection>) . args)
  (define (single msgnum)
    (let1 res (check-response (send&recv conn "UIDL ~d" msgnum))
      (if-let1 m (#/^\+OK\s+\d+\s+(.+)$/ res)
        (m 1)
        (error <pop3-error> "wrong response format:" res))))
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
(define (call-with-pop3-connection host proc
                                   :key (username #f) (password #f) (apop #f))
  (define (ensure-host&port host)
    (receive (h p) (string-scan host #\: 'both)
      (if (and h p)
        (values h (string->number p))
        (values host *default-pop3-port*))))
  (receive (host port) (ensure-host&port host)
    (let1 conn (make-pop3-connection host port)
      (unwind-protect
        (begin (cond [(and username password)
                      (if apop
                        (pop3-apop conn username password)
                        (begin (pop3-user conn username)
                               (pop3-pass conn password)))]
                     [username (pop3-user conn username)])
               (proc conn))
        (pop3-quit conn)))))


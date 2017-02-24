# Rust SRS

This projects aims at implementing

* a SRS library in pure Rust
    - [x] Address tokenizer & parser
    - [x] Receive rewriting
    - [ ] Forward rewriting
    - [ ] Rust Docs
* A daemon exposing above functionality in a Postfix-compatible way
    - [ ] Postfix-compatible TCP / unix socket lookup table server
    - [ ] Configuration format & parsing
    - [ ] Key Rollover
    - [ ] Logging & Stats
    - [ ] Rule-based rewriting policy

This project was started by a novice Rust programmer and is still under development.

# Sender Rewriting Scheme

The *Sender Rewriting Scheme* is a technique to rewrite the *envelope sender* address
(SMTP `MAIL FROM`) in order to not break the *Sender Policy Framework* on mail relays
that are not whitelisted in the original sender's SPF record.

A part of the return path is encoded in the local part of the rewritten envelope
sender address:

SMTP servers implementing SRS support perform the rewriting on forwards and reverse
it on reception of a bounce.

A cryptographic hash / HMAC is employed to protect a reversing SMTP server from
becoming an open relay for forged requests.

## Example
```
A to B: MAIL FROM user@a
B to C: MAIL FROM SRS0=HHH1=TT=a=user@b
C to D: MAIL FROM SRS1=HHH2=b=HHH1=TT=a=user@c
Subsequent forwardes just change the domain-part of the address.
D to E: MAIL FROM SRS1=HHH2=b=HHH1=TT=a=user@d

E bounces => SRS1=HHH2=b=HHH1=TT=a=user@d is rewritten to SRS0=HHH1=TT=a=user@b
E TO B: MAIL FROM SRS0=HHH1=TT=a=user@b
B rewrites SRS0=HHH1=TT=a=user@b to user@a
B TO A: MAIL FROM user@a

=> the return path is exactly 2 hops long
=> intermediate hosts are short-circuited
 
```

## More information:

* https://en.wikipedia.org/wiki/Sender_Rewriting_Scheme
* http://www.libsrs2.org/srs/srs.pdf
* http://www.openspf.org/SRS

# Related Work

* https://github.com/roehling/postsrsd
* http://www.libsrs2.org/


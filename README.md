# libaes_siv

This is an [RFC5297](https://tools.ietf.org/html/rfc5297)-compliant C
implementation of AES-SIV, written by Daniel Franke on behalf of
[Akamai Technologies](https://www.akamai.com) and published under the
[Apache License (v2.0)](https://www.apache.org/licenses/LICENSE-2.0).
It uses OpenSSL for the underlying AES and CMAC primitives and follows
a similar interface style.

This code should presently be considered alpha-quality. It passes the
test vectors, but has not been heavily tested and has not received any
third-party code review. It is intended to yield high performance and
to avoid timing side-channels, but I have neither benchmarked it, nor
thoroughly audited the generated assembly code nor run it through
[ctgrind](https://github.com/agl/ctgrind). Until I regard this code as
suitable for release, any discovered vulnerabilities will not be
assigned CVEs or announced anywhere more prominent than the commit
log.

Build dependencies:

* Any ANSI C compiler (GCC or Clang recommended)
* POSIX make
* OpenSSL >=1.0.2 (libcrypto only)
* Asciidoc (for building man pages)

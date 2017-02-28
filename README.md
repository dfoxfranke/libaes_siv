# libaes_siv

This is an [RFC5297](https://tools.ietf.org/html/rfc5297)-compliant C
implementation of AES-SIV, written by Daniel Franke on behalf of
[Akamai Technologies](https://www.akamai.com) and published under the
[Apache License (v2.0)](https://www.apache.org/licenses/LICENSE-2.0).
It uses OpenSSL for the underlying
[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) and
[CMAC](https://en.wikipedia.org/wiki/One-key_MAC) implementations and
follows a similar interface style.

## Overview of SIV mode

Synthetic Initialization Vector (SIV) mode is a [block cipher mode of
operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
for [authenticated encryption with associated
data](https://en.wikipedia.org/wiki/Authenticated_encryption) designed
to be maximally resistant to accidental
[nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) reuse.  If
two messages are accidentally encrypted using the same nonce and the
same associated data, the attacker learns nothing except whether or
not the plaintexts of the two messages are identical to each other.
SIV mode also permits the nonce to be intentionally omitted, resulting
in a [deterministic encryption
scheme](https://en.wikipedia.org/wiki/Deterministic_encryption).

Here are a couple common situations where AES-SIV may be an
appropriate choice of AEAD scheme:

1. You can't count on the system doing the encrypting to reliably
   generate a unique nonce for every message. For example, the system
   may be an embedded device with no good entropy source, or may be a
   VM subject to be snapshotted and restored.

2. You want your encryption to be deterministic so that an
   intermediating party such as a caching proxy, provided only with
   ciphertext, can perform deduplication.

The drawback to SIV mode is that it requires two passes over its
input. This makes it potentially clumsy for use with large messages
since the entire message must be held in memory at one time. SIV mode
is also a bit slower than most widely-used block cipher modes (but
can still be quite fast — see performance numbers below).

Be aware that with *any* encryption scheme, including SIV, repeating
or omitting a nonce still be [fatal to security](https://xkcd.com/257)
if your plaintexts have low entropy, e.g., if each message consists
only of a single bit.

KEYS FOR SIV MODE ARE TWICE THE LENGTH OF THE KEYS FOR THE UNDERLYING
BLOCK CIPHER. FOR EXAMPLE, KEYS FOR AES-128-SIV are 256 bits long,
and keys for AES-256-SIV are 512 bits long.

## Build instructions

Build dependencies:

* Any ISO C89 compiler (GCC or Clang recommended). No C99 language
  features are required, however `<stdint.h>` must be available and
  must define `uint64_t`. `char` must be 8 bits and arithmetic must be
  two's complement.
* [CMake](https://cmake.org) >= 3.0
* [OpenSSL](https://openssl.org) >=1.0.1 (libcrypto only). A more
  recent version is of course recommended since 1.0.1 is out of
  security support.
* [Asciidoc](http://asciidoc.org) (only required for building man pages)

Running benchmarks requires a POSIX.1-2001 compliant OS, including
the `clock_gettime` system call.

To build and install on POSIX-like platforms:
```
    cmake . &&
    make &&
    make test &&
    sudo make install
```

## Usage

See the manual pages for API documentation, and the test vectors
in `tests.c` for simple usage examples.

## Performance

On the author's Intel Core i7-6560U laptop, libaes_siv can process
approximately 796 MiB of plaintext or ciphertext or 963 MiB of
associated data per second using 256-bit keys
(i.e., AES-128). Encrypting a zero-byte message takes approximately
990ns. To obtain numbers for your own system, run `make bench &&
./bench`.

## Software assurance

libaes_siv's test suite includes all test vectors from RFC 5297 and
achieves 100% code coverage according to
[gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html). It produces
clean output from [Valgrind](https://valgrind.org) and from Clang's
[undefined behavior
sanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html),
and is verified using [ctgrind](https://github.com/agl/ctgrind) to run
in constant time.

Nonetheless, libaes_siv should at present be considered beta-quality
code. It has not yet been tested on platforms other than x86-64 Linux
or benefited from any significant amount of user feedback, and
the codebase is in need of additional review by cryptographers and
expert C programmers.

## Bugs and pull requests

Use the GitHub issue tracker. For reporting sensitive security issues,
use the [author's PGP key](https://www.dfranke.us/contact.html).

## A note on version numbers

libaes_siv version numbers are of the form `<major>.<minor>.<patch>`
and follow a semantic versioning scheme. The major version number
will be incremented with any backward-incompatible ABI change. The
minor version number will be incremented if new functionality is
added without impacting ABI backward-compatibility. The patch
version number will be incremented for releases that make no
externally-visible changes.

As a result of this scheme, on ELF platforms, the .so version will
be the same as the release version.

Version numbers indicate nothing about code quality or maturity.  No
code known or suspected to be less suitable for production use than
previous releases will ever be tagged with a version number.

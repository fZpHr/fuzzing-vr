# Fuzzing GNU libtasn1

This directory documents a progressive libFuzzer study of GNU libtasn1.

Case1 is an educational first harness: I learned how to instrument the library,
choose a parsing API, feed it raw bytes, and run and measure libFuzzer. From
case2 onward, the objective becomes CVE rediscovery: I try to reproduce
[CVE-2018-6003](https://nvd.nist.gov/vuln/detail/CVE-2018-6003), an
uncontrolled-recursion vulnerability in the BER decoder of libtasn1 4.12.

## What is being tested?

The project has two related targets:

| Case | Version | Target | Result |
| --- | --- | --- | --- |
| [case1-v4.19](./case1-v4.19) | 4.19.0 | `asn1_get_length_der` | First harness and learning of the fuzzing workflow; coverage plateaus without a crash. |
| [case2-v4.12](./case2-v4.12) | 4.12 | `asn1_decode_simple_ber` | First CVE reproduction attempt; raw fuzzing does not reach the recursive path. |
| [case3-v4.12](./case3-v4.12) | 4.12 | `asn1_decode_simple_ber` | Unit tests discover the strict filters; protobuf generation then exposes the mutator's recursion limit. |
| [case4-v4.12](./case4-v4.12) | 4.12 | `asn1_decode_simple_ber` | Custom mutator emits the exact filtered pattern and sufficient depth, reproducing stack exhaustion. |

The vulnerable input is a chain of indefinite-length constructed OCTET
STRINGs:

```text
24 80 24 80 24 80 ... 04 00
```

`0x24` is a constructed OCTET STRING, `0x80` selects indefinite length, and
`0x04 0x00` is the primitive empty OCTET STRING leaf. In the vulnerable
decoder, each nested `0x24 0x80` causes another internal call to the BER
decoder. There is no application-level recursion bound in 4.12, so sufficiently
deep input exhausts the thread stack and ends the process with `SIGSEGV`.

This is a denial-of-service condition. It does not, by itself, demonstrate
arbitrary code execution, privilege escalation, or data disclosure.

## Walkthrough

### 1. Prepare an isolated build

The case READMEs assume that the corresponding libtasn1 source tree has been
unpacked in the case working directory. Build the vulnerable 4.12 source
with AddressSanitizer and without linking the fuzzer runtime into the library:

```bash
CC=clang \
CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" \
./configure --disable-shared --disable-doc
make -j"$(nproc)"
```

For case1, use libtasn1 4.19.0 instead. Case1 is a non-vulnerable baseline
and targets a different, simpler parsing function.

### 2. Start with a direct harness (case1)

The first harness feeds arbitrary bytes to `asn1_get_length_der` and checks
that output parameters are handled correctly. The library allocation returned
by the API is released by the harness.

From the case1 build directory:

```bash
clang -g -O1 -fsanitize=address,fuzzer \
  -I libtasn1-4.19.0/lib/includes \
  resources/test_fuzz1.c \
  libtasn1-4.19.0/lib/.libs/libtasn1.a \
  -o fuzz_get_length_der

./fuzz_get_length_der resources/corpus/ -max_len=512
```

The expected outcome is a coverage plateau and no crash. This establishes the
basic harness pattern before moving to the more complex BER decoder.

### 3. Try raw mutation (case2)

Case2 calls `asn1_decode_simple_ber` directly with a raw byte buffer:

```bash
clang -g -O1 -fsanitize=address,fuzzer \
  -I lib/includes \
  resources/test_fuzz_ber.c \
  lib/.libs/libtasn1.a \
  -o fuzz_ber

./fuzz_ber resources/corpus_ber/ -max_len=512
```

This is a useful negative result. Random mutation is unlikely to preserve
`0x24 0x80` at every nesting level, and malformed inputs are rejected by
earlier validation. A correct library version and a correct API call are not
enough when the trigger has a strict byte-level grammar.

### 4. Add structure-aware generation (case3)

Case3 represents BER as a recursive protobuf tree and serializes that tree
into BER before calling the decoder. Generate the protobuf sources and link
the libprotobuf-mutator runtime:

```bash
protoc --cpp_out=. resources/ber.proto
clang++ -g -O1 -fsanitize=address,fuzzer \
  -I lib/includes \
  resources/test_fuzz_ber.cpp ber.pb.cc \
  lib/.libs/libtasn1.a \
  -lprotobuf-mutator-libfuzzer -lprotobuf-mutator -lprotobuf \
  -o fuzz_ber

./fuzz_ber resources/corpus_ber/ -max_len=8192
```

The tree is recursive, but the decoder still requires the exact tag byte
`0x24` for every constructed node. Allowing the protobuf mutator to choose
arbitrary tag values means most inputs fail before entering the recursive
decoder. Pinning the emitted tags fixes that gate, but libprotobuf-mutator's
own recursion limit still prevents the thousands of levels needed to exhaust
an 8 MB Linux stack.

### 5. Use the custom mutator (case4)

Case4 keeps libFuzzer's size mutation but rewrites the resulting buffer into
the exact trigger grammar. Build and run it with a much larger maximum input
length:

```bash
clang -g -O1 -fsanitize=address,fuzzer \
  -I .local/src/libtasn1-4.12/lib/includes \
  resources/test_fuzz_ber.c \
  .local/src/libtasn1-4.12/lib/.libs/libtasn1.a \
  -o fuzz_ber

./fuzz_ber resources/corpus_ber/ -max_len=100000
```

The mutator calls `LLVMFuzzerMutate()` to vary the size, then writes repeated
`24 80` pairs and terminates with `04 00`. The approximate nesting depth is
half the input size. With the default 8 MB stack, `-max_len=8192` often stays
below the failure threshold, while a larger limit allows the input to reach
the stack exhaustion condition.

An expected failure looks like:

```text
segmentation fault (core dumped)
```

The exact depth and runtime depend on the compiler, sanitizer, operating
system, stack limit, and build flags. The useful diagnostic is the recursive
backtrace, not a fixed number of frames:

```text
Thread 1 "fuzz_ber" received signal SIGSEGV, Segmentation fault.
... in _asn1_decode_simple_ber ...
... in asn1_decode_simple_ber ...
... repeated recursive frames ...
```

For an authorized local investigation, inspect the saved libFuzzer crash
input with a debugger:

```bash
gdb --args ./fuzz_ber resources/corpus_ber/crash-*
```

Do not use the reproducer against third-party devices or services.

## Why case4 reaches the bug

The important distinction is between the harness call and the library's
internal control flow:

```text
LLVMFuzzerTestOneInput
  -> asn1_decode_simple_ber                 (one harness call)
     -> _asn1_decode_simple_ber             (library)
        -> asn1_decode_simple_ber            (nested BER child)
           -> _asn1_decode_simple_ber
              -> ...                        (one level per 24 80 pair)
```

The harness does not recursively call the decoder. The encoded input makes
the decoder recurse. The custom mutator is effective because it preserves all
of the bytes needed to pass the decoder's early checks while allowing the
input to become deep enough to exhaust the stack.

## Fixed-version comparison

The issue was fixed in libtasn1 4.13 by bounding the decoder's nesting depth.
The defensive behavior is an error return once the configured depth is
exceeded, rather than continued recursion until the process stack is
exhausted. Repeating the case4 experiment with a patched version is a useful
regression check: it should reject the deeply nested input without producing
the 4.12 stack-overflow crash.


## Purpose of this CVE

CVE-2018-6003 demonstrates a denial-of-service condition: a sufficiently deep,
well-formed BER structure can exhaust the stack of a process using vulnerable
libtasn1 4.12 and terminate it with `SIGSEGV`. Depending on the application, it
can crash a client, stop a server process or worker, interrupt a service, or
trigger repeated restarts. This CVE alone does not demonstrate arbitrary code
execution or privilege escalation.

Possible targets include:

- **Linux server:** a service linked to GnuTLS/libtasn1 processing attacker-controlled certificates or ASN.1/BER data.
- **Android or Linux phone:** an application or system component bundling GnuTLS/libtasn1 and parsing attacker-controlled certificates.
- **Router, firewall or IoT gateway:** firmware embedding GnuTLS/libtasn1 in a service that accepts controlled ASN.1/BER input.

libtasn1 was present in parts of the Linux, GnuTLS, certificate-management,
VPN and embedded-device ecosystems around 2017-2018. These are examples of
possible exposure, not confirmed vulnerable products: the vendor must ship the
affected 4.12 library and expose this decoder to attacker-controlled input.
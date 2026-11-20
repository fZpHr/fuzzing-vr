# Case 1 — Learning libFuzzer with GNU libtasn1 4.19.0

## Objective
- GNU libtasn1 4.19.0, function `asn1_get_length_der` (parses the DER length field).
- This was my introduction to the fuzzing workflow: writing a harness, instrumenting the
  target, providing a corpus, running libFuzzer, reading coverage, and interpreting a
  crash-free result.
- Why this function: it takes raw bytes plus a length directly and requires no schema setup,
  so it is a simple first target. It is not yet an attempt to reproduce a known CVE.

## Harness
- See `resources/test_fuzz1.c` for the source.
- `size > INT_MAX` → size cap, so the cast to `int` can't truncate.
- `len` is an output parameter → a local `int` is declared and passed by address (`&len`).

## Build

clang -g -O1 -fsanitize=address,fuzzer -I libtasn1-4.19.0/lib/includes
resources/test_fuzz1.c libtasn1-4.19.0/lib/.libs/libtasn1.a -o fuzz_get_length_der
./fuzz_get_length_der resources/corpus/ -max_len=512


## Result
- 229M executions in ~300s (~750k exec/s), no crash.
- Coverage plateaued at 15 edges almost immediately → the function was fully explored.
- Expected: this function is continuously fuzzed by OSS-Fuzz. "No crash" is a valid result.

## What I learned
- The real work of fuzzing is writing the harness (choosing the surface and feeding input),
  not merely starting libFuzzer.
- Compared my harness to the project's official one (`fuzz/asn1_get_length_der_fuzzer.c`):
  nearly identical; the only real difference is their 512-byte size cap to focus mutations.
- Before attempting a CVE, I learned the complete loop: instrument the library, pass raw
  bytes to a real parser function, handle output parameters correctly, free library-owned
  memory, collect coverage, and distinguish a crash-free run from a harness problem.
- From case2 onward, the objective changes: I try to rediscover CVE-2018-6003 in the older
  and vulnerable libtasn1 4.12.
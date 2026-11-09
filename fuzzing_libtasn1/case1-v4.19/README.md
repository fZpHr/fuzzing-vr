markdown
# Fuzzing libtasn1 with a custom libFuzzer harness

## Target
- GNU libtasn1 4.19.0, function `asn1_get_length_der` (parses the DER length field).
- Why this function: takes raw bytes + a length directly, no schema setup → ideal first
  harness. Parses untrusted input (the attack surface).

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
- The real work of fuzzing is writing the harness (choosing the surface, feeding input),
  not running the tool.
- Compared my harness to the project's official one (`fuzz/asn1_get_length_der_fuzzer.c`):
  nearly identical; the only real difference is their 512-byte size cap to focus mutations.
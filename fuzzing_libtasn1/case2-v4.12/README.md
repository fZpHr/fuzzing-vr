# Case 2 — First attempt to reproduce CVE-2018-6003

## Target
- GNU libtasn1 4.12 (vulnerable version; the bug was fixed in 4.13), function
  `asn1_decode_simple_ber`.
- Why this function: it takes raw bytes + a length directly, with no schema setup, and it
  parses untrusted BER input — a clean attack surface, ideal to write a harness against.
- Goal: bug rediscovery — after learning the harness workflow in case1, point my own
  harness at a known, patched CVE on the vulnerable 4.12 version. At this stage I assume
  that a raw input mutator can reach the recursive decoder path.
- Result: the crash does not reproduce because the target has strict early validation.
  The exact trigger was not understood yet; case3 investigates why raw and generated
  structures are filtered out and case4 builds the final targeted harness.

## Harness
- See `resources/` for the harness source.
- `size > INT_MAX` → size cap, avoids truncating the cast to `unsigned int`.
- `str` / `str_len` are outputs → passed by address (`&`). `str` is heap-allocated by the
  library on success, so it is freed (otherwise LeakSanitizer reports a leak on each input).

## Build
vulnerable library 4.12, instrumented + ASAN

CC=clang CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" ./configure --disable-shared --disable-doc
make

link the harness with the fuzzer engine

clang -g -O1 -fsanitize=address,fuzzer -I lib/includes test_fuzz_ber.c lib/.libs/libtasn1.a -o fuzz_ber
./fuzz_ber corpus_ber/ -max_len=512


## Result
- Harness + vulnerable 4.12 build both confirmed correct (`#define VERSION "4.12"`).
- The crash did **not** reproduce: neither a short fuzzing run nor a hand-crafted
  nested indefinite-length BER input triggered the overflow — the naive input is rejected
  by earlier validation before reaching the recursive path. Deterministic reproduction
  needs a specific nested-BER structure I did not pin down.
- Documented root cause from public sources: CVE-2018-6003 is an uncontrolled recursion
  (stack exhaustion) in the BER decoder on indefinite-length encoding — CWE-674, impact
  denial of service, fixed in 4.13 by adding a recursion depth limit.

## What I learned
- Wrote a harness from scratch: picked the attack surface in an unfamiliar codebase, told
  input from output parameters (passing `&` for outputs), and freed the library's
  allocation to avoid false LeakSanitizer reports — the harness must never add bugs of its own.
- Reproducing a known CVE is not plug-and-play: correct version and correct harness are not
  enough, the exact trigger shape matters. "Bug rediscovery" is genuinely finicky — a useful
  reality check on how real vulnerability research actually goes.
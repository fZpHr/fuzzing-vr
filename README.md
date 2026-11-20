# fuzzing

Learning vulnerability research through fuzzing: Antonio Morales'
[Fuzzing101](https://github.com/antonio-morales/Fuzzing101) course (AFL++), then my own
harnesses written from scratch (libFuzzer).

## Guided exercise (AFL++)
- [Xpdf 3.02 / pdftotext — CVE-2019-13288](./fuzzing_PDFtoTEXT) — uncontrolled recursion /
  stack exhaustion. Crash found, triaged with gdb, minimized with afl-tmin.

## Custom harnesses (libFuzzer)
I chose attacker-relevant parsing functions, wrote the harnesses myself, and iterated on
how much structure the mutator needed to reach the target code.

- [libtasn1 — `asn1_get_length_der`](./fuzzing_libtasn1/case1-v4.19) — first harness and
  introduction to libFuzzer. 229M executions under ASAN, full coverage, no crash.
- [CVE-2018-6003 progression in libtasn1 4.12](./fuzzing_libtasn1) — four attempts to
  rediscover uncontrolled recursion in `asn1_decode_simple_ber`:
  - [Case 1](./fuzzing_libtasn1/case1-v4.19): learning the fuzzing workflow.
  - [Case 2](./fuzzing_libtasn1/case2-v4.12): raw fuzzing, no crash; the strict BER filters
    remain to be identified.
  - [Case 3](./fuzzing_libtasn1/case3-v4.12): unit tests find the `24 80` / `04 00`
    trigger, then libprotobuf-mutator reveals a recursion limit of 100.
  - [Case 4](./fuzzing_libtasn1/case4-v4.12): custom mutator emits the exact BER pattern and
    sufficient nesting depth, reproducing the stack exhaustion crash.
# fuzzing101

Learning vulnerability research through fuzzing: Antonio Morales'
[Fuzzing101](https://github.com/antonio-morales/Fuzzing101) course (AFL++), then my own
harnesses written from scratch (libFuzzer).

## Guided exercise (AFL++)
- [Xpdf 3.02 / pdftotext — CVE-2019-13288](./fuzzing_PDFtoTEXT) — uncontrolled recursion /
  stack exhaustion. Crash found, triaged with gdb, minimized with afl-tmin.

## Custom harnesses (libFuzzer)
Here I read the library, picked the functions that parse untrusted input, and wrote the
harnesses myself.
- [libtasn1 — `asn1_get_length_der`](./fuzzing_libtasn1/case1-v4.19) — 229M execs under ASAN,
  full coverage, no crash (continuously fuzzed by OSS-Fuzz).
- [libtasn1 — `asn1_decode_simple_ber`, targeting CVE-2018-6003](./fuzzing_libtasn1/case2-v4.12)
  on the vulnerable 4.12.
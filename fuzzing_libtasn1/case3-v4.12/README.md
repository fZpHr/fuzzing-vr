# Case 3 — Understanding the strict BER trigger and the protobuf limit

## Target
- GNU libtasn1 4.12 (vulnerable version; the bug was fixed in 4.13), function
  `asn1_decode_simple_ber`.
- Same CVE as case2 (CVE-2018-6003: uncontrolled recursion / stack exhaustion in the BER
  decoder on indefinite-length encoding — CWE-674, DoS, fixed in 4.13 by a recursion depth
  limit). case2 failed to reproduce because a naive input is rejected before reaching the
  recursive path, so case3 switches to **structure-aware fuzzing** to generate valid nested
  BER directly.

## Approach: structure-aware fuzzing with libprotobuf-mutator
- Instead of mutating raw bytes, I mutate a typed tree and serialize it into well-formed BER.
- `ber.proto` describes a recursive BER node:
  ```proto
  message BerNode {
    uint32 tag = 1;
    oneof content {
      Container constructed = 2;   // -> repeated BerNode children (recursion)
      bytes    leaf        = 3;
    }
  }
  ```
- `test_fuzz_ber.cpp` walks the tree (`serialize()`) and emits TLV bytes: a constructed node
  becomes `tag` + `0x80` (indefinite length) + children + `00 00` (EOC); a leaf becomes
  `tag` + length + value. The resulting buffer is fed to `asn1_decode_simple_ber(ASN1_ETYPE_OCTET_STRING, ...)`.
- The generator is recursive by construction, so it can describe deeply nested BER shapes,
  subject to libprotobuf-mutator's internal recursion limit.

## Build
Vulnerable library 4.12, instrumented + ASAN:

    CC=clang CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" ./configure --disable-shared --disable-doc
    make

Generate the proto sources and link the harness with libprotobuf-mutator + the fuzzer engine:

    protoc --cpp_out=. ber.proto
    clang++ -g -O1 -fsanitize=address,fuzzer -I lib/includes \
        test_fuzz_ber.cpp ber.pb.cc \
        lib/.libs/libtasn1.a \
        -lprotobuf-mutator-libfuzzer -lprotobuf-mutator -lprotobuf \
        -o fuzz_ber
    ./fuzz_ber corpus_ber/ -max_len=8192

## Restriction encountered: the decoder recursion never fires
The harness builds and runs, but coverage flatlines almost immediately:

- `cov: 192  ft: 1247  corp: 172` — frozen since exec **#7268**, and still identical after
  **53M+** executions (~8900 exec/s). Every recent log line is `REDUCE`: libFuzzer is only
  minimizing the corpus, finding no new coverage and no crash.

Root cause (in `lib/decoding.c`, `_asn1_decode_simple_ber`, called with `DECODE_FLAG_HAVE_TAG`):

1. `if (tag != ETYPE_TAG(etype)) return ASN1_DER_ERROR;` — for `OCTET_STRING` the tag value
   must be **4**, i.e. the tag byte must be `0x04` (primitive) or `0x24` (constructed).
2. To enter the recursive indefinite-constructed loop it additionally requires
   `class == ASN1_CLASS_STRUCTURED` → the tag byte must be exactly **`0x24`**, followed by a
   length byte of exactly **`0x80`**. It then calls `asn1_decode_simple_ber` **recursively**
   on each inner element, each of which must again be `0x24`/`0x04`.

In `serialize()` the tag comes straight from the proto's free `uint32 tag`, which the mutator
fills with arbitrary values and we cast to one byte:

    out.push_back((char)node.tag());   // random byte, almost never 0x24

So the top-level tag matches `0x24` only ~1/256 of the time, and a nested structure needs
`0x24` at **every** level → exponentially unlikely. The decoder bails at the tag check
(step 1) before it ever recurses. The generative recursion works; the decoder's recursion is
never reached, which is why coverage is stuck at `cov: 192`.

## Fix
Pin the tag in the harness instead of letting the mutator pick it, so every generated input is
a valid (possibly deeply nested) constructed octet string:

```cpp
static void serialize(const BerNode &node, std::string &out) {
    if (node.has_constructed()) {
        out.push_back((char)0x24);      // OCTET STRING, constructed  (was node.tag())
        out.push_back((char)0x80);      // indefinite length
        for (const BerNode &child : node.constructed().children())
            serialize(child, out);
        out.push_back(0x00); out.push_back(0x00);   // EOC
    } else {
        out.push_back((char)0x04);      // OCTET STRING, primitive    (was node.tag())
        // length + value unchanged
    }
}
```

With this, the decoder's indefinite-constructed loop runs on every input and accepts the
constructed grammar. It would be able to recurse deeper if the generator could emit enough
levels, but libprotobuf-mutator is still restricted to `SetRecursionLimit(100)`. The `tag`
field in the proto becomes redundant once the bytes are pinned.


## What I learned
- Structure-aware fuzzing only helps if the generated structure actually satisfies the
  decoder's *early* validation. Here the grammar allowed recursion, but a single wrong byte
  (the tag) made every input die at the entry check — the fuzzer looked busy (53M execs) while
  exploring almost nothing.
- Coverage is the real signal: a flat `cov:` across tens of millions of executions, with only
  `REDUCE` events, means the harness is gated out of the interesting code, not that the target
  is bug-free.
- Reproducing CVE-2018-6003 needs the trigger byte-exact (`0x24` + `0x80`, nested), followed
  by enough nesting depth to trigger stack exhaustion.
- Unit tests were used to isolate the target filters. They confirmed that the decoder needs
  a constructed OCTET STRING tag `0x24`, indefinite length `0x80`, and a primitive leaf
  `0x04 0x00`; inputs missing this pattern are rejected before recursion.
- The structure-aware harness made the pattern correct, but libprotobuf-mutator imposed
  `SetRecursionLimit(100)`. Therefore the generated tree was never deep enough for the 8 MB
  stack overflow. This is the second half of why the case3 reproduction did not succeed.
- The installed libprotobuf-mutator source explicitly sets this limit in
  `port/protobuf.h`:
  ```cpp
  parser.SetRecursionLimit(100);
  ```
- The execution log also records Google's Protobuf parser rejecting an excessively deep
  `BerNode`:
  ```text
  text_format.cc:430] Error parsing text-format BerNode: ...
  Message is too deep, the parser exceeded the configured recursion limit of 100.
  ```
  This error comes from the Protobuf TextFormat parser, not from `asn1_decode_simple_ber`.
  It demonstrates that libprotobuf-mutator rejects or fails to process a mutation before
  it can generate the thousands of nested constructed nodes needed to exhaust the stack.
- Case4 removes that intermediary and returns to a custom libFuzzer harness which generates
  the exact filtered pattern with the required nesting depth, then proves the CVE.

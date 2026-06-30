# FINDING-BINUTILS-EXAMPLE-001: Example validated parser defect report format

## Status
Example Only / Not a Real Finding

## Summary
This document demonstrates the required report structure for a validated Binutils issue. It is not a vulnerability claim.

## Affected Component
- Package: Binutils
- Version / Commit: `<real commit required>`
- Component: `<real component required>`

## Source Code Evidence
- File: `<real file required>`
- Function: `<real function required>`
- Lines: `<real line range required>`

## Source-to-Sink Path
```text
malformed local object input -> parser state -> missing validation -> dangerous operation
```

## Validation Evidence
- Method: ASan/UBSan/fuzz replay/minimal testcase
- Command: `<real command required>`
- Result: `<real result required>`

## CVSS
- Version: CVSS v3.1
- Status: provisional until maintainer confirmation
- Vector: `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L` (example only; replace with evidence-based vector)
- Calculator: validate with `tools/cvss31_calculator.py --validate`

## Fix Recommendation
Add bounds/type validation, reject malformed input gracefully, and add a regression testcase.

## Disclosure Level
Internal example only.

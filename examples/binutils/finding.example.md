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
- Version: CVSS v4.0
- Status: provisional until maintainer confirmation
- Vector: `<real vector required>`

## Fix Recommendation
Add bounds/type validation, reject malformed input gracefully, and add a regression testcase.

## Disclosure Level
Internal example only.

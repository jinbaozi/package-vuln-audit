# Validation Result: CAND-BINUTILS-EXAMPLE-001

## Status
Needs Manual Review

## Validation Method
Local ASan/UBSan execution against a malformed ELF testcase.

## Example Command

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=1 \
timeout 10s build-asan/binutils/readelf -r testcase.elf
```

## Evidence Required
- Sanitizer log or graceful rejection output.
- Backtrace if crash occurs.
- Exact source commit and build flags.
- Confirmation that the testcase is local and authorized.

## Note
This file is an example validation artifact. It intentionally does not include a real testcase or claim a real bug.

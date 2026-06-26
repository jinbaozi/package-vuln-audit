# Binutils Validation Notes

Use this reference only after a candidate reaches `Likely`.

## High-value validation targets

- `readelf -a`, `readelf -r`, `readelf --debug-dump=*`
- `objdump -D`, `objdump -x`, `objdump -s`, `objdump -W`
- `nm-new`, `objcopy`, `strip-new`

## Signals that support validation

- ASan/UBSan crash with stack trace in the candidate path
- deterministic SIGSEGV/SIGABRT/assertion on malformed local input
- timeout/OOM only when bounded and reproducible
- fuzz reproducer that maps to the reviewed source location

## Signals that are not enough

- a raw tool warning without source-to-sink evidence
- a malformed input being gracefully rejected
- an AI hypothesis without a testcase or static proof
- expected behavior documented by the utility language or CLI option

## Disclosure

Keep testcase files and reproducer scripts in `audit-output/04-validation/poc-tests/<finding-id>/` until coordinated disclosure is ready.

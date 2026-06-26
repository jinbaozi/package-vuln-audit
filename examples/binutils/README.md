# Binutils Audit Example Runbook

This directory contains a ready-to-run Binutils audit wrapper for an existing GNU Binutils source tree.

## Scope

The wrapper focuses on user-controlled binary input surfaces:

- `readelf` handling of ELF files and archives
- `objdump` handling of object files and archive members
- BFD ELF/archive parsing paths
- DWARF/debug-section parsing
- opcodes/disassembler backend assumptions

The focus mirrors the upstream manuals: `readelf` displays information about ELF object files and archives containing ELF files, while `objdump` displays information about object files and archive members.

## Run artifact-only audit

```bash
./examples/binutils/run-binutils-audit.sh /path/to/binutils /path/to/audit-output
```

This produces profile, tool summary, ranked candidates and AI review packets. It does not claim vulnerabilities.

## Build sanitizer target

```bash
./tools/build_binutils_asan.sh /path/to/binutils /path/to/binutils/build-asan
```

## Validate a local testcase

```bash
./tools/validate_binutils_input.sh /path/to/binutils/build-asan testcase.elf audit-output/04-validation/binutils
```

Only findings with reproducible sanitizer/fuzz/testcase evidence may move to `Validated`.

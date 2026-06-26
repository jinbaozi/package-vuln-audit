# Real Binutils Source Audit Runbook

This runbook is for local authorized analysis of an existing GNU Binutils checkout or source package.

## 1. Generate audit artifacts

```bash
examples/binutils/run-binutils-audit.sh /path/to/binutils /path/to/binutils-audit-output
```

Review:

- `01-profile/package-profile.json`
- `01-profile/binutils/package-profile.binutils.json`
- `03-candidates/ranked-candidates.json`
- `03-candidates/packets/*.md`

## 2. Build with sanitizers

```bash
tools/build_binutils_asan.sh /path/to/binutils /path/to/binutils/build-asan
```

## 3. Validate a testcase

```bash
tools/validate_binutils_input.sh /path/to/binutils/build-asan testcase.elf /path/to/binutils-audit-output/04-validation/binutils
```

## 4. Report admission

Only promote a candidate when it has:

1. source file/function/line evidence;
2. an input field or external input source;
3. a source-to-sink explanation;
4. reproducible validation evidence;
5. false-positive exclusion notes;
6. CVSS scoring rationale if validated.

# Release Notes: 0.5.0-alpha5

This release adds a real-source Binutils audit runbook and helper scripts.

## Added

- `tools/profile_binutils.sh`
- `tools/build_binutils_asan.sh`
- `tools/validate_binutils_input.sh`
- `examples/binutils/run-binutils-audit.sh`
- `examples/binutils/README.md`
- `references/binutils-validation.md`
- `docs/runbooks/binutils-real-source.md`
- `tests/test_binutils_helpers.py`

## Validation

`./run-tests.sh` now covers the Binutils helper scripts and profiling behavior using a local fixture.

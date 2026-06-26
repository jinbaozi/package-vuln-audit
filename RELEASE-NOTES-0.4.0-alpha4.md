# Release Notes: 0.4.0-alpha4

This release adds a real sample end-to-end pipeline exercise using a local C fixture.

## Added

- `examples/toy-cpkg/`: small local-only C parser fixture.
- `examples/toy-cpkg/run-audit-demo.sh`: end-to-end artifact generation demo.
- `tests/test_e2e_toy_project.py`: automated E2E verification.
- `docs/runbooks/real-sample-e2e.md`: runbook for local sample validation.
- `profile_project.sh` now emits `package-profile.json` and `package-profile.md`.

## Validation

- Schema validation.
- Candidate ranking tests.
- AI packet generation tests.
- Report admission tests.
- Toy C project end-to-end artifact chain.

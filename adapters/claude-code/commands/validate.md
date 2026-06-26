# /validate

Validate a Likely candidate using local, defensive evidence.

Arguments:
- `candidate` path to candidate packet
- `output_dir` default `audit-output`

Dispatch `validator`. Allowed validation includes sanitizer builds, unit tests, fuzz reproducer replay, minimal malformed local testcases, and static refutation. The output must conform to `schemas/validation-result.schema.json`. Do not create weaponized exploit code.

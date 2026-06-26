# Real Sample E2E Runbook

This runbook validates that the skill can generate artifacts from a real source tree without relying on an online model.

## Fixture

`examples/toy-cpkg` is a local-only C parser fixture. It contains intentionally unsafe parsing code so the pipeline can exercise:

- package profiling
- tool execution
- result normalization
- candidate ranking
- AI packet generation
- artifact summarization

## Run

```bash
cd package-vuln-audit-skill
examples/toy-cpkg/run-audit-demo.sh
```

## Expected artifacts

```text
examples/toy-cpkg/audit-output/
├── 01-profile/package-profile.json
├── 02-tools/tool-summary.json
├── 03-candidates/raw-candidates.json
├── 03-candidates/ranked-candidates.json
├── 03-candidates/packets/packet-index.json
└── summary.json
```

This fixture does not represent a real vulnerability disclosure. It is for validating the audit pipeline only.

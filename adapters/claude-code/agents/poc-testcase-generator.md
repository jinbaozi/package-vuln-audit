# PoC Testcase Generator

Generate local multi-language reproducer and regression-test artifacts for Validated Findings and Needs Manual Review Findings. PoC here means local validation testcase, not weaponized exploit.

## Capabilities

- **Multi-language generation**: Produces PoC variants in Python, C, C++, Java, Go (and optionally Perl, Shell, Ruby, etc.)
- **Auto language selection**: Selects languages based on package profile (project primary language) or source code evidence
- **Explicit language override**: Accepts `--languages` parameter to override auto-selection
- **Draft mode for Manual Review**: Generates draft/unverified PoCs for Needs Manual Review findings

## Requirements per variant

Each language variant must include:
- Build steps (for compiled languages, via Makefile)
- Reproduce command (with `timeout` protection)
- Expected vulnerable behavior
- Expected fixed behavior
- Artifact hashes (SHA256)
- `poc-manifest.json` with `discovery_method_ref`
- `input-description.md` with SHA256 and purpose

## Safety constraints

- Local-validation-only
- No network access (no curl, wget, ssh, etc.)
- No privilege escalation (no sudo, su, setcap)
- No system writes (no writes to /etc, /usr, /var/lib, /root)
- `timeout` mandatory on all execution
- Temporary directory cleanup

## Output structure

```
<FINDING-ID>/
├── <language>/
│   ├── reproduce.<ext>
│   ├── poc-manifest.json
│   ├── poc-run-result.json
│   ├── input-description.md
│   ├── expected-vulnerable.txt
│   └── expected-fixed.txt
├── reproduce.sh      (main runner)
├── poc-manifest.json  (aggregate manifest with language_variants)
├── input-description.md
└── README.md
```

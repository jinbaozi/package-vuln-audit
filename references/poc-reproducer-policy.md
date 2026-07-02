# PoC / Reproducer Policy

PoC means local reproducer testcase for authorized validation and regression testing. Default disclosure is internal or maintainer-private. Public advisory output must not include reproducer scripts or testcase bytes unless public-after-fix is explicitly approved.

## Multi-Language PoC Generation

PoC testcases are generated in **multiple programming languages** for each finding. The default language set is Python, C, C++, Java, and Go. Language selection can be:

- **Auto-selected** based on the package profile (primary language and detected languages)
- **Explicitly specified** via the `--languages` parameter

### Language Selection Rules

| Project Language | Default PoC Languages |
|-----------------|----------------------|
| C/C++ | C, C++, Python |
| Java | Java, Python, Go |
| Python | Python, C, Go |
| Go | Go, Python, C |
| Other/Unknown | All 5 (Python, C, C++, Java, Go) |

### Output Structure

Each finding gets a multi-language PoC package:

```
audit-output/04-validation/poc-tests/<FINDING-ID>/
├── python/         # Python variant
├── c/              # C variant (with Makefile)
├── cpp/            # C++ variant (with Makefile)
├── java/           # Java variant (with Makefile)
├── go/             # Go variant
├── reproduce.sh    # Main runner (tries all variants)
├── poc-manifest.json
├── input-description.md
└── README.md
```

## Finding Status Requirements

- **Validated findings**: verified PoC must execute successfully in at least one language variant (`poc-run-result.json` status = `passed`). Manifest status uses the verified finding state.
- **Needs Manual Review findings**: PoC is generated as a draft (`status: "draft"`, `verification: "unverified"`). At least one local draft variant must execute successfully (`poc-run-result.json` status = `passed`). The passed draft run is a manual-review signal only and must not promote the finding to a verified state.

## Safety Requirements

All PoC variants must:
- Use `timeout` to prevent hangs
- Avoid network access (no curl, wget, ssh, etc.)
- Avoid privilege escalation (no sudo, su, setcap)
- Avoid system writes (no writes to /etc, /usr, /var/lib, /root)
- Clean up temporary directories
- Be local-validation-only

`Needs Manual Review` items also receive manual validation plans in addition to draft PoC packages. Final reports must cite both the manual validation plan and the passed draft execution result. They can be promoted only after the full validation workflow confirms stable local reproduction and updates the finding state.

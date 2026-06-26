# /hypothesis-hunt

Generate AI hypotheses for vulnerabilities traditional tools may miss.

Arguments:
- `profile` path to `package-profile.json`
- `recipe` optional selected recipe path
- `output_dir` default `audit-output`

Dispatch `hypothesis-hunter` with read-only source access and no raw tool-log context. Each hypothesis must name a real component, a concrete safety assumption, an attacker-controlled input or state, a possible sink, and a safe validation method. Hypotheses are not findings.

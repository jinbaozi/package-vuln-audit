# tool-install-assistant

Purpose: assist strict-mode traditional tool recovery without polluting the parent agent context.

Responsibilities:
- Probe environment summaries only: OS family, architecture, Python/Node/Go availability, glibc, PATH, offline-bundle presence.
- Generate controlled install plans with this priority: offline-bundle, Python/pipx/uv, npm/npx, user-local binary/distribution, administrator RPM/DNF plan.
- Enforce dry-run by default.
- Require per-tool authorization before any user-prefix installation action.
- Enforce prefix realpath containment and reject prefix escape.
- Verify offline-bundle manifest and SHA256 before any offline install action.
- Treat network mode as offline unless explicitly approved.
- Treat RPM/DNF as a last-resort plan. When `--authorize-system-install` and `--interactive-sudo` are both set, execute `sudo dnf install` after interactive sudo password authentication via `sudo -v`. Block if sudo authentication fails.
- Write `install-assistant-summary.json`, `install-assistant-decision.json`, and a short log digest.

Parent context rule:
- The parent agent may read only summary, decision, and digest files.
- The parent agent must not read raw pip/npm/uv/go/dnf logs, full installer logs, full download logs, or complete manifests.

Outputs:
- `audit-output/00-environment/install-assistant-summary.json`
- `audit-output/00-environment/install-assistant-decision.json`
- `audit-output/00-environment/install-assistant-log-digest.txt`

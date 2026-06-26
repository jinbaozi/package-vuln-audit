#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install/verify-install.sh [options]

Options:
  --target DIR       Target repository root. Default: current directory.
  --platform NAME    all | claude-code | codex | opencode. Default: all.
  -h, --help         Show help.
EOF
}

TARGET="$(pwd)"
PLATFORM="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
TARGET="$(cd "$TARGET" && pwd)"
case "$PLATFORM" in all|claude-code|codex|opencode) ;; *) echo "Invalid --platform: $PLATFORM" >&2; exit 2 ;; esac

missing=0
check_path() {
  local p="$1"
  if [[ ! -e "$TARGET/$p" ]]; then
    echo "[missing] $p"
    missing=1
  else
    echo "[ok] $p"
  fi
}

check_skill_core() {
  local base="$1"
  check_path "$base/SKILL.md"
  check_path "$base/AGENTS.md"
  check_path "$base/workflows/00-intake.md"
  check_path "$base/recipes/binary-parser.md"
  check_path "$base/agents/coordinator.md"
  check_path "$base/tools/profile_project.sh"
  check_path "$base/schemas/finding.schema.json"
  check_path "$base/schemas/context-budget.schema.json"
  check_path "$base/schemas/environment-check.schema.json"
  check_path "$base/schemas/tool-install-plan.schema.json"
  check_path "$base/templates/finding.md"
  check_path "$base/templates/tool-install-plan.md"
  check_path "$base/references/context-hygiene.md"
  check_path "$base/references/context-budget-policy.md"
  check_path "$base/references/tool-installation-policy.md"
  check_path "$base/tools/context_budget.py"
  check_path "$base/tools/verify_environment.py"
  check_path "$base/tools/generate_install_plan.py"
}

verify_claude() {
  check_path ".claude/commands/package-vuln-audit.md"
  check_path ".claude/agents/package-profiler.md"
  check_path "CLAUDE.md"
  check_skill_core ".claude/skills/package-vuln-audit"
}
verify_codex() {
  check_path "AGENTS.md"
  check_skill_core ".codex/skills/package-vuln-audit"
}
verify_opencode() {
  check_path ".opencode/opencode.json"
  check_path ".opencode/agents/coordinator.md"
  check_path ".opencode/commands/package-vuln-audit.md"
  check_skill_core ".opencode/skills/package-vuln-audit"
}

case "$PLATFORM" in
  all) verify_claude; verify_codex; verify_opencode ;;
  claude-code) verify_claude ;;
  codex) verify_codex ;;
  opencode) verify_opencode ;;
esac

if [[ "$missing" -ne 0 ]]; then
  echo "[verify] failed" >&2
  exit 1
fi

echo "[verify] installation looks complete for platform=$PLATFORM target=$TARGET"

test -f "$TARGET/schemas/bilingual-output.schema.json" || test -f "$TARGET/.claude/skills/package-vuln-audit/schemas/bilingual-output.schema.json" || true

test -f "$TARGET/tools/publish_bilingual_reports.py" || test -f "$TARGET/.claude/skills/package-vuln-audit/tools/publish_bilingual_reports.py" || true

test -f "$TARGET/tools/correlate_public_vulns.py" || test -f "$TARGET/.claude/skills/package-vuln-audit/tools/correlate_public_vulns.py" || true

test -f "$TARGET/tools/generate_poc_testcase.py" || test -f "$TARGET/.claude/skills/package-vuln-audit/tools/generate_poc_testcase.py" || true

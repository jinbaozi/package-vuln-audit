#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install/install.sh [options]

Install package-vuln-audit-skill adapters into a target repository.

Options:
  --target DIR             Target repository root. Default: current directory.
  --source DIR             Skill package root. Default: parent of this script directory.
  --platform NAME          all | claude-code | codex | opencode. Default: all.
  --mode MODE              copy | symlink. Default: copy.
  --force                  Overwrite existing adapter files.
  --no-root-agents         Do not install AGENTS.md into target root.
  -h, --help               Show help.

Examples:
  install/install.sh --target /repo --platform all --mode copy
  install/install.sh --target /repo --platform opencode --mode symlink --force
EOF
}

TARGET="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$(cd "$SCRIPT_DIR/.." && pwd)"
PLATFORM="all"
MODE="copy"
FORCE=0
INSTALL_ROOT_AGENTS=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --no-root-agents) INSTALL_ROOT_AGENTS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

TARGET="$(mkdir -p "$TARGET" && cd "$TARGET" && pwd)"
SOURCE="$(cd "$SOURCE" && pwd)"

case "$PLATFORM" in all|claude-code|codex|opencode) ;; *) echo "Invalid --platform: $PLATFORM" >&2; exit 2 ;; esac
case "$MODE" in copy|symlink) ;; *) echo "Invalid --mode: $MODE" >&2; exit 2 ;; esac

require_file() { [[ -f "$SOURCE/$1" ]] || { echo "Missing source file: $SOURCE/$1" >&2; exit 1; }; }
require_dir() { [[ -d "$SOURCE/$1" ]] || { echo "Missing source directory: $SOURCE/$1" >&2; exit 1; }; }

require_file SKILL.md
require_file AGENTS.md
require_dir workflows
require_dir recipes
require_dir agents
require_dir tools
require_dir schemas
require_dir templates
require_dir references

copy_or_link() {
  local src="$1"
  local dst="$2"
  mkdir -p "$(dirname "$dst")"
  if [[ -e "$dst" || -L "$dst" ]]; then
    if [[ "$FORCE" -eq 1 ]]; then
      rm -rf "$dst"
    else
      echo "Refusing to overwrite existing path: $dst (use --force)" >&2
      exit 1
    fi
  fi
  if [[ "$MODE" == "symlink" ]]; then
    ln -s "$src" "$dst"
  else
    cp -a "$src" "$dst"
  fi
}

install_core_skill_dir() {
  local dst="$1"
  mkdir -p "$dst"
  for item in SKILL.md AGENTS.md README.md workflows recipes agents tools schemas templates references; do
    [[ -e "$SOURCE/$item" ]] || continue
    copy_or_link "$SOURCE/$item" "$dst/$item"
  done
}

install_root_agents() {
  [[ "$INSTALL_ROOT_AGENTS" -eq 1 ]] || return 0
  copy_or_link "$SOURCE/AGENTS.md" "$TARGET/AGENTS.md"
}

install_claude() {
  echo "[install] Claude Code adapter -> $TARGET/.claude"
  mkdir -p "$TARGET/.claude/commands" "$TARGET/.claude/agents" "$TARGET/.claude/skills/package-vuln-audit"
  install_core_skill_dir "$TARGET/.claude/skills/package-vuln-audit"
  copy_or_link "$SOURCE/adapters/claude-code/CLAUDE.md" "$TARGET/CLAUDE.md"
  for f in "$SOURCE"/adapters/claude-code/commands/*.md; do copy_or_link "$f" "$TARGET/.claude/commands/$(basename "$f")"; done
  for f in "$SOURCE"/adapters/claude-code/agents/*.md; do copy_or_link "$f" "$TARGET/.claude/agents/$(basename "$f")"; done
}

install_codex() {
  echo "[install] Codex adapter -> $TARGET/.codex"
  mkdir -p "$TARGET/.codex/skills/package-vuln-audit"
  install_core_skill_dir "$TARGET/.codex/skills/package-vuln-audit"
  copy_or_link "$SOURCE/adapters/codex/AGENTS.md" "$TARGET/AGENTS.md"
}

install_opencode() {
  echo "[install] opencode adapter -> $TARGET/.opencode"
  mkdir -p "$TARGET/.opencode/agents" "$TARGET/.opencode/commands" "$TARGET/.opencode/skills/package-vuln-audit"
  install_core_skill_dir "$TARGET/.opencode/skills/package-vuln-audit"
  copy_or_link "$SOURCE/adapters/opencode/opencode.json" "$TARGET/.opencode/opencode.json"
  for f in "$SOURCE"/adapters/opencode/agents/*.md; do copy_or_link "$f" "$TARGET/.opencode/agents/$(basename "$f")"; done
  for f in "$SOURCE"/adapters/opencode/commands/*.md; do copy_or_link "$f" "$TARGET/.opencode/commands/$(basename "$f")"; done
  install_root_agents
}

case "$PLATFORM" in
  all)
    # Avoid duplicate AGENTS.md installs: Codex owns AGENTS.md in this mode, then opencode skips root AGENTS.
    install_claude
    INSTALL_ROOT_AGENTS=0 install_codex
    INSTALL_ROOT_AGENTS=0 install_opencode
    ;;
  claude-code) install_root_agents; install_claude ;;
  codex) install_codex ;;
  opencode) install_opencode ;;
esac

echo "[install] completed platform=$PLATFORM mode=$MODE target=$TARGET"
echo "[install] run: $SOURCE/install/verify-install.sh --target '$TARGET' --platform '$PLATFORM'"

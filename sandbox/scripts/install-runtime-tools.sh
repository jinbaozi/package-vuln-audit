#!/usr/bin/env sh
# Stage static binaries, Python wrappers, and clang toolchain symlinks
# from offline-bundle/binaries/ to /opt/pvas/tools/bin/.
#
# Tools are taken from offline-bundle/binaries/ which is populated by
# sandbox/scripts/stage-deps.sh (run on the host before docker build)
# or by the upstream maintainer's install script.
#
# Note: missing tools are NOT fatal here. audit-image-verify.py runs after
# docker build and reports which tools are unavailable.

set -eu

bundle="${1:-/opt/pvas/offline-bundle}"
prefix="${2:-/opt/pvas/tools}"
mkdir -p "$prefix/bin"

# ---------------------------------------------------------------------------
# Stage 1: Static binaries and Python wrappers from offline-bundle/binaries/
# ---------------------------------------------------------------------------
# Complete tool list. Add new tools here when adding them to the audit matrix.
# Each entry is a tool name that should exist in offline-bundle/binaries/.
for tool in \
    osv-scanner codeql syft grype trivy joern \
    semgrep cppcheck rg grep find xargs \
    ; do
  if [ -x "$bundle/binaries/$tool" ]; then
    cp "$bundle/binaries/$tool" "$prefix/bin/$tool"
    chmod 0755 "$prefix/bin/$tool"
  fi
done

# ---------------------------------------------------------------------------
# Stage 2: Symlink host clang/llvm tools (when available in the imported image).
# Many audits need clang+libasan to compile C PoCs in-container. The imported
# Kylin V11 image provides /usr/bin/clang etc. when installed via dnf.
# ---------------------------------------------------------------------------
for tool in clang clang++ llvm-symbolizer ld.lld; do
  if [ -x "/usr/bin/$tool" ] && [ ! -e "$prefix/bin/$tool" ]; then
    ln -sf "/usr/bin/$tool" "$prefix/bin/$tool"
  fi
done

# ---------------------------------------------------------------------------
# Stage 3: Verify Python wrappers will resolve modules at runtime.
# The runtime image ENV must include PYTHONPATH=...site-packages.
# This step only emits a warning if venv is missing.
# ---------------------------------------------------------------------------
if [ ! -d "/opt/pvas/venv/lib64/python3.11/site-packages" ]; then
    echo "[install-runtime-tools] WARN: /opt/pvas/venv not yet created; wheels will install there" >&2
fi
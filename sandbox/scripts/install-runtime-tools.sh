#!/usr/bin/env sh
set -eu

bundle="${1:-/opt/pvas/offline-bundle}"
prefix="${2:-/opt/pvas/tools}"
mkdir -p "$prefix/bin"

# The runtime image build is allowed to proceed without optional bundle tools.
# verify_runtime_tools.py enforces strict-required presence before audits run.
for tool in osv-scanner codeql syft grype trivy joern semgrep; do
  if [ -x "$bundle/binaries/$tool" ]; then
    cp "$bundle/binaries/$tool" "$prefix/bin/$tool"
    chmod 0755 "$prefix/bin/$tool"
  fi
done

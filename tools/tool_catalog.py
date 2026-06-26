#!/usr/bin/env python3
"""Shared tool catalog for Package Vulnerability Audit Skill."""
from __future__ import annotations

CATALOG = {
    "rg": {
        "binary": "rg",
        "level": "recommended",
        "profiles": ["minimal", "standard", "full", "binutils"],
        "required_for": ["basic-search", "dangerous-api-search"],
        "impact": "High-speed source search and dangerous API grep will use slower grep/find fallbacks or be unavailable.",
        "install_hint_id": "rg",
        "version_args": ["--version"],
        "dnf_package": "ripgrep",
    },
    "semgrep": {
        "binary": "semgrep",
        "level": "recommended",
        "profiles": ["standard", "full", "binutils"],
        "required_for": ["rule-scanning", "sast-candidates"],
        "impact": "Semgrep rule-based SAST candidates will not be generated.",
        "install_hint_id": "semgrep",
        "version_args": ["--version"],
        "dnf_package": "semgrep",
    },
    "cppcheck": {
        "binary": "cppcheck",
        "level": "recommended",
        "profiles": ["standard", "full", "binutils"],
        "required_for": ["c-cpp-baseline", "static-analysis"],
        "impact": "C/C++ baseline static-analysis candidates will be reduced.",
        "install_hint_id": "cppcheck",
        "version_args": ["--version"],
        "dnf_package": "cppcheck",
    },
    "osv-scanner": {
        "binary": "osv-scanner",
        "level": "recommended",
        "profiles": ["standard", "full", "binutils"],
        "required_for": ["known-vulnerability-scan", "dependency-cve-scan"],
        "impact": "Known dependency vulnerability matching against OSV will not run.",
        "install_hint_id": "osv-scanner",
        "version_args": ["--version"],
    },
    "npm": {
        "binary": "npm",
        "level": "optional",
        "profiles": ["standard", "full"],
        "required_for": ["node-dependency-audit", "npm-audit"],
        "impact": "Node.js projects cannot use npm audit as a dependency vulnerability fallback.",
        "install_hint_id": "npm",
        "version_args": ["--version"],
    },
    "codeql": {
        "binary": "codeql",
        "level": "optional",
        "profiles": ["full", "binutils"],
        "required_for": ["semantic-analysis", "dataflow-analysis"],
        "impact": "CodeQL semantic/dataflow analysis will not run.",
        "install_hint_id": "codeql",
        "version_args": ["version"],
    },
    "joern": {
        "binary": "joern",
        "level": "optional",
        "profiles": ["full"],
        "required_for": ["cpg-analysis", "deep-c-cpp-analysis"],
        "impact": "Code Property Graph analysis will not run.",
        "install_hint_id": "joern",
        "version_args": ["--version"],
    },
    "syft": {
        "binary": "syft",
        "level": "optional",
        "profiles": ["full"],
        "required_for": ["sbom-generation"],
        "impact": "SBOM generation will not run.",
        "install_hint_id": "syft",
        "version_args": ["version"],
    },
    "grype": {
        "binary": "grype",
        "level": "optional",
        "profiles": ["full"],
        "required_for": ["sbom-vulnerability-scan"],
        "impact": "Grype vulnerability scanning will not run.",
        "install_hint_id": "grype",
        "version_args": ["version"],
    },
    "trivy": {
        "binary": "trivy",
        "level": "optional",
        "profiles": ["full"],
        "required_for": ["vulnerability-scan", "sbom-scan", "config-scan"],
        "impact": "Trivy vulnerability/SBOM/config scanning will not run.",
        "install_hint_id": "trivy",
        "version_args": ["--version"],
    },
    "afl-fuzz": {
        "binary": "afl-fuzz",
        "level": "optional",
        "profiles": ["full", "binutils"],
        "required_for": ["fuzzing"],
        "impact": "AFL++ fuzzing workflows will not run.",
        "install_hint_id": "afl-fuzz",
        "version_args": ["-V"],
    },
    "gcc": {
        "binary": "gcc",
        "level": "recommended",
        "profiles": ["binutils"],
        "required_for": ["asan-ubsan-build", "c-cpp-build"],
        "impact": "Binutils sanitizer builds may not run with GCC.",
        "install_hint_id": "gcc",
        "version_args": ["--version"],
        "dnf_package": "gcc",
    },
    "make": {
        "binary": "make",
        "level": "recommended",
        "profiles": ["binutils"],
        "required_for": ["project-build"],
        "impact": "Autotools/Make based package builds may not run.",
        "install_hint_id": "make",
        "version_args": ["--version"],
        "dnf_package": "make",
    },
    "timeout": {
        "binary": "timeout",
        "level": "recommended",
        "profiles": ["binutils"],
        "required_for": ["bounded-validation"],
        "impact": "Validation commands cannot be bounded with timeout.",
        "install_hint_id": "coreutils-timeout",
        "version_args": ["--version"],
    },
}

PROFILE_TOOLS = {
    "minimal": ["rg"],
    "standard": ["rg", "semgrep", "cppcheck", "osv-scanner", "npm"],
    "full": ["rg", "semgrep", "cppcheck", "osv-scanner", "npm", "codeql", "joern", "syft", "grype", "trivy", "afl-fuzz"],
    "binutils": ["rg", "semgrep", "cppcheck", "osv-scanner", "codeql", "gcc", "make", "timeout", "afl-fuzz"],
}

STRICT_REQUIRED_TOOLS = {
    "minimal": ["rg"],
    "standard": ["rg", "semgrep", "cppcheck", "osv-scanner"],
    "binutils": ["rg", "semgrep", "cppcheck", "osv-scanner", "gcc", "make", "timeout"],
    "full": ["rg", "semgrep", "cppcheck", "osv-scanner", "codeql", "syft", "grype"],
}

CONTROLLED_INSTALL_METHOD_ORDER = [
    "offline-bundle",
    "python-pipx",
    "python-uv",
    "npm-npx",
    "github-release-download",
    "user-local-binary",
    "user-local-distribution",
    "go-install-user-local",
    "admin-rpm-dnf-plan",
]

INSTALL_HINTS = {
    "semgrep": [
        {"priority": 0, "method": "offline-bundle", "commands": ["python3 tools/install_assistant.py --tool semgrep --mode strict --dry-run --offline-bundle offline-bundle"], "notes": "Preferred controlled path: verify offline-bundle manifest/hash and install into an approved user prefix only after per-tool authorization."},
        {"priority": 1, "method": "python-pipx", "commands": ["python3 -m pip install --user pipx", "python3 -m pipx ensurepath", "pipx install semgrep"], "notes": "User-local isolated Python CLI install. Requires explicit per-tool authorization and allowed network or internal index."},
        {"priority": 2, "method": "python-uv", "commands": ["uv tool install semgrep"], "notes": "Alternative isolated Python tool installer. Requires explicit per-tool authorization and allowed network or internal index."},
        {"priority": 9, "method": "admin-rpm-dnf-plan", "commands": ["# Last-resort administrator plan only; do not execute automatically", "# sudo dnf install <approved-semgrep-package-or-local-rpm>"], "notes": "System package management requires separate system-install authorization and is never executed by default."},
    ],
    "cppcheck": [
        {"priority": 0, "method": "offline-bundle", "commands": ["python3 tools/install_assistant.py --tool cppcheck --mode strict --dry-run --offline-bundle offline-bundle"], "notes": "Preferred controlled path: offline binary/RPM payload verified by hash and installed into the user prefix only after authorization."},
        {"priority": 4, "method": "user-local-binary", "commands": ["mkdir -p ~/.pvas/bin", "install -m 0755 cppcheck ~/.pvas/bin/cppcheck", "export PATH=\"$HOME/.pvas/bin:$PATH\""], "notes": "Use a vetted user-local binary from the offline bundle or internal artifact store."},
        {"priority": 9, "method": "admin-rpm-dnf-plan", "commands": ["# Last-resort administrator plan only", "# sudo dnf install cppcheck"], "notes": "RPM/DNF is a final administrator option; do not execute without separate authorization."},
    ],
    "osv-scanner": [
        {"priority": 0, "method": "offline-bundle", "commands": ["python3 tools/install_assistant.py --tool osv-scanner --mode strict --dry-run --offline-bundle offline-bundle"], "notes": "Preferred controlled path: verified offline-bundle binary installed under the user prefix."},
        {"priority": 3, "method": "github-release-download", "commands": ["install_assistant.py --tool osv-scanner --network-mode online-approved --execute"], "notes": "Download the official prebuilt Linux binary from GitHub releases (github.com/google/osv-scanner). Requires --network-mode online-approved and explicit --authorize-tool osv-scanner. Architecture auto-detected."},
        {"priority": 4, "method": "user-local-binary", "commands": ["mkdir -p ~/.pvas/bin", "install -m 0755 osv-scanner ~/.pvas/bin/osv-scanner", "export PATH=\"$HOME/.pvas/bin:$PATH\""], "notes": "Use the official/pre-approved prebuilt binary or an internal mirror."},
        {"priority": 5, "method": "go-install-user-local", "commands": ["GOBIN=$HOME/.pvas/bin go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"], "notes": "Requires Go plus an approved network/proxy mode; not used in offline mode."},
        {"priority": 9, "method": "admin-rpm-dnf-plan", "commands": ["# Last-resort administrator plan only", "# sudo dnf install <approved-osv-scanner-package-or-local-rpm>"], "notes": "System package management requires separate authorization."},
    ],
    "npm": [
        {"priority": 0, "method": "offline-bundle", "commands": ["# Use an approved Node.js/npm offline bundle and validate bundle hashes first"], "notes": "Preferred for controlled networks. npx remote fetch is disabled unless network mode authorizes it."},
        {"priority": 3, "method": "npm-npx", "commands": ["npm --version", "npm audit --json"], "notes": "Only run against local project dependencies or approved registries; npx remote package execution needs explicit network authorization."},
        {"priority": 9, "method": "admin-rpm-dnf-plan", "commands": ["# Last-resort administrator plan only", "# sudo dnf install nodejs npm"], "notes": "Do not execute system package manager by default."},
    ],
    "codeql": [
        {"priority": 0, "method": "offline-bundle", "commands": ["python3 tools/install_assistant.py --tool codeql --mode strict --dry-run --offline-bundle offline-bundle"], "notes": "Preferred controlled path: verified CodeQL bundle extracted into the user prefix."},
        {"priority": 4, "method": "user-local-distribution", "commands": ["mkdir -p ~/.pvas/codeql", "# Extract approved CodeQL bundle into ~/.pvas/codeql", "export PATH=\"$HOME/.pvas/codeql:$PATH\"", "codeql version"], "notes": "Use official CodeQL CLI bundle or internal mirror; glibc Linux required."},
    ],
    "syft": [
        {"priority": 0, "method": "offline-bundle", "commands": ["python3 tools/install_assistant.py --tool syft --mode strict --dry-run --offline-bundle offline-bundle"], "notes": "Preferred controlled path: verified offline-bundle binary."},
        {"priority": 4, "method": "user-local-binary", "commands": ["mkdir -p ~/.pvas/bin", "install -m 0755 syft ~/.pvas/bin/syft"], "notes": "Use approved user-local binary."},
    ],
    "grype": [
        {"priority": 0, "method": "offline-bundle", "commands": ["python3 tools/install_assistant.py --tool grype --mode strict --dry-run --offline-bundle offline-bundle"], "notes": "Preferred controlled path: verified offline-bundle binary."},
        {"priority": 4, "method": "user-local-binary", "commands": ["mkdir -p ~/.pvas/bin", "install -m 0755 grype ~/.pvas/bin/grype"], "notes": "Use approved user-local binary."},
    ],
    "trivy": [
        {"priority": 0, "method": "offline-bundle", "commands": ["python3 tools/install_assistant.py --tool trivy --mode strict --dry-run --offline-bundle offline-bundle"], "notes": "Preferred controlled path: verified offline-bundle binary."},
        {"priority": 4, "method": "user-local-binary", "commands": ["mkdir -p ~/.pvas/bin", "install -m 0755 trivy ~/.pvas/bin/trivy"], "notes": "Use approved user-local binary."},
    ],
    "rg": [
        {"priority": 0, "method": "offline-bundle", "commands": ["python3 tools/install_assistant.py --tool rg --mode strict --dry-run --offline-bundle offline-bundle"], "notes": "Preferred controlled path: verified ripgrep binary from offline bundle."},
        {"priority": 4, "method": "user-local-binary", "commands": ["mkdir -p ~/.pvas/bin", "install -m 0755 rg ~/.pvas/bin/rg"], "notes": "Use approved user-local binary."},
        {"priority": 9, "method": "admin-rpm-dnf-plan", "commands": ["# Last-resort administrator plan only", "# sudo dnf install ripgrep"], "notes": "Do not execute RPM/DNF without separate system-install authorization."},
    ],
    "joern": [
        {"priority": 0, "method": "offline-bundle", "commands": ["# Extract approved Joern offline distribution after hash validation"], "notes": "Preferred controlled path."},
        {"priority": 4, "method": "user-local-distribution", "commands": ["# Extract Joern distribution into ~/.pvas/joern", "export PATH=\"$HOME/.pvas/joern:$PATH\""], "notes": "Prefer internal mirrored distribution for offline environments."},
    ],
    "afl-fuzz": [
        {"priority": 0, "method": "offline-bundle", "commands": ["# Use an approved AFL++ container/image/build artifact; keep fuzzing separate from baseline scan"], "notes": "Fuzzing is not a default strict-mode gate unless explicitly required."},
        {"priority": 4, "method": "user-local-binary", "commands": ["# Install approved afl-fuzz binary/build under ~/.pvas"], "notes": "Do not install system-wide by default."},
    ],
    "gcc": [
        {"priority": 0, "method": "offline-bundle", "commands": ["# Use approved offline toolchain bundle or existing build environment"], "notes": "Compiler toolchains are environment dependencies; do not mutate system by default."},
        {"priority": 9, "method": "admin-rpm-dnf-plan", "commands": ["# Last-resort administrator plan only", "# sudo dnf install gcc"], "notes": "Requires separate system-install authorization."},
    ],
    "make": [
        {"priority": 0, "method": "offline-bundle", "commands": ["# Use approved offline build tools bundle or existing build environment"], "notes": "Build tools are environment dependencies; do not mutate system by default."},
        {"priority": 9, "method": "admin-rpm-dnf-plan", "commands": ["# Last-resort administrator plan only", "# sudo dnf install make"], "notes": "Requires separate system-install authorization."},
    ],
    "coreutils-timeout": [
        {"priority": 0, "method": "offline-bundle", "commands": ["# Use approved coreutils/timeout from existing environment or offline bundle"], "notes": "Usually provided by GNU coreutils."},
        {"priority": 9, "method": "admin-rpm-dnf-plan", "commands": ["# Last-resort administrator plan only", "# sudo dnf install coreutils"], "notes": "Requires separate system-install authorization."},
    ],
}

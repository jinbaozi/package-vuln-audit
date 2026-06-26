# Recipe: package-manager

## Applies to

Package managers, installers, updaters, repository clients, signature verifiers, and dependency resolvers.

## First-pass scope

Start with package resolution, download/fetch paths, signature verification, archive extraction, dependency graph processing, and configuration handling. Avoid overfitting to a package type until the Package Profiler has higher confidence.

## High-risk inputs

- Package name and version strings (injection, comparison logic)
- Repository URLs and redirect chains
- Signature data and certificate chains for package verification
- Dependency graphs and resolution metadata
- Archive-internal paths and filenames (zip-slip, symlink in archive)
- Package metadata fields (description, scripts, hooks)
- Lock files and cache state

## Primary tools

- `rg` for package-manager patterns: `verify_signature`, `extract_to`, `resolve_version`, `download_url`, `exec_hook`, `eval` on metadata
- Semgrep for missing signature verification, unsafe archive extraction, shell injection in hooks
- CodeQL for dataflow from package metadata to execution
- Package vulnerability scanners for known CVEs in dependencies

## AI hypothesis focus

The hypothesis hunter should search for safety assumptions that traditional tools may miss:

- Dependency confusion (typosquatting, private registry fallback)
- Signature verification bypass (skipping check on error, accepting expired signatures)
- Archive path traversal during extraction (zip-slip, symlink-to-absolute)
- Version comparison logic errors (string vs numeric, pre-release handling)
- Repository hijacking via MitM or DNS poisoning without pinning
- Cache poisoning with stale or tampered packages
- Post-install script execution without sandboxing
- Lock file manipulation to pin malicious versions

## Candidate priority

Prioritize candidates involving untrusted package data influencing file extraction, command execution, signature decisions, or dependency resolution.

## Recommended evidence

Every candidate must be grounded in real source path, function, line range, source-to-sink reasoning, and validation or a clear statement of missing validation.

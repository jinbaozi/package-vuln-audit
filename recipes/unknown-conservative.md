# Recipe: unknown-conservative

## Applies to

Fallback recipe when profiling is low confidence. Provides safe, broad, low-assumption scanning only.

## First-pass scope

Start with external input handling, configuration parsing, file/path processing, boundary-crossing logic, and dependency manifests. Avoid overfitting to a package type until the Package Profiler has higher confidence.

## High-risk inputs

- External input from files, network, stdin, or command-line arguments
- Configuration values that influence program behavior
- File paths and directory names from untrusted sources
- Deserialized data or parsed structured formats

## Primary tools

- `rg` for general safety patterns: buffer operations, string handling, memory allocation with input-controlled sizes
- Semgrep for common dangerous APIs across languages
- CodeQL where supported for dataflow analysis
- Package vulnerability scanners and safe local tests

## AI hypothesis focus

Use broad, language-agnostic hypothesis generation:

- Missing input validation on external data
- Unsafe memory operations (buffer overflow, use-after-free, double-free)
- Injection vulnerabilities (command, path, template)
- Error handling that leaks information or leaves inconsistent state

## Recommended evidence

Every candidate must be grounded in real source path, function, line range, source-to-sink reasoning, and validation or a clear statement of missing validation.

## Upgrade path

When profiling confidence increases during the audit (e.g., the Package Profiler identifies the package as a `binary-parser` or `network-service` after deeper analysis), transition to the appropriate specific recipe. The Coordinator should re-dispatch the Scope Selector with the updated profile to select a more targeted recipe. Do not continue with `unknown-conservative` when a more specific recipe is available and profiling confidence is `medium` or higher.

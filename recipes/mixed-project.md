# Recipe: mixed-project

## Applies to

Projects with multiple languages, code generators, vendored dependencies, or mixed build systems.

## First-pass scope

Start with cross-language boundaries, generated code pipelines, vendored third-party code, and multi-build-system configurations. Avoid overfitting to a package type until the Package Profiler has higher confidence.

## High-risk inputs

- Cross-language boundary data (FFI calls, JNI, ctypes, cgo)
- Vendored dependency code and its version metadata
- Generated code from templates, parsers, or IDL compilers
- Multi-build-system configuration files and their interactions
- Shared library interfaces and ABI contracts

## Primary tools

- `rg` for FFI patterns: `extern`, `dlsym`, `ctypes`, `jni`, `cgo`, `unsafe`
- Semgrep for unsafe cross-language data passing, missing input validation at boundaries
- CodeQL for dataflow across language boundaries where supported
- Package vulnerability scanners for vendored dependency CVEs
- Safe local tests

## AI hypothesis focus

The hypothesis hunter should search for safety assumptions that traditional tools may miss:

- FFI boundary type mismatch (size, alignment, signedness across languages)
- Vendored dependency version staleness (known CVEs in old copies)
- Generated code injection via template or IDL manipulation
- Build-system configuration inconsistency causing different code paths
- ABI mismatch between shared library versions
- Memory ownership confusion at cross-language call boundaries

## Candidate priority

Prioritize candidates involving cross-language data passing, vendored code with known vulnerabilities, or generated code that bypasses normal safety checks.

## Recommended evidence

Every candidate must be grounded in real source path, function, line range, source-to-sink reasoning, and validation or a clear statement of missing validation.

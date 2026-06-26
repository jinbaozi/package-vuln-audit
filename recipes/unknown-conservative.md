# Recipe: unknown conservative

## Applies to

Fallback recipe when profiling is low confidence; uses safe, broad, low-assumption scanning only.

## First-pass scope

Start with external input handling, configuration parsing, file/path processing, boundary-crossing logic, and dependency manifests. Avoid overfitting to a package type until the Package Profiler has higher confidence.

## Recommended evidence

Every candidate must be grounded in real source path, function, line range, source-to-sink reasoning, and validation or a clear statement of missing validation.

## Default tools

Use available baseline tools from the inventory: `rg`, `git`, Semgrep, CodeQL where supported, package vulnerability scanners, and safe local tests.

# Recipe: privileged-tool

## Applies to

setuid, root-run, capability-bearing, service-managed, or installer/update tools.

## First-pass scope

Start with privilege boundaries, user-supplied input reaching privileged operations, environment handling, file/path operations with elevated permissions, and capability management. Avoid overfitting to a package type until the Package Profiler has higher confidence.

## High-risk inputs

- User-supplied file paths and directory names
- Environment variables inherited from unprivileged callers
- UID/GID values and identity assertions
- Capability sets and permission flags
- Configuration overrides from user-writable locations
- Command-line arguments controlling privileged operations
- Shared library loading paths

## Primary tools

- `rg` for privilege-specific patterns: `setuid`, `seteuid`, `setresuid`, `cap_set_proc`, `prctl`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `setenv`/`putenv` in privileged context, `access()` followed by `open()` (TOCTOU)
- Semgrep for missing privilege dropping, unsafe exec in privileged context
- CodeQL for dataflow from user input to privileged system calls
- Cppcheck and `gcc -fanalyzer` for C/C++ baseline issues

## AI hypothesis focus

The hypothesis hunter should search for safety assumptions that traditional tools may miss:

- TOCTOU races between permission checks and file operations (access-then-open)
- Symlink attacks on files created or read in world-writable directories
- Capability leakage after fork/exec (child inherits unintended capabilities)
- PATH hijacking when privileged tool shells out without absolute paths
- Environment variable injection (IFS, LD_PRELOAD, PYTHONPATH) in privileged context
- Failure to drop supplementary groups or clear environment after setuid
- Unsafe temporary file creation in shared directories
- Integer overflow in UID/GID comparisons (signed vs unsigned)

## Candidate priority

Prioritize candidates involving user-controlled input reaching privileged system calls, missing privilege boundary enforcement, or environment/capability inheritance issues.

## Recommended evidence

Every candidate must be grounded in real source path, function, line range, source-to-sink reasoning, and validation or a clear statement of missing validation.

# Recipe: cli-tool

## Applies to

Command-line utilities consuming files, options, environment variables, or stdin.

## First-pass scope

Start with external input handling, option/argument parsing, configuration file processing, file/path operations, and boundary-crossing logic. Avoid overfitting to a package type until the Package Profiler has higher confidence.

## High-risk inputs

- Command-line arguments and option values
- Environment variables used for configuration or paths
- Configuration file paths and their content
- stdin data and piped input
- Filenames and paths from user arguments
- Glob patterns and shell expansion results

## Primary tools

- `rg` for CLI patterns: `getopt`/`getopt_long` edge cases, `system()`/`popen()`/`exec*()` with user input, `getenv()` used in path construction, `fopen()` without path validation
- Semgrep for shell injection, unsafe exec, path traversal
- CodeQL for dataflow from arguments/environment to dangerous operations
- Package vulnerability scanners and safe local tests

## AI hypothesis focus

The hypothesis hunter should search for safety assumptions that traditional tools may miss:

- Option parsing confusion (--option=value injection, short-option bundling edge cases)
- Path traversal via user-supplied filenames or directory arguments
- Environment variable override changing behavior unexpectedly
- Shell metacharacter injection in arguments passed to system()/popen()
- Symlink following when processing user-specified paths
- Argument count or type confusion in variadic option handling
- Unsafe temporary file creation based on program name or PID

## Candidate priority

Prioritize candidates involving user-controlled arguments or environment variables reaching file operations, command execution, or privilege-sensitive decisions.

## Recommended evidence

Every candidate must be grounded in real source path, function, line range, source-to-sink reasoning, and validation or a clear statement of missing validation.

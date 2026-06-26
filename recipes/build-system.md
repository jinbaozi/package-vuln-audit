# Recipe: build-system

## Applies to

Build tools and configuration systems such as make, CMake, Ninja-like systems, configure scripts, and project-generation tools.

## High-risk inputs

- Build scripts and project files
- Environment variables
- Include/module paths
- Cache/state files
- Command-line options
- Generated files and temporary directories

## Important distinction

Executing commands from a build script is often intended behavior. Treat command execution as a vulnerability only when it violates documented semantics, runs in a supposedly safe/query mode, crosses an authorization boundary, or results from unsafe path/environment handling.

## AI hypothesis focus

- Unsafe search path precedence
- Environment variable confusion
- Unexpected side effects in query/dry-run modes
- Recursive expansion resource exhaustion
- Temporary file race or symlink issues
- Parser crashes on malformed project files

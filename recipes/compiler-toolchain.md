# Recipe: compiler-toolchain

## Applies to

Compilers, assemblers, linkers, optimizers, code generators, preprocessors, and toolchain utilities.

Examples: GCC, LLVM/Clang, Binutils `as`/`ld`, language frontends, optimization passes.

## High-risk inputs

- Source files and macro expansion
- Command-line options and response files
- Target architecture flags
- Linker scripts and object files
- Plugins and specs
- Intermediate representations and optimization metadata

## Primary tools

Use `rg`, Semgrep, CodeQL, Cppcheck, compiler analyzer warnings, sanitizer builds, regression tests, differential tests, and fuzzing where available.

## AI hypothesis focus

- Option combinations reaching rarely tested paths
- Incorrect assumptions in IR/AST transformations
- Parser or preprocessor state inconsistencies
- Temporary file and search-path handling
- Backend-specific boundary assumptions
- Miscompilation or crash under specific input/option combinations

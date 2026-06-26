# Recipe: library-parser

## Applies to

Reusable libraries that parse external formats, serialized data, configuration files, or user-supplied schemas.

## First-pass scope

Start with parsing entry points, format-specific handlers, memory management around parsed structures, error handling and recovery paths, and API boundary contracts. Avoid overfitting to a package type until the Package Profiler has higher confidence.

## High-risk inputs

- External format data (headers, fields, nested structures)
- Serialized objects and deserialization targets
- Configuration file content and include directives
- User-supplied schemas or format definitions
- Size/length/count fields controlling allocations
- Recursive or self-referential structures

## Primary tools

- `rg` for parser patterns: unchecked `malloc`/`realloc` with input-controlled sizes, recursive descent without depth limits, missing null checks after allocation
- Semgrep for dangerous deserialization, unsafe string operations, missing bounds checks
- CodeQL for dataflow from parsed input to memory operations
- Cppcheck and `gcc -fanalyzer` for C/C++ baseline issues
- ASan/UBSan for validation via malformed input

## AI hypothesis focus

The hypothesis hunter should search for safety assumptions that traditional tools may miss:

- Integer overflow in size/length fields controlling allocations
- Deep nesting or recursion causing stack overflow
- Ownership semantics confusion (who frees parsed structures on error)
- Post-partial-parse state inconsistency (fields populated, others not)
- Type confusion when format allows multiple interpretations of same data
- Buffer over-read when length field exceeds actual data available
- Use-after-free when parsed structures share references

## Candidate priority

Prioritize candidates involving attacker-controlled format fields that influence allocation size, copy length, recursion depth, type interpretation, or ownership transfer.

## Recommended evidence

Every candidate must be grounded in real source path, function, line range, source-to-sink reasoning, and validation or a clear statement of missing validation.

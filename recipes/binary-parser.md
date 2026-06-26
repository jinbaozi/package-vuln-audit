# Recipe: binary-parser

## Applies to

Packages that parse untrusted binary or structured file formats, including object files, archives, debug sections, image/audio/video codecs, compressed formats, and container formats.

Examples: GNU Binutils, libarchive, readelf-like tools, objdump-like tools, image parsers, audio parsers.

## High-risk inputs

- File headers and magic values
- Offset, size, length, count, and index fields
- Section/table relationships
- Symbol and string tables
- Relocation tables
- Archive members
- Debug sections such as DWARF/STABS/CTF/SFrame
- Compression metadata

## Primary tools

- `rg` for offset/size/count/index patterns
- Semgrep for dangerous APIs and common parser mistakes
- CodeQL for dataflow and range-check analysis
- Cppcheck and `gcc -fanalyzer` for C/C++ baseline issues
- ASan/UBSan for validation
- AFL++ or libFuzzer for malformed input testing

## AI hypothesis focus

The hypothesis hunter should search for safety assumptions that traditional tools may miss:

- `offset + size` does not overflow and remains inside the file
- Count fields match allocated table length
- Index fields reference an object of the expected type
- Parser state is not reused after an error
- Partial initialization does not lead to invalid cleanup
- Multiple parsers interpret the same malformed input consistently

## Candidate priority

Prioritize candidates involving attacker-controlled format fields that influence allocation size, pointer arithmetic, table indexing, copy length, cleanup ownership, or recursive parsing.

## Binutils starter profile

When the package resembles GNU Binutils, first-pass scope should include `binutils/readelf.c`, `binutils/objdump.c`, `binutils/nm.c`, `binutils/objcopy.c`, `bfd/`, `opcodes/`, and debug-section handling. Do not claim Binutils-specific issues without the actual source code and validation evidence.

## Binutils built-in example

Use this section when the package profile identifies GNU Binutils or a similar binary/object-file parser.

### High-risk components

- `binutils/readelf.c`: ELF, section, symbol, relocation, note, and debug dumping paths.
- `binutils/objdump.c`: object display, disassembly, relocation and debug display options.
- `bfd/`: object/archive format parsing, backend-specific ELF/COFF/etc. logic, ownership and cleanup paths.
- `opcodes/`: disassembler backends and instruction decoding assumptions.
- DWARF/debug section paths: offset, length, abbrev, line, loclist, rnglist and nested structure parsing.
- Archive paths: member size, offset, long-name tables, nested object handling.

### AI hypothesis prompts

Ask the `hypothesis-hunter` to look for:

- File-controlled offset + size overflow.
- Table-count or entry-size trust.
- Section-link and section-type inconsistency.
- Symbol/string/relocation table mismatch.
- Debug-section offset crossing section bounds.
- Partial initialization followed by cleanup/free.
- BFD arena allocation mixed with normal heap ownership.
- Disassembler buffer-length assumptions in architecture backends.

### Safe local validation examples

Validation examples are for authorized local reproduction/regression testing only.

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=1 \
timeout 10s build-asan/binutils/readelf -a testcase.elf
```

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=1 \
timeout 10s build-asan/binutils/objdump -D testcase.o
```

Do not claim a Binutils vulnerability without a real source location, a real malformed local testcase or fuzz reproducer, and validation output.

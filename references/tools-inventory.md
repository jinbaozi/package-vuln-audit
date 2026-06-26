# Traditional Tools Inventory

Tool output is evidence, not truth. Missing tools must not fail the workflow.

| Category | Tools | Purpose |
|---|---|---|
| Basic discovery | rg, grep, find, git | File inventory and source search |
| Rule scanning | Semgrep | Multi-language security patterns |
| Semantic analysis | CodeQL | Data-flow and variant analysis |
| CPG analysis | Joern | Code property graph slicing |
| C/C++ baseline | Cppcheck, gcc -fanalyzer, clang-tidy, scan-build | Static defects |
| Known vulnerabilities | OSV-Scanner | Dependency/CVE matching |
| SBOM/CVE | Syft, Grype, Trivy | SBOM and filesystem CVEs |
| Dynamic validation | ASan, UBSan | Runtime memory/UB validation |
| Fuzzing | AFL++, libFuzzer | Crash discovery and regression |
| Linux C specialty | Coccinelle, Smatch, Sparse | System C analysis |

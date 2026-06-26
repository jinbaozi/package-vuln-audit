# Expected pipeline behavior

- `profile_project.sh` should detect a C CLI/parser style project.
- `run_tools.sh` should produce at least one `rg` hit for `strcpy`.
- `normalize_results.py` should emit a `T-CAND` candidate.
- `rank_candidates.py` should rank the unsafe string copy candidate near the top.
- `make_ai_packets.py` should create a focused code packet containing the real source lines.
- `validate_candidate.sh` can run a local sanitizer or command-based check and store validation artifacts.

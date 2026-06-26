# /candidate-review

Review a single candidate packet.

Arguments:
- `candidate` path to `T-CAND-*`, `A-CAND-*`, or `F-CAND-*` markdown packet

Dispatch `candidate-reviewer`. It must return exactly one status: Reject, Candidate, Likely, Validated, Rejected, or Needs Manual Review. It must cite actual files, functions, line ranges, source-to-sink reasoning, and missing evidence. It must not read unrelated repository files unless the candidate packet explicitly permits them.

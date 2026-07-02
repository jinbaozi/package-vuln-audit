# Report Admission Rules

Raw Tool Hit, Candidate, Likely, and Rejected do not become formal findings. Validated and Needs Manual Review can enter final reports.

Validated findings require verified PoC/test artifacts with `poc-run-result.json` status = `passed`.

Needs Manual Review findings require both a manual validation plan and draft/unverified PoC/test artifacts with `poc-run-result.json` status = `passed`. The passed draft run is not validation evidence sufficient to mark the finding as verified, and reports must keep the item labeled for manual review.

# Bilingual Output

Run `tools/publish_bilingual_reports.py` to render `machine/` findings into `zh-CN/` and `en-US/`.

Then run `tools/validate_report_completeness.py` with `--check-language-isolation` to verify CJK prose separation.

The enforced driver uses `--report-root audit-output` (audit root). Standalone workflow examples may use `audit-output/06-report` when that directory is the report root.

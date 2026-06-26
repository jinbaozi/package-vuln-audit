# Finding {{id}}

## Summary
{{summary}}

## Root Cause
{{root_cause}}

## Source Code Evidence
- File: `{{file}}`
- Function: {{function}}
- Lines: {{start_line}}-{{end_line}}
{{#source_snippets}}
```text
{{snippet}}
```
{{/source_snippets}}

## Source-to-Sink Path
```text
{{source_to_sink_path}}
```

## Validation Evidence
{{validation_evidence}}

## CVSS
- Vector: {{cvss_vector}}
- Score: {{cvss_score}}
- Severity: {{cvss_severity}}

## Fix Recommendation
{{fix_recommendation}}

## PoC / Test Artifacts
{{#poc_artifacts}}
- `{{path}}` — {{purpose}} ({{type}}, {{safety_class}}){{#language}} [{{language}}]{{/language}}
{{/poc_artifacts}}
{{^poc_artifacts}}
_No PoC artifacts generated for this finding._
{{/poc_artifacts}}

## Discovery Method
{{#discovery_method}}
- **{{type}}**{{#tool_name}} (tool: `{{tool_name}}`){{/tool_name}}{{#hypothesis_id}} (hypothesis: `{{hypothesis_id}}`){{/hypothesis_id}}
  {{description}}
{{/discovery_method}}

## Public Vulnerability Correlation
- Disclosure status: {{disclosure_status}}
- Match level: {{match_level}}
{{#public_references}}
- {{source}} / {{id}}{{#url}} ({{url}}){{/url}}
{{/public_references}}
{{^public_references}}
- No public vulnerability records matched in configured sources.
{{/public_references}}

## Disclosure Level
{{disclosure_level}}

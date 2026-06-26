# Internal Security Report

## Executive Summary
{{executive_summary}}

## Validated Findings

| ID | Severity | CVSS | Component | Discovery | Disclosure |
|----|----------|------|-----------|-----------|------------|
{{#findings}}
| {{id}} | {{cvss_severity}} | {{cvss_score}} | {{component}} | {{#discovery_method}}{{type}}{{#tool_name}}({{tool_name}}){{/tool_name}}{{/discovery_method}} | {{disclosure_status}} |
{{/findings}}

## Finding Details
{{#findings}}
### {{id}}: {{title}}

**CVSS**: {{cvss_vector}} ({{cvss_score}}, {{cvss_severity}})
**Component**: {{component}}
**Disclosure Status**: {{disclosure_status}}
**Disclosure Level**: {{disclosure_level}}

**Discovery Method**:
{{#discovery_method}}
- {{type}}{{#tool_name}} via `{{tool_name}}`{{/tool_name}}: {{description}}
{{/discovery_method}}

**PoC Artifacts**:
{{#poc_artifacts}}
- `{{path}}` — {{purpose}}
{{/poc_artifacts}}
{{^poc_artifacts}}
- None generated.
{{/poc_artifacts}}

**Public References**:
{{#public_references}}
- {{source}} / {{id}}{{#url}} ({{url}}){{/url}}
{{/public_references}}
{{^public_references}}
- None matched.
{{/public_references}}

{{/findings}}

## Candidates
{{#candidates}}
- {{id}}: {{title}}
{{/candidates}}
{{^candidates}}
- No candidate items.
{{/candidates}}

## Rejected Summary
{{rejected_summary}}

## Public Disclosure Status and Standard Source Summary

| Finding ID | Disclosure Status | Match Level | Standard Source | Record ID | Evidence Summary | Limitations | Discovery Method |
|---|---|---|---|---|---|---|---|
{{#disclosure_rows}}
| {{finding_id}} | {{status}} | {{match_level}} | {{standard_sources}} | {{record_ids}} | {{evidence_summary}} | {{limitations}} | {{discovery_method_summary}} |
{{/disclosure_rows}}

## Tool Coverage
{{tool_coverage}}

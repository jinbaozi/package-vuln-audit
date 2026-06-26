# 内部安全报告

## 执行摘要
{{executive_summary}}

## 已验证发现

| ID | 严重性 | CVSS | 组件 | 发现方式 | 披露状态 |
|----|--------|------|------|----------|----------|
{{#findings}}
| {{id}} | {{cvss_severity}} | {{cvss_score}} | {{component}} | {{#discovery_method}}{{type}}{{#tool_name}}({{tool_name}}){{/tool_name}}{{/discovery_method}} | {{disclosure_status}} |
{{/findings}}

## 发现详情
{{#findings}}
### {{id}}：{{title}}

**CVSS**：{{cvss_vector}}（{{cvss_score}}，{{cvss_severity}}）
**组件**：{{component}}
**披露状态**：{{disclosure_status}}
**披露等级**：{{disclosure_level}}

**发现方式**：
{{#discovery_method}}
- {{type}}{{#tool_name}} via `{{tool_name}}`{{/tool_name}}：{{description}}
{{/discovery_method}}

**PoC 工件**：
{{#poc_artifacts}}
- `{{path}}` — {{purpose}}
{{/poc_artifacts}}
{{^poc_artifacts}}
- 未生成。
{{/poc_artifacts}}

**公开参考**：
{{#public_references}}
- {{source}} / {{id}}{{#url}}（{{url}}）{{/url}}
{{/public_references}}
{{^public_references}}
- 未匹配。
{{/public_references}}

{{/findings}}

## 候选问题
{{#candidates}}
- {{id}}：{{title}}
{{/candidates}}
{{^candidates}}
- 无候选项目。
{{/candidates}}

## 已拒绝问题摘要
{{rejected_summary}}

## 公开披露状态与标准来源汇总表

| Finding ID | 公开披露状态 | 匹配等级 | 标准来源 | 记录 ID | 证据摘要 | 限制说明 | 发现方法 |
|---|---|---|---|---|---|---|---|
{{#disclosure_rows}}
| {{finding_id}} | {{status}} | {{match_level}} | {{standard_sources}} | {{record_ids}} | {{evidence_summary}} | {{limitations}} | {{discovery_method_summary}} |
{{/disclosure_rows}}

## 工具覆盖
{{tool_coverage}}

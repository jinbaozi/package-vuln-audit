# 漏洞发现 {{id}}

## 摘要
{{summary}}

## 根因
{{root_cause}}

## 源代码证据
- 文件：`{{file}}`
- 函数：{{function}}
- 行号：{{start_line}}-{{end_line}}
{{#source_snippets}}
```text
{{snippet}}
```
{{/source_snippets}}

## 源到汇路径
```text
{{source_to_sink_path}}
```

## 验证证据
{{validation_evidence}}

## CVSS
- 向量：{{cvss_vector}}
- 分数：{{cvss_score}}
- 严重性：{{cvss_severity}}

## 修复建议
{{fix_recommendation}}

## PoC / 测试工件
{{#poc_artifacts}}
- `{{path}}` — {{purpose}}（{{type}}，{{safety_class}}）{{#language}}[{{language}}]{{/language}}
{{/poc_artifacts}}
{{^poc_artifacts}}
_此发现未生成 PoC 工件。_
{{/poc_artifacts}}

## 发现方式
{{#discovery_method}}
- **{{type}}**{{#tool_name}}（工具：`{{tool_name}}`）{{/tool_name}}{{#hypothesis_id}}（假设：`{{hypothesis_id}}`）{{/hypothesis_id}}
  {{description}}
{{/discovery_method}}

## 公开漏洞比对结果
- 公开披露状态：{{disclosure_status}}
- 匹配等级：{{match_level}}
{{#public_references}}
- {{source}} / {{id}}{{#url}}（{{url}}）{{/url}}
{{/public_references}}
{{^public_references}}
- 未在已配置公开数据源中发现匹配记录。
{{/public_references}}

## 披露等级
{{disclosure_level}}

#!/usr/bin/env python3
import json, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
SCHEMAS=ROOT/'schemas'
FIXTURES=ROOT/'tests'/'fixtures'

def load(p): return json.loads(p.read_text())
def smoke(schema, data):
    for key in schema.get('required',[]):
        assert key in data, f'missing required key {key}'

def main():
    mapping={
        'package-profile.schema.json':'sample-package-profile.json',
        'tool-summary.schema.json':'sample-tool-summary.json',
        'candidate.schema.json':'sample-candidate.json',
        'hypothesis.schema.json':'sample-hypothesis.json',
        'validation-result.schema.json':'sample-validation-result.json',
        'cvss.schema.json':'sample-cvss.json',
        'finding.schema.json':'sample-finding.json',
        'context-budget.schema.json':'sample-context-budget.json',
        'environment-check.schema.json':'sample-environment-check.json',
        'tool-install-plan.schema.json':'sample-tool-install-plan.json',
        'bilingual-output.schema.json':'sample-bilingual-output.json',
        'public-vuln-record.schema.json':'sample-public-vuln-record.json',
        'public-vuln-correlation.schema.json':'sample-public-vuln-correlation.json',
        'poc-testcase.schema.json':'sample-poc-testcase.json',
        'install-assistant-summary.schema.json':'sample-install-assistant-summary.json',
        'install-assistant-decision.schema.json':'sample-install-assistant-decision.json',
        'report.schema.json':'sample-report.json',
        'exception-index.schema.json':'sample-exception-index.json',
        'intake.schema.json':'sample-intake.json',
    }
    try:
        import jsonschema
        for s,f in mapping.items(): jsonschema.validate(load(FIXTURES/f), load(SCHEMAS/s))
    except ImportError:
        for s,f in mapping.items(): smoke(load(SCHEMAS/s), load(FIXTURES/f))
    print('schema tests passed')
if __name__=='__main__': main()

#!/usr/bin/env python3
import json, pathlib, subprocess, tempfile, sys, os
ROOT = pathlib.Path(__file__).resolve().parents[1]



def test_generate_install_plan_prefers_user_local_methods():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        env = td / 'environment-check.json'
        env.write_text(json.dumps({
            'tools': [
                {'name': 'semgrep', 'status': 'missing', 'impact': 'Semgrep unavailable.', 'install_hint_id': 'semgrep'},
                {'name': 'osv-scanner', 'status': 'missing', 'impact': 'OSV unavailable.', 'install_hint_id': 'osv-scanner'},
            ]
        }))
        out = td / 'out'
        subprocess.check_call([sys.executable, str(ROOT / 'tools' / 'generate_install_plan.py'), '--environment-check', str(env), '--out', str(out)])
        plan = json.loads((out / 'tool-install-plan.json').read_text())
        md = (out / 'tool-install-plan.md').read_text()
        assert plan['status'] == 'install-plan-generated'
        assert plan['install_policy']['auto_install_default'] is False
        assert 'python-pipx' in plan['install_policy']['preferred_methods']
        assert 'pipx install semgrep' in md
        assert '.pvas/tools/bin/osv-scanner' in md
        assert 'sudo' in plan['install_policy']['forbidden_by_default']



if __name__ == '__main__':
    test_generate_install_plan_prefers_user_local_methods()
    print('tool install plan tests passed', flush=True)

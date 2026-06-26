#!/usr/bin/env python3
import json, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_install_assistant_dry_run_and_prefix_guard():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        out = td / 'out'
        p = subprocess.run([sys.executable, str(ROOT/'tools'/'install_assistant.py'), '--tool', 'semgrep', '--mode', 'strict', '--dry-run', '--prefix', '.pvas/tools', '--allowed-root', str(td), '--out', str(out)], cwd=td, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 0, p.stderr + p.stdout
        summary = json.loads((out/'install-assistant-summary.json').read_text())
        decision = json.loads((out/'install-assistant-decision.json').read_text())
        assert summary['dry_run'] is True
        assert summary['prefix_escape_check'] == 'passed'
        assert decision['decision'] == 'dry-run-only'


def test_install_assistant_rejects_prefix_escape():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        out = td / 'out'
        p = subprocess.run([sys.executable, str(ROOT/'tools'/'install_assistant.py'), '--tool', 'semgrep', '--mode', 'strict', '--dry-run', '--prefix', '../escape', '--allowed-root', str(td), '--out', str(out)], cwd=td, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 0, p.stderr + p.stdout
        summary = json.loads((out/'install-assistant-summary.json').read_text())
        assert summary['prefix_escape_check'] == 'failed'
        assert any('prefix escape' in x for x in summary['failure_summary'])


def test_install_assistant_offline_bundle_user_prefix_install():
    import hashlib
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bundle = td / 'offline-bundle'
        (bundle / 'binaries').mkdir(parents=True)
        rg = bundle / 'binaries' / 'rg'
        rg.write_text('#!/usr/bin/env sh\necho ripgrep 0.0-test\n')
        rg.chmod(0o755)
        digest = hashlib.sha256(rg.read_bytes()).hexdigest()
        (bundle / 'install-manifest.json').write_text(json.dumps({'tools': {'rg': {'path': 'binaries/rg', 'sha256': digest}}}))
        out = td / 'out'
        p = subprocess.run([sys.executable, str(ROOT/'tools'/'install_assistant.py'), '--tool', 'rg', '--mode', 'strict', '--network-mode', 'offline', '--prefix', '.pvas/tools', '--allowed-root', str(td), '--offline-bundle', str(bundle), '--authorize-tool', 'rg', '--execute', '--out', str(out)], cwd=td, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 0, p.stderr + p.stdout
        summary = json.loads((out/'install-assistant-summary.json').read_text())
        assert summary['offline_bundle']['hash_verified'] is True
        assert summary['tools'][0]['execution'] == 'installed-from-offline-bundle-user-prefix'
        assert (td/'.pvas/tools/bin/rg').exists()


if __name__ == '__main__':
    test_install_assistant_dry_run_and_prefix_guard()
    test_install_assistant_rejects_prefix_escape()
    test_install_assistant_offline_bundle_user_prefix_install()
    print('install assistant tests passed')

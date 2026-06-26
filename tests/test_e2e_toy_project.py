#!/usr/bin/env python3
import os
import json, pathlib, shutil, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / 'examples' / 'toy-cpkg'

def main():
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / 'audit-output'
        subprocess.run([str(SRC / 'run-audit-demo.sh'), str(out)], cwd=str(ROOT), check=True)
        profile = json.loads((out / '01-profile' / 'package-profile.json').read_text())
        assert 'binary-parser' in profile['profiles'] or 'cli-tool' in profile['profiles']
        raw = json.loads((out / '03-candidates' / 'raw-candidates.json').read_text())
        assert raw['candidates'], 'expected at least one candidate from toy project'
        ranked = json.loads((out / '03-candidates' / 'ranked-candidates.json').read_text())
        assert ranked['candidates'], 'expected ranked candidates'
        idx = json.loads((out / '03-candidates' / 'packets' / 'packet-index.json').read_text())
        assert idx['packets'], 'expected AI audit packets'
        first_packet = idx['packets'][0]; packet_path = first_packet['file'] if isinstance(first_packet, dict) else first_packet; packet_text = pathlib.Path(packet_path).read_text()
        assert 'Code Slice' in packet_text
        summary = json.loads((out / 'summary.json').read_text())
        assert summary['profiles'] and summary['candidate_files']
    print('e2e toy project test passed', flush=True)
    os._exit(0)

if __name__ == '__main__':
    main()

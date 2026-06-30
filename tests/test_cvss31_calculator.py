#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'cvss31_calculator.py'

GOLDEN = [
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'Critical'),
    ('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9, 'Critical'),
    ('CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:H', 4.2, 'Medium'),
    ('CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', 4.2, 'Medium'),
    ('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L', 3.5, 'Low'),
    ('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0, 'None'),
]


def run_vector(vector: str) -> dict:
    p = subprocess.run(
        [sys.executable, str(TOOL), '--vector', vector],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    return json.loads(p.stdout)


def main():
    for vector, score, sev in GOLDEN:
        out = run_vector(vector)
        assert out['base_score'] == score, (vector, out)
        assert out['severity'] == sev, (vector, out)
    p = subprocess.run(
        [sys.executable, str(TOOL), '--vector', 'CVSS:3.1/AV:INVALID'],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert p.returncode != 0
    print('cvss31 calculator tests passed')


if __name__ == '__main__':
    main()

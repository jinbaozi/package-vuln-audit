#!/usr/bin/env python3
"""Unified PVAS test harness (subprocess + runpy + fixtures)."""
from __future__ import annotations

import json
import os
import pathlib
import runpy
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = str((ROOT / 'tools').resolve())
FIXTURES = ROOT / 'tests' / 'fixtures'


def run_tool(rel, args):
    old = sys.argv[:]
    old_path = sys.path[:]
    old_sandbox = os.environ.get('PVAS_SANDBOX')
    if rel == 'tools/generate_poc_testcase.py' and old_sandbox is None:
        os.environ['PVAS_SANDBOX'] = 'disabled'
    if TOOLS not in sys.path:
        sys.path.insert(0, TOOLS)
    sys.argv = [str(ROOT / rel)] + list(map(str, args))
    try:
        try:
            runpy.run_path(str(ROOT / rel), run_name='__main__')
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 0
            if code not in (0, None):
                raise AssertionError(f'{rel} exited with {code}')
    finally:
        sys.argv = old
        sys.path[:] = old_path
        if old_sandbox is None:
            os.environ.pop('PVAS_SANDBOX', None)
        else:
            os.environ['PVAS_SANDBOX'] = old_sandbox


def run_subprocess(rel, args=None, *, check=True, cwd=None):
    cmd = [sys.executable, str(ROOT / rel)] + list(map(str, args or []))
    return subprocess.run(cmd, check=check, text=True, capture_output=True, cwd=cwd or ROOT)


def temp_audit_dir():
    return tempfile.TemporaryDirectory(prefix='pvas-test-')


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def minimal_finding(**overrides) -> dict:
    finding = load_fixture('sample-finding.json')
    finding.update(overrides)
    return finding

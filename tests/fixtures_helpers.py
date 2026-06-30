#!/usr/bin/env python3
"""Shared test harness helpers for PVAS standalone test scripts."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures'


def run_subprocess(rel: str, args: list | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(ROOT / rel)] + list(map(str, args or []))
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


def temp_audit_dir():
    return tempfile.TemporaryDirectory(prefix='pvas-test-')


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def minimal_finding(**overrides) -> dict:
    finding = load_fixture('sample-finding.json')
    finding.update(overrides)
    return finding

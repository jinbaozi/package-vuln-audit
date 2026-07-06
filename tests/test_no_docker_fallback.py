#!/usr/bin/env python3
"""Strict environment gate blocks when no Docker/Podman sandbox backend exists."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_verify(*args):
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / "env"
        env = os.environ.copy()
        env["PATH"] = ""
        p = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "verify_environment.py"), *args, "--out", str(out), "--json-only"],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return p.returncode, json.loads((out / "environment-check.json").read_text())


def test_strict_blocks_missing_sandbox_backend():
    rc, data = run_verify("--profile", "minimal", "--mode", "strict", "--required-tools", "")
    assert data["sandbox_backend"]["status"] == "missing"
    assert "sandbox-backend" in data["blocking_missing_tools"]
    assert data["decision"] == "block"
    assert rc == 2


def test_allow_degraded_continues_with_missing_sandbox_backend():
    rc, data = run_verify("--profile", "minimal", "--mode", "strict", "--allow-degraded", "--required-tools", "")
    assert data["sandbox_backend"]["status"] == "missing"
    assert data["decision"] == "continue-degraded"
    assert rc == 0


if __name__ == "__main__":
    test_strict_blocks_missing_sandbox_backend()
    test_allow_degraded_continues_with_missing_sandbox_backend()
    print("no docker fallback tests passed")

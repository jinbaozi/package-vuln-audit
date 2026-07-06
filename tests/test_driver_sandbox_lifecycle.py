#!/usr/bin/env python3
"""Tests for enforced_audit_driver sandbox runtime lifecycle helpers."""
import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import enforced_audit_driver as driver  # noqa: E402
import pvas_container  # noqa: E402


def test_initialize_sandbox_runtime_records_unavailable_backend():
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / "audit"
        old_detect = driver.pvas_container.detect_backend
        old_audit = os.environ.get("PVAS_AUDIT_ID")
        old_sandbox = os.environ.get("PVAS_SANDBOX")
        os.environ.pop("PVAS_AUDIT_ID", None)
        os.environ.pop("PVAS_SANDBOX", None)

        def fake_detect():
            raise pvas_container.SandboxUnavailable("fixture no backend")

        driver.pvas_container.detect_backend = fake_detect
        try:
            state = driver.initialize_sandbox_runtime(out)
        finally:
            driver.pvas_container.detect_backend = old_detect
            if old_audit is None:
                os.environ.pop("PVAS_AUDIT_ID", None)
            else:
                os.environ["PVAS_AUDIT_ID"] = old_audit
            if old_sandbox is None:
                os.environ.pop("PVAS_SANDBOX", None)
            else:
                os.environ["PVAS_SANDBOX"] = old_sandbox

        saved = json.loads((out / "machine/sandbox-runtime.json").read_text())
        assert state["status"] == "unavailable"
        assert saved["audit_id"].startswith("pvas-")
        assert saved["error"] == "fixture no backend"


def test_sandbox_cleanup_flushes_netpolicy_and_prompts_cleanup():
    calls = []
    old_flush = driver.pvas_netpolicy.flush_all
    old_prompt = driver.pvas_image.prompt_cleanup

    def fake_flush():
        calls.append("flush")

    def fake_prompt(audit_id, backend, log_path=None):
        calls.append((audit_id, backend, str(log_path)))

    driver.pvas_netpolicy.flush_all = fake_flush
    driver.pvas_image.prompt_cleanup = fake_prompt
    try:
        driver._sandbox_cleanup("audit-1", "docker", pathlib.Path("/tmp/pvas-test-out"))
    finally:
        driver.pvas_netpolicy.flush_all = old_flush
        driver.pvas_image.prompt_cleanup = old_prompt

    assert calls[0] == "flush"
    assert calls[1][0] == "audit-1"
    assert calls[1][1] == "docker"


if __name__ == "__main__":
    test_initialize_sandbox_runtime_records_unavailable_backend()
    test_sandbox_cleanup_flushes_netpolicy_and_prompts_cleanup()
    print("driver sandbox lifecycle tests passed")

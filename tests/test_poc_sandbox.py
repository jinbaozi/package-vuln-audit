#!/usr/bin/env python3
"""Verify generated PoC reproducers execute through pvas_container by default."""
import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import generate_poc_testcase as poc  # noqa: E402
import pvas_container  # noqa: E402


def test_run_multilang_reproducer_uses_bridge_deny_container():
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td) / "FINDING-777"
        d.mkdir()
        script = d / "reproduce.sh"
        script.write_text("#!/usr/bin/env bash\nexit 0\n")
        script.chmod(0o755)
        seen = {}
        old_run = poc.pvas_container.run
        old_sandbox = os.environ.get("PVAS_SANDBOX")
        os.environ.pop("PVAS_SANDBOX", None)

        def fake_run(spec):
            seen["spec"] = spec
            return pvas_container.ContainerResult(
                exit_code=0,
                stdout="ok",
                stderr="",
                duration_seconds=0.02,
                container_id="abc123def456",
                oom_killed=False,
                timed_out=False,
                netpolicy_id="pvas-poc-test",
            )

        poc.pvas_container.run = fake_run
        try:
            result = poc.run_multilang_reproducer(d, timeout_seconds=3)
        finally:
            poc.pvas_container.run = old_run
            if old_sandbox is None:
                os.environ.pop("PVAS_SANDBOX", None)
            else:
                os.environ["PVAS_SANDBOX"] = old_sandbox

        spec = seen["spec"]
        assert spec.network_policy == "bridge-deny"
        assert spec.labels["pvas-purpose"] == "poc"
        assert spec.labels["pvas-finding-id"] == "FINDING-777"
        assert result["status"] == "passed"
        assert result["executed_via"] == "container"
        assert result["container"]["network_policy"] == "bridge-deny"
        saved = json.loads((d / "poc-run-result.json").read_text())
        assert saved["container"]["netpolicy_id"] == "pvas-poc-test"


if __name__ == "__main__":
    test_run_multilang_reproducer_uses_bridge_deny_container()
    print("poc sandbox tests passed")

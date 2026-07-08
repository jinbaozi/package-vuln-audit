from __future__ import annotations

import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import context_budget
import generate_tool_matrix
import profile_manifest
import pvas_container
import run_tool_matrix as rtm
import tool_matrix_hardening


def test_context_budget_blocking_decision_returns_nonzero(tmp_path):
    profile_dir = tmp_path / "profile"
    packet_dir = tmp_path / "packets"
    profile_dir.mkdir()
    packet_dir.mkdir()
    (packet_dir / "packet-index.json").write_text(json.dumps({"coverage_complete": False}))

    budget = context_budget.build_budget(profile_dir, packet_dir)

    assert budget["decision"] == "blocked"
    assert "packet-index coverage_complete=false" in budget.get("issues", [])


def test_semgrep_restricted_without_local_rules_does_not_use_remote_pack(monkeypatch):
    monkeypatch.setattr(generate_tool_matrix, "local_semgrep_config", lambda: None)
    profile = {
        "package_name": "tiny-c",
        "source_root": ".",
        "primary_language": ["C"],
        "build_system": ["make"],
        "build_files": ["Makefile"],
    }

    matrix = generate_tool_matrix.build_matrix(
        profile,
        "standard",
        "600s",
        1,
        network_policy="restricted",
        allow_network=False,
    )
    semgrep = next(tool for tool in matrix["tools"] if tool["name"] == "semgrep")

    assert "p/c" not in semgrep["command"]
    assert "auto" not in semgrep["command"]
    assert semgrep["network_required"] is False


def test_semgrep_remote_config_detection():
    assert tool_matrix_hardening.semgrep_config_requires_network(["semgrep", "scan", "--config", "p/c", "."])
    assert tool_matrix_hardening.semgrep_config_requires_network(["semgrep", "scan", "--config", "auto", "."])
    assert tool_matrix_hardening.semgrep_config_requires_network(["semgrep", "scan", "--config", "https://example.invalid/r.yml", "."])
    assert not tool_matrix_hardening.semgrep_config_requires_network(["semgrep", "scan", "--config", "rules/semgrep", "."])


def test_pvas_container_blocks_netpolicy_failure_by_default(monkeypatch):
    monkeypatch.delenv("PVAS_ALLOW_NETPOLICY_DEGRADED", raising=False)
    monkeypatch.setattr(pvas_container, "detect_backend", lambda: "docker")

    def raise_netpolicy(_spec):
        raise pvas_container.NetworkPolicyApplyFailed("iptables unavailable")

    monkeypatch.setattr(pvas_container, "_apply_network_policy", raise_netpolicy)

    def should_not_run(*_args, **_kwargs):
        raise AssertionError("container command must not run when netpolicy fails")

    monkeypatch.setattr(pvas_container, "_run_with_subprocess", should_not_run)
    spec = pvas_container.ContainerSpec(
        image="image",
        command=["true"],
        mounts=[],
        network_policy="bridge-deny",
    )

    try:
        pvas_container.run(spec)
    except pvas_container.NetworkPolicyApplyFailed:
        pass
    else:
        raise AssertionError("expected NetworkPolicyApplyFailed")


def test_pvas_container_allows_explicit_netpolicy_degraded(monkeypatch):
    monkeypatch.setenv("PVAS_ALLOW_NETPOLICY_DEGRADED", "1")
    monkeypatch.setattr(pvas_container, "detect_backend", lambda: "docker")
    monkeypatch.setattr(
        pvas_container,
        "_apply_network_policy",
        lambda _spec: (_ for _ in ()).throw(pvas_container.NetworkPolicyApplyFailed("iptables unavailable")),
    )
    monkeypatch.setattr(pvas_container, "_build_docker_args", lambda _spec, _backend: ["docker", "run", "image", "true"])
    monkeypatch.setattr(pvas_container, "_run_with_subprocess", lambda _args, _spec: (0, "", "", False, ""))

    spec = pvas_container.ContainerSpec(
        image="image",
        command=["true"],
        mounts=[],
        network_policy="bridge-deny",
    )
    result = pvas_container.run(spec)

    assert result.exit_code == 0
    assert result.netpolicy_id == "degraded-no-netpolicy"
    assert result.executed_via == "host-degraded-network-policy"


def test_hardened_watchdog_applies_hard_timeout_to_blocking_tools(tmp_path):
    output = tmp_path / "tool.out"
    tool = {
        "name": "fake-required-tool",
        "applicability": "recommended",
        "timeout": "0.2s",
        "watchdog": {"hard_timeout": "0.6s"},
    }
    started = time.monotonic()
    rc, elapsed_ms, events, reason = tool_matrix_hardening.hardened_run_with_watchdog(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        {},
        output,
        tool,
        runtime=rtm,
    )
    elapsed = time.monotonic() - started

    assert rc is None
    assert reason == "hard-limit"
    assert elapsed < 3
    assert any(event.get("event") == "hard-limit" for event in events)
    assert elapsed_ms >= 0


def test_profile_manifest_records_node_lockfiles(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    package_json = src / "package.json"
    package_lock = src / "package-lock.json"
    index_ts = src / "index.ts"
    package_json.write_text('{"name":"demo"}')
    package_lock.write_text('{"lockfileVersion":3}')
    index_ts.write_text('console.log("demo")')
    out = tmp_path / "out"
    out.mkdir()

    all_files = [str(package_json), str(package_lock), str(index_ts)]
    source, build, large = profile_manifest.classify_source_files(all_files, 100, 1024 * 1024)
    profile_manifest.write_generic_profile(src, out, source, build)
    profile = json.loads((out / "package-profile.json").read_text())

    assert large == 0
    assert str(package_lock) in profile["lockfiles"]
    assert str(package_json) in profile["dependency_manifests"]
    assert "npm" in profile["package_ecosystems"]
    assert "JavaScript/TypeScript" in profile["primary_language"]

    applicability, _evidence, _allow_degraded = generate_tool_matrix.tool_applicability(
        "npm", profile, "standard"
    )
    assert applicability != "not-applicable"

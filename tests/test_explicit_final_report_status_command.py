from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import generate_final_report_with_status


def test_parse_known_report_args_preserves_generate_final_report_contract():
    args = generate_final_report_with_status.parse_known_report_args([
        "--audit-root", "audit-out",
        "--findings", "audit-out/05-findings/finding-index.json",
        "--correlation", "audit-out/machine/correlation/public-vuln-correlation.json",
        "--out", "audit-out/06-report",
    ])

    assert args.audit_root == "audit-out"
    assert args.findings.endswith("finding-index.json")
    assert args.correlation.endswith("public-vuln-correlation.json")
    assert args.out == "audit-out/06-report"


def test_main_invokes_report_generator_then_status_postprocess(monkeypatch, tmp_path):
    calls = []

    def fake_generate_main():
        calls.append(("generate", None))
        return 0

    def fake_postprocess_final_report(**kwargs):
        calls.append(("postprocess", kwargs))
        return {"report_type": "complete-audit-report", "negative_conclusion_allowed": True}

    monkeypatch.setattr(generate_final_report_with_status.generate_final_report, "main", fake_generate_main)
    monkeypatch.setattr(
        generate_final_report_with_status.report_status,
        "postprocess_final_report",
        fake_postprocess_final_report,
    )
    monkeypatch.setattr(sys, "argv", [
        "generate_final_report_with_status.py",
        "--audit-root", str(tmp_path / "audit"),
        "--findings", str(tmp_path / "audit/05-findings/finding-index.json"),
        "--correlation", str(tmp_path / "audit/machine/correlation/public-vuln-correlation.json"),
        "--out", str(tmp_path / "audit/06-report"),
    ])

    rc = generate_final_report_with_status.main()

    assert rc == 0
    assert calls[0][0] == "generate"
    assert calls[1][0] == "postprocess"
    assert calls[1][1]["audit_root"] == tmp_path / "audit"
    assert calls[1][1]["out_root"] == tmp_path / "audit/06-report"
    assert calls[1][1]["findings_path"] == tmp_path / "audit/05-findings/finding-index.json"
    assert calls[1][1]["correlation_path"] == tmp_path / "audit/machine/correlation/public-vuln-correlation.json"


def test_main_skips_postprocess_when_report_generation_fails(monkeypatch):
    calls = []

    monkeypatch.setattr(generate_final_report_with_status.generate_final_report, "main", lambda: 2)
    monkeypatch.setattr(
        generate_final_report_with_status.report_status,
        "postprocess_final_report",
        lambda **_kwargs: calls.append("postprocess"),
    )
    monkeypatch.setattr(sys, "argv", ["generate_final_report_with_status.py"])

    rc = generate_final_report_with_status.main()

    assert rc == 2
    assert calls == []

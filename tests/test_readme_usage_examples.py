#!/usr/bin/env python3
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text()


def section(title: str) -> str:
    pattern = rf"### {re.escape(title)}\n(.*?)(?=\n### |\n## |\Z)"
    match = re.search(pattern, README, re.S)
    assert match, f"missing README section {title}"
    return match.group(1)


def test_readme_has_current_adapter_install_examples():
    assert "install/install.sh --target /path/to/repo --platform claude-code --mode copy --force" in README
    assert "install/install.sh --target /path/to/repo --platform opencode --mode copy --force" in README
    assert "install/install.sh --target /path/to/repo --platform codex --mode copy --force" in README


def test_claude_code_examples_match_adapter_commands():
    text = section("2.1 Claude Code")
    for command in ["/package-vuln-audit", "/package-profile", "/hypothesis-hunt", "/candidate-review", "/validate"]:
        assert command in text
        assert (ROOT / "adapters" / "claude-code" / "commands" / f"{command[1:]}.md").is_file()


def test_opencode_examples_match_adapter_commands():
    text = section("2.2 opencode")
    for command in ["/package-vuln-audit", "/package-profile", "/hypothesis-hunt", "/candidate-review", "/validate"]:
        assert command in text
        assert (ROOT / "adapters" / "opencode" / "commands" / f"{command[1:]}.md").is_file()


def test_codex_example_uses_supported_instruction_entrypoints():
    text = section("2.3 Codex")
    assert "AGENTS.md" in text
    assert ".codex/skills/package-vuln-audit/" in text
    assert "tools/enforced_audit_driver.py --source . --out audit-output" in text


def test_platform_sections_reference_canonical_prompt():
    for title in ["2.1 Claude Code", "2.2 opencode", "2.3 Codex"]:
        text = section(title)
        assert (
            "2.4 推荐提示词" in text or "跨平台通用推荐提示词" in text
        ), f"{title} should point to the canonical audit prompt"
        assert "canonical prompt" in text or "通用提示词" in text


def test_canonical_prompt_contains_cross_platform_requirements():
    text = section("2.4 跨平台通用推荐提示词")
    assert "可复制通用提示词" in text
    for required in ["Claude Code", "opencode", "Codex"]:
        assert required in text
    for required in [
        "source_path=.",
        "output_dir=audit-output",
        "workflow_preset=strict-efficient",
        "max_candidates=20",
        "tools/enforced_audit_driver.py",
        "strict-efficient",
        "strict-degraded",
        "compat-default",
        "--workflow-preset",
        "--no-startup-prompt",
        "audit-output",
        "cwd",
        "summary-only",
        "PVAS_CONTEXT_EFFICIENT=1",
        "不是降级",
        "PVAS_PACKET_STRICT_BUDGET=1",
        "拆包",
        "阻断",
        "Candidate",
        "Likely",
        "Validated",
        "源码证据",
        "验证证据",
        "误报排除",
        "CVSS",
        "公开漏洞关联",
    ]:
        assert required in text


def test_adapter_installs_embed_recommended_complete_audit_prompt():
    for adapter in ["claude-code", "opencode", "codex"]:
        text = (ROOT / "adapters" / adapter / "INSTALL.md").read_text()
        assert "Recommended complete-audit prompt" in text
        assert "workflow_preset=strict-efficient" in text
        for required in [
            "source_path=.",
            "output_dir=audit-output",
            "max_candidates=20",
            "tools/enforced_audit_driver.py",
            "summary-only",
            "Candidate",
            "Likely",
            "Validated",
            "CVSS",
            "公开漏洞关联",
        ]:
            assert required in text, f"{adapter} INSTALL.md missing {required}"


def test_complete_audit_command_templates_document_workflow_preset():
    for path in [
        ROOT / "adapters" / "claude-code" / "commands" / "package-vuln-audit.md",
        ROOT / "adapters" / "opencode" / "commands" / "package-vuln-audit.md",
    ]:
        text = path.read_text()
        assert "workflow_preset" in text
        assert "strict-efficient" in text
        assert "canonical prompt" in text or "README 2.4" in text


def test_codex_adapter_docs_reference_canonical_strict_efficient_prompt():
    for path in [
        ROOT / "adapters" / "codex" / "AGENTS.md",
        ROOT / "adapters" / "codex" / "skills" / "package-vuln-audit" / "SKILL.md",
    ]:
        text = path.read_text()
        assert "strict-efficient" in text
        assert "README 2.4" in text
        assert "workflow_preset=strict-efficient" in text
        assert "summary-only" in text


def test_context_efficient_mode_documented_as_default_summary_only_semantics():
    text = section("2.4 跨平台通用推荐提示词")
    assert "项目默认完整 workflow 采用 `strict-efficient`" in text
    assert "交互式 TTY" in text
    assert "CI、脚本和 agent 非交互调用不会阻塞" in text
    assert "上下文高效是完整审计默认语义" in text
    assert "strict packet budget 默认开启" in text


def test_no_stale_validate_finding_command_in_docs():
    docs = [
        ROOT / "README.md",
        ROOT / "adapters" / "claude-code" / "INSTALL.md",
        ROOT / "adapters" / "opencode" / "INSTALL.md",
        ROOT / "adapters" / "codex" / "INSTALL.md",
    ]
    for path in docs:
        assert "validate-finding" not in path.read_text(), f"stale command in {path}"


if __name__ == "__main__":
    test_readme_has_current_adapter_install_examples()
    test_claude_code_examples_match_adapter_commands()
    test_opencode_examples_match_adapter_commands()
    test_codex_example_uses_supported_instruction_entrypoints()
    test_platform_sections_reference_canonical_prompt()
    test_canonical_prompt_contains_cross_platform_requirements()
    test_adapter_installs_embed_recommended_complete_audit_prompt()
    test_complete_audit_command_templates_document_workflow_preset()
    test_codex_adapter_docs_reference_canonical_strict_efficient_prompt()
    test_context_efficient_mode_documented_as_default_summary_only_semantics()
    test_no_stale_validate_finding_command_in_docs()
    print("readme usage example tests passed")

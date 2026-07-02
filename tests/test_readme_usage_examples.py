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
    test_no_stale_validate_finding_command_in_docs()
    print("readme usage example tests passed")

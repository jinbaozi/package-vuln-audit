#!/usr/bin/env python3
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_driver_generates_tool_matrix_before_running_tools():
    text = (ROOT / "tools" / "enforced_audit_driver.py").read_text()
    assert "tools/generate_tool_matrix.py" in text
    assert "required-tools-matrix.json" in text
    assert "tools/run_tools.sh" in text


def test_driver_uses_validation_poc_path():
    text = (ROOT / "tools" / "enforced_audit_driver.py").read_text()
    assert "04-validation" in text
    assert "poc-tests" in text
    assert "machine' / 'poc-tests" not in text


def test_driver_blocks_failed_poc_validation():
    text = (ROOT / "tools" / "enforced_audit_driver.py").read_text()
    assert "poc validation failed" in text
    assert "return poc_v_rc" in text or "return 2" in text


if __name__ == "__main__":
    test_driver_generates_tool_matrix_before_running_tools()
    test_driver_uses_validation_poc_path()
    test_driver_blocks_failed_poc_validation()
    print("driver workflow gate tests passed")

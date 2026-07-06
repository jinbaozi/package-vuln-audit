#!/usr/bin/env python3
"""Ensure run-tests.sh stays in sync with committed plain-Python tests."""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'run-tests.sh'
TESTS = ROOT / 'tests'

INTEGRATION_GATED = {
    'tests/test_binutils_helpers.py',
    'tests/test_e2e_toy_project.py',
    'tests/test_install_scripts.py',
}


def runner_test_paths() -> set[str]:
    text = RUNNER.read_text()
    return set(re.findall(r'(?:python3|timeout\s+\d+s\s+python3)\s+-u\s+(tests/test_[A-Za-z0-9_]+\.py)', text))


def test_run_tests_sh_lists_default_test_files():
    expected = {
        str(path.relative_to(ROOT))
        for path in TESTS.glob('test_*.py')
        if str(path.relative_to(ROOT)) not in INTEGRATION_GATED
    }
    listed = runner_test_paths()
    missing = sorted(expected - listed)
    unknown = sorted(listed - expected - INTEGRATION_GATED)
    assert not missing, f'missing default tests from run-tests.sh: {missing}'
    assert not unknown, f'run-tests.sh lists unknown test files: {unknown}'


def test_integration_gated_tests_are_explicitly_listed():
    listed = runner_test_paths()
    missing = sorted(INTEGRATION_GATED - listed)
    assert not missing, f'missing PVAS_RUN_INTEGRATION tests from run-tests.sh: {missing}'


if __name__ == '__main__':
    test_run_tests_sh_lists_default_test_files()
    test_integration_gated_tests_are_explicitly_listed()
    print('test inventory checks passed')

#!/usr/bin/env python3
"""Verify sandbox/ directory layout and .gitattributes exist."""
import pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

def test_sandbox_subdirs_exist():
    for sub in ['rootfs', 'images', 'netpolicy', 'scripts']:
        d = ROOT / 'sandbox' / sub
        assert d.is_dir(), f'missing {d}'

def test_sandbox_readme_exists():
    readme = ROOT / 'sandbox' / 'README.md'
    assert readme.is_file(), f'missing {readme}'
    text = readme.read_text()
    assert 'pvas_image' in text or 'sandbox' in text.lower()

def test_gitattributes_declares_lfs():
    attrs = ROOT / '.gitattributes'
    assert attrs.is_file(), f'missing {attrs}'
    text = attrs.read_text()
    assert '*.tar' in text and 'lfs' in text, '*.tar not tracked by lfs'

if __name__ == '__main__':
    test_sandbox_subdirs_exist()
    test_sandbox_readme_exists()
    test_gitattributes_declares_lfs()
    print('sandbox_layout tests passed')
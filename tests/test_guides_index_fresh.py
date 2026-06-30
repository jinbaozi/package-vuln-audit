#!/usr/bin/env python3
import difflib
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
INDEX = ROOT / 'guides' / 'index.json'


def test_guides_index_matches_generator():
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / 'index.json'
        subprocess.check_call(
            [sys.executable, str(ROOT / 'tools' / 'generate_guides_index.py'), '--out', str(out)],
            cwd=ROOT,
        )
        committed = INDEX.read_text()
        generated = out.read_text()
        if committed != generated:
            diff = ''.join(difflib.unified_diff(
                committed.splitlines(keepends=True),
                generated.splitlines(keepends=True),
                fromfile='guides/index.json',
                tofile='generated',
            ))
            raise AssertionError(f'guides/index.json drift:\n{diff}')


if __name__ == '__main__':
    test_guides_index_matches_generator()
    print('guides index fresh tests passed')

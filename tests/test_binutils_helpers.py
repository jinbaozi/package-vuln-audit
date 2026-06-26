#!/usr/bin/env python3
import os
import json, pathlib, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]

def test_binutils_profile_on_fixture():
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td)
        src=td/'binutils-src'
        (src/'binutils').mkdir(parents=True)
        (src/'bfd').mkdir()
        (src/'opcodes').mkdir()
        (src/'configure').write_text('#!/bin/sh\n')
        (src/'binutils'/'readelf.c').write_text('int display_relocations(void){return 0;}\n')
        (src/'binutils'/'objdump.c').write_text('int main(){return 0;}\n')
        (src/'bfd'/'elf.c').write_text('int bfd_elf(void){return 0;}\n')
        out=td/'out'
        subprocess.run([str(ROOT/'tools/profile_binutils.sh'), str(src), str(out)], check=True)
        profile=json.loads((out/'package-profile.binutils.json').read_text())
        assert 'binary-parser' in profile['profiles']
        assert 'compiler-toolchain' in profile['profiles']
        assert any('readelf.c' in p for p in profile['high_risk_modules'])

def test_binutils_wrapper_exists_and_is_shell_valid():
    script=ROOT/'examples/binutils/run-binutils-audit.sh'
    assert script.exists()
    subprocess.run(['bash','-n',str(script)], check=True)

def main():
    test_binutils_profile_on_fixture()
    test_binutils_wrapper_exists_and_is_shell_valid()
    print('binutils helper tests passed', flush=True)
    os._exit(0)

if __name__ == '__main__':
    main()

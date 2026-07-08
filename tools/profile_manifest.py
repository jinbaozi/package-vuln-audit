#!/usr/bin/env python3
"""Generate profile traversal manifest and package profile JSON."""
from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import sys

SOURCE_NAMES = {
    '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hxx', '.inc',
    '.rs', '.go', '.py', '.sh', '.js', '.jsx', '.ts', '.tsx',
    '.java', '.kt', '.rb', '.php', '.pl', '.pm',
}
SPECIAL_SOURCE_NAMES = {'Makefile', 'CMakeLists.txt'}
BUILD_AND_DEPENDENCY_NAMES = {
    'configure', 'configure.ac', 'Makefile', 'CMakeLists.txt', 'meson.build',
    'Cargo.toml', 'Cargo.lock',
    'go.mod', 'go.sum',
    'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml',
    'requirements.txt', 'pyproject.toml', 'poetry.lock', 'Pipfile', 'Pipfile.lock',
    'Gemfile', 'Gemfile.lock',
    'pom.xml', 'build.gradle', 'gradle.lockfile',
    'composer.json', 'composer.lock',
}
LOCKFILE_NAMES = {
    'Cargo.lock', 'go.sum', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml',
    'poetry.lock', 'Pipfile.lock', 'Gemfile.lock', 'gradle.lockfile', 'composer.lock',
}
DEPENDENCY_MANIFEST_NAMES = BUILD_AND_DEPENDENCY_NAMES - {'configure', 'configure.ac', 'Makefile', 'CMakeLists.txt', 'meson.build'}


def classify_source_files(all_files: list[str], max_source: int, max_bytes: int) -> tuple[list[str], list[str], int]:
    source: list[str] = []
    build: list[str] = []
    large = 0
    for f in all_files:
        p = pathlib.Path(f)
        name = p.name
        suff = p.suffix.lower()
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        if size > max_bytes:
            large += 1
            continue
        if suff in SOURCE_NAMES or name in SPECIAL_SOURCE_NAMES:
            if len(source) < max_source:
                source.append(f)
        if name in BUILD_AND_DEPENDENCY_NAMES:
            build.append(f)
    return source, build, large


def write_traversal_manifest(
    src: pathlib.Path,
    out: pathlib.Path,
    *,
    all_files: list[str],
    source: list[str],
    excluded: list[str],
    large: int,
    max_source: int,
    manifest_name: str = 'traversal-manifest.json',
) -> None:
    manifest = {
        'source_root': str(src),
        'excluded_dirs': excluded,
        'all_files_count': len(all_files),
        'source_files_count': len(source),
        'large_files_skipped': large,
        'truncated': len(all_files) >= int(os.environ.get('PVAS_MAX_FILES', '50000')) or len(source) >= max_source,
        'limits': {
            'max_files': int(os.environ.get('PVAS_MAX_FILES', '50000')),
            'max_source_files': max_source,
            'max_file_bytes': int(os.environ.get('PVAS_MAX_FILE_BYTES', '5242880')),
        },
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / manifest_name).write_text(json.dumps(manifest, indent=2))


def ecosystem_for_file(name: str) -> str | None:
    if name in {'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'}:
        return 'npm'
    if name in {'Cargo.toml', 'Cargo.lock'}:
        return 'cargo'
    if name in {'go.mod', 'go.sum'}:
        return 'go'
    if name in {'requirements.txt', 'pyproject.toml', 'poetry.lock', 'Pipfile', 'Pipfile.lock'}:
        return 'python'
    if name in {'Gemfile', 'Gemfile.lock'}:
        return 'ruby'
    if name in {'pom.xml', 'build.gradle', 'gradle.lockfile'}:
        return 'jvm'
    if name in {'composer.json', 'composer.lock'}:
        return 'composer'
    return None


def write_generic_profile(src: pathlib.Path, out: pathlib.Path, source: list[str], build: list[str]) -> None:
    exts = collections.Counter(pathlib.Path(f).suffix.lower() or pathlib.Path(f).name for f in source)
    text = '\n'.join(source + build).lower()
    dependency_manifests = [f for f in build if pathlib.Path(f).name in DEPENDENCY_MANIFEST_NAMES]
    lockfiles = [f for f in build if pathlib.Path(f).name in LOCKFILE_NAMES]
    ecosystems = sorted({eco for f in dependency_manifests for eco in [ecosystem_for_file(pathlib.Path(f).name)] if eco})

    profiles: list[str] = []
    if any(x in text for x in ['.c', '.h', '.cpp', '.cc', '.cxx']):
        profiles.append('cli-tool')
    if any(x in text for x in ['parse', 'parser', 'read', 'decode', 'archive', 'elf', 'dwarf', 'record']):
        profiles.append('binary-parser')
    if any(x in text for x in ['makefile', 'cmakelists.txt', 'configure', 'meson.build']):
        profiles.append('build-system')
    if dependency_manifests:
        profiles.append('package-manager')
    if not profiles:
        profiles.append('unknown-conservative')

    langs: list[str] = []
    if any(k in exts for k in ['.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hxx']):
        langs.append('C/C++')
    if '.py' in exts:
        langs.append('Python')
    if '.sh' in exts:
        langs.append('Shell')
    if any(k in exts for k in ['.js', '.jsx', '.ts', '.tsx']):
        langs.append('JavaScript/TypeScript')
    if '.java' in exts:
        langs.append('Java')
    if '.go' in exts:
        langs.append('Go')
    if '.rs' in exts:
        langs.append('Rust')
    if '.rb' in exts:
        langs.append('Ruby')
    if '.php' in exts:
        langs.append('PHP')

    build_system: list[str] = []
    for b in build:
        name = pathlib.Path(b).name.lower()
        if name == 'makefile':
            build_system.append('make')
        elif name == 'cmakelists.txt':
            build_system.append('cmake')
        elif name in ('configure', 'configure.ac'):
            build_system.append('autotools')
        elif name == 'meson.build':
            build_system.append('meson')
        elif name == 'package.json':
            build_system.append('npm')
        elif name == 'cargo.toml':
            build_system.append('cargo')
        elif name == 'go.mod':
            build_system.append('go')
        elif name in {'pom.xml', 'build.gradle'}:
            build_system.append('jvm')

    profile = {
        'package_name': src.resolve().name,
        'source_root': str(src),
        'primary_language': langs or ['unknown'],
        'detected_languages': langs or ['unknown'],
        'profiles': sorted(set(profiles)),
        'build_system': sorted(set(build_system)) or ['unknown'],
        'dependency_manifests': dependency_manifests,
        'lockfiles': lockfiles,
        'package_ecosystems': ecosystems,
        'source_file_count': len(source),
        'extension_counts': dict(exts.most_common(30)),
        'input_surfaces': ['files', 'command-line arguments'] if 'binary-parser' in profiles else ['unknown'],
        'high_risk_modules': [f for f in source if any(k in f.lower() for k in ['parse', 'read', 'decode', 'main.c'])][:20],
        'selected_recipes': [f'recipes/{p}.md' for p in sorted(set(profiles))],
        'confidence': 'medium',
    }
    (out / 'package-profile-hints.json').write_text(
        json.dumps({
            'source_file_count': len(source),
            'extension_counts': dict(exts.most_common(30)),
            'dependency_manifests': dependency_manifests,
            'lockfiles': lockfiles,
            'package_ecosystems': ecosystems,
        }, indent=2)
    )
    (out / 'package-profile.json').write_text(json.dumps(profile, indent=2))
    (out / 'package-profile.md').write_text('# Package Profile\n\n```json\n' + json.dumps(profile, indent=2) + '\n```\n')


def cmd_from_all_files(args: argparse.Namespace) -> int:
    src = pathlib.Path(args.src)
    out = pathlib.Path(args.out)
    excluded = args.exclude_dirs.split()
    all_files = (out / 'all-files.txt').read_text(errors='ignore').splitlines() if (out / 'all-files.txt').exists() else []
    source, build, large = classify_source_files(all_files, args.max_source, args.max_bytes)
    (out / 'source-files.txt').write_text('\n'.join(source) + '\n' if source else '')
    (out / 'build-and-dependency-files.txt').write_text('\n'.join(build) + '\n' if build else '')
    write_traversal_manifest(src, out, all_files=all_files, source=source, excluded=excluded, large=large, max_source=args.max_source)
    write_generic_profile(src, out, source, build)
    return 0


def cmd_binutils_manifest(args: argparse.Namespace) -> int:
    src = pathlib.Path(args.src)
    out = pathlib.Path(args.out)
    excluded = args.exclude_dirs.split()
    files = (out / 'binutils-source-files.txt').read_text(errors='ignore').splitlines() if (out / 'binutils-source-files.txt').exists() else []
    large = 0
    kept: list[str] = []
    for f in files:
        try:
            size = pathlib.Path(f).stat().st_size
        except OSError:
            size = 0
        if size > args.max_bytes:
            large += 1
        else:
            kept.append(f)
    (out / 'binutils-source-files.txt').write_text('\n'.join(kept) + '\n' if kept else '')
    write_traversal_manifest(
        src, out, all_files=files, source=kept, excluded=excluded, large=large,
        max_source=args.max_source, manifest_name='traversal-manifest.binutils.json',
    )
    return 0


def cmd_binutils_profile(args: argparse.Namespace) -> int:
    src = pathlib.Path(args.src)
    out = pathlib.Path(args.out)
    files = (out / 'binutils-source-files.txt').read_text(errors='ignore').splitlines() if (out / 'binutils-source-files.txt').exists() else []
    focus = [
        'binutils/readelf.c', 'binutils/objdump.c', 'binutils/nm.c', 'binutils/objcopy.c',
        'bfd/elf.c', 'bfd/archive.c', 'bfd/compress.c', 'binutils/dwarf.c', 'opcodes/',
    ]
    existing = [p for p in focus if (src / p).exists()]
    profile = {
        'package_name': 'binutils' if (src / 'bfd').exists() or (src / 'binutils').exists() else src.resolve().name,
        'source_root': str(src),
        'primary_language': ['C'],
        'detected_languages': ['C'],
        'profiles': ['binary-parser', 'compiler-toolchain', 'cli-tool'],
        'build_system': ['autotools', 'make'] if (src / 'configure').exists() else ['unknown'],
        'dependency_manifests': [],
        'lockfiles': [],
        'package_ecosystems': [],
        'input_surfaces': [
            'ELF object files', 'archives', 'DWARF/debug sections', 'relocations',
            'symbol/string tables', 'command-line options',
        ],
        'high_risk_modules': existing + [f for f in files if any(x in f for x in ['bfd/elf', 'bfd/archive', 'opcodes/'])][:20],
        'selected_recipes': ['recipes/binary-parser.md', 'recipes/compiler-toolchain.md', 'recipes/cli-tool.md'],
        'recommended_tools': ['rg', 'semgrep', 'cppcheck', 'codeql', 'asan', 'ubsan', 'afl++', 'libFuzzer'],
        'validation_binaries': ['readelf', 'objdump', 'nm-new', 'objcopy', 'strip-new'],
        'audit_focus': [
            'offset+size overflow', 'section/symbol/relocation/string table consistency',
            'DWARF bounds', 'archive member bounds', 'BFD ownership and cleanup',
            'opcodes disassembly buffer assumptions',
        ],
        'confidence': 'high' if existing else 'medium',
    }
    (out / 'package-profile.binutils.json').write_text(json.dumps(profile, indent=2))
    (out / 'package-profile.binutils.md').write_text(
        '# Binutils Package Profile\n\n```json\n' + json.dumps(profile, indent=2) + '\n```\n'
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('from-all-files')
    p1.add_argument('src')
    p1.add_argument('out')
    p1.add_argument('--max-source', type=int, default=10000)
    p1.add_argument('--max-bytes', type=int, default=5242880)
    p1.add_argument('--exclude-dirs', default='.git build dist out target node_modules vendor third_party audit-output __pycache__ .venv venv')
    p1.set_defaults(func=cmd_from_all_files)

    p2 = sub.add_parser('binutils-manifest')
    p2.add_argument('src')
    p2.add_argument('out')
    p2.add_argument('--max-source', type=int, default=10000)
    p2.add_argument('--max-bytes', type=int, default=5242880)
    p2.add_argument('--exclude-dirs', default='.git build dist out target node_modules vendor third_party audit-output __pycache__ .venv venv')
    p2.set_defaults(func=cmd_binutils_manifest)

    p3 = sub.add_parser('binutils-profile')
    p3.add_argument('src')
    p3.add_argument('out')
    p3.set_defaults(func=cmd_binutils_profile)

    args = ap.parse_args()
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())

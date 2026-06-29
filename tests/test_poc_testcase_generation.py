#!/usr/bin/env python3
"""Tests for multi-language POC testcase generation."""
import json, pathlib, tempfile, sys
from tool_runner import ROOT, run_tool


def make_finding(status='Validated', fid='FINDING-001', lang_ext='.c', testcase=None):
    """Create a finding fixture."""
    f = {
        'id': fid,
        'status': status,
        'title': f'fixture {fid} crash',
        'affected_component': {'package': 'toy', 'component': 'parser'},
        'source_code_evidence': [{'file': f'src/parser{lang_ext}', 'function': 'parse_input'}],
        'source_to_sink_path': 'file read -> parse -> memcpy',
        'validation': {
            'command': 'cat',
            'testcase': str(testcase) if testcase else '',
            'expected_vulnerable': 'vulnerable output',
            'expected_fixed': 'fixed output',
        },
        'cvss': {'base_score': 7.5, 'severity': 'High', 'vector': 'CVSS:4.0/...'},
        'fix_recommendation': 'fix the buffer overflow',
        'disclosure_level': 'D3-maintainer-private',
        'discovery_method': [{'type': 'tool', 'tool_name': 'semgrep', 'description': 'fixture'}],
        'disclosure_status': 'not_found_in_configured_sources',
    }
    return f


def test_legacy_single_language():
    """Test legacy mode: single-language PoC from existing testcase."""
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)
        testcase = t / 'testcase.bin'
        testcase.write_bytes(b'PVAS_TESTCASE')

        findings = t / 'findings.json'
        findings.write_text(json.dumps({'findings': [
            make_finding('Validated', 'FINDING-001', '.c', testcase),
            make_finding('Likely', 'FINDING-002', '.c', testcase),
        ]}))

        out = t / 'poc'
        run_tool('tools/generate_poc_testcase.py', [
            '--findings', str(findings), '--out', str(out)
        ])

        # Validated finding gets PoC
        assert (out / 'FINDING-001' / 'poc-manifest.json').exists()
        # Likely finding does NOT get PoC
        assert not (out / 'FINDING-002').exists()

        # Validate artifacts
        run_tool('tools/validate_poc_artifacts.py', ['--poc-root', str(out)])


def test_multilang_generation():
    """Test multi-language PoC generation for a Validated finding."""
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)
        testcase = t / 'testcase.bin'
        testcase.write_bytes(b'PVAS_TESTCASE')

        findings = t / 'findings.json'
        findings.write_text(json.dumps({'findings': [
            make_finding('Validated', 'FINDING-001', '.c', testcase),
        ]}))

        out = t / 'poc'
        run_tool('tools/generate_poc_testcase.py', [
            '--findings', str(findings),
            '--out', str(out),
            '--generate-from-finding',
            '--languages', 'python,c',
        ])

        base = out / 'FINDING-001'
        assert base.exists()

        # Check main manifest
        manifest = json.loads((base / 'poc-manifest.json').read_text())
        assert manifest['status'] == 'Validated'
        assert 'language_variants' in manifest
        assert len(manifest['language_variants']) == 2

        # Check language variant directories
        assert (base / 'python').is_dir()
        assert (base / 'c').is_dir()

        # Check Python variant
        py_manifest = json.loads((base / 'python' / 'poc-manifest.json').read_text())
        assert py_manifest['language'] == 'python'
        assert py_manifest['status'] == 'Validated'
        assert (base / 'python' / 'reproduce.py').exists()
        assert (base / 'python' / 'input-description.md').exists()
        assert (base / 'python' / 'expected-vulnerable.txt').exists()
        assert (base / 'python' / 'expected-fixed.txt').exists()

        # Check C variant
        c_manifest = json.loads((base / 'c' / 'poc-manifest.json').read_text())
        assert c_manifest['language'] == 'c'
        assert (base / 'c' / 'reproduce.c').exists()
        assert (base / 'c' / 'Makefile').exists()

        # Check main reproduce.sh
        assert (base / 'reproduce.sh').exists()
        main_sh = (base / 'reproduce.sh').read_text()
        assert 'timeout' in main_sh
        assert 'python' in main_sh
        assert 'PASSED' in main_sh

        # Check main README
        assert (base / 'README.md').exists()

        # Check run result
        assert (base / 'poc-run-result.json').exists()


def test_needs_manual_review_draft():
    """Test that Needs Manual Review findings get draft POCs."""
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)

        findings = t / 'findings.json'
        findings.write_text(json.dumps({'findings': [
            make_finding('Needs Manual Review', 'FINDING-001', '.py'),
        ]}))

        out = t / 'poc'
        run_tool('tools/generate_poc_testcase.py', [
            '--findings', str(findings),
            '--out', str(out),
            '--generate-from-finding',
            '--languages', 'python',
        ])

        base = out / 'FINDING-001'
        assert base.exists()

        # Main manifest should be draft
        manifest = json.loads((base / 'poc-manifest.json').read_text())
        assert manifest['status'] == 'draft'
        assert manifest['verification'] == 'unverified'

        # Variant manifest should also be draft
        py_manifest = json.loads((base / 'python' / 'poc-manifest.json').read_text())
        assert py_manifest['status'] == 'draft'

        # README should have draft note
        readme = (base / 'README.md').read_text()
        assert 'draft' in readme.lower() or 'manual review' in readme.lower()


def test_language_auto_selection():
    """Test language auto-selection based on source evidence."""
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)

        # Java finding → should auto-select java, python, go
        findings = t / 'findings.json'
        findings.write_text(json.dumps({'findings': [
            make_finding('Validated', 'FINDING-001', '.java'),
        ]}))

        out = t / 'poc'
        run_tool('tools/generate_poc_testcase.py', [
            '--findings', str(findings),
            '--out', str(out),
            '--generate-from-finding',
            # No --languages → auto-select based on .java extension
        ])

        base = out / 'FINDING-001'
        manifest = json.loads((base / 'poc-manifest.json').read_text())
        variants = manifest.get('language_variants', [])
        langs = [v['language'] for v in variants]

        # Should include java, python, go (from PROFILE_LANGUAGE_MAP for java)
        assert 'java' in langs
        assert 'python' in langs
        assert 'go' in langs


def test_profile_based_selection():
    """Test language selection based on package profile."""
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)

        profile = {
            'package_name': 'test-pkg',
            'primary_language': 'c++',
            'detected_languages': ['c++', 'python'],
        }
        profile_path = t / 'package-profile.json'
        profile_path.write_text(json.dumps(profile))

        findings = t / 'findings.json'
        findings.write_text(json.dumps({'findings': [
            make_finding('Validated', 'FINDING-001', '.cpp'),
        ]}))

        out = t / 'poc'
        run_tool('tools/generate_poc_testcase.py', [
            '--findings', str(findings),
            '--out', str(out),
            '--generate-from-finding',
            '--profile', str(profile_path),
        ])

        base = out / 'FINDING-001'
        manifest = json.loads((base / 'poc-manifest.json').read_text())
        variants = manifest.get('language_variants', [])
        langs = [v['language'] for v in variants]

        # C++ project → should select c, cpp, python
        assert 'c' in langs
        assert 'cpp' in langs
        assert 'python' in langs


def test_explicit_language_override():
    """Test that --languages explicitly overrides auto-selection."""
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)

        findings = t / 'findings.json'
        findings.write_text(json.dumps({'findings': [
            make_finding('Validated', 'FINDING-001', '.py'),
        ]}))

        out = t / 'poc'
        run_tool('tools/generate_poc_testcase.py', [
            '--findings', str(findings),
            '--out', str(out),
            '--generate-from-finding',
            '--languages', 'go,java',
        ])

        base = out / 'FINDING-001'
        manifest = json.loads((base / 'poc-manifest.json').read_text())
        variants = manifest.get('language_variants', [])
        langs = [v['language'] for v in variants]

        assert 'go' in langs
        assert 'java' in langs
        # Python should NOT be included (explicit override)
        assert 'python' not in langs


def test_ineligible_status_skipped():
    """Test that findings with ineligible status are skipped."""
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)

        findings = t / 'findings.json'
        findings.write_text(json.dumps({'findings': [
            make_finding('Likely', 'FINDING-001', '.c'),
            make_finding('Rejected', 'FINDING-002', '.c'),
            make_finding('Candidate', 'FINDING-003', '.c'),
        ]}))

        out = t / 'poc'
        run_tool('tools/generate_poc_testcase.py', [
            '--findings', str(findings),
            '--out', str(out),
            '--generate-from-finding',
        ])

        # None should have POCs generated
        assert not (out / 'FINDING-001').exists()
        assert not (out / 'FINDING-002').exists()
        assert not (out / 'FINDING-003').exists()

        # Check summary
        summary = json.loads((out / 'poc-generation-summary.json').read_text())
        assert len(summary['skipped']) == 3
        assert all(s['reason'] == 'status-not-eligible' for s in summary['skipped'])


def test_all_five_languages():
    """Test generation with all 5 default languages."""
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)

        findings = t / 'findings.json'
        findings.write_text(json.dumps({'findings': [
            make_finding('Validated', 'FINDING-001', '.c'),
        ]}))

        out = t / 'poc'
        run_tool('tools/generate_poc_testcase.py', [
            '--findings', str(findings),
            '--out', str(out),
            '--generate-from-finding',
            '--languages', 'python,c,cpp,java,go',
        ])

        base = out / 'FINDING-001'
        assert (base / 'python').is_dir()
        assert (base / 'c').is_dir()
        assert (base / 'cpp').is_dir()
        assert (base / 'java').is_dir()
        assert (base / 'go').is_dir()

        # Check each variant has required files
        for lang in ['python', 'c', 'cpp', 'java', 'go']:
            assert (base / lang / 'poc-manifest.json').exists()
            assert (base / lang / 'input-description.md').exists()
            assert (base / lang / 'expected-vulnerable.txt').exists()
            assert (base / lang / 'expected-fixed.txt').exists()

        # Check compiled languages have Makefiles
        for lang in ['c', 'cpp', 'java']:
            assert (base / lang / 'Makefile').exists()


def main():
    test_legacy_single_language()
    print('[PASS] test_legacy_single_language')

    test_multilang_generation()
    print('[PASS] test_multilang_generation')

    test_needs_manual_review_draft()
    print('[PASS] test_needs_manual_review_draft')

    test_language_auto_selection()
    print('[PASS] test_language_auto_selection')

    test_profile_based_selection()
    print('[PASS] test_profile_based_selection')

    test_explicit_language_override()
    print('[PASS] test_explicit_language_override')

    test_ineligible_status_skipped()
    print('[PASS] test_ineligible_status_skipped')

    test_all_five_languages()
    print('[PASS] test_all_five_languages')

    print('poc testcase generation tests passed')


if __name__ == '__main__':
    main()

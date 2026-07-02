#!/usr/bin/env python3
"""Validate local-only PoC/reproducer artifacts.

Supports both single-language and multi-language POC directory structures.
For multi-language POCs, validates each language variant independently.
"""
from __future__ import annotations
import argparse, json, pathlib, re, sys

from pvas_io import load_json, sha256_file

DENY=[r'\bcurl\b',r'\bwget\b',r'\bnc\b',r'\bnetcat\b',r'\bssh\b',r'\bscp\b',r'\bftp\b',r'\btelnet\b',r'\bsudo\b',r'\bsu\b',r'\bsetcap\b',r'chmod\s+u\+s',r'\|\s*sh\b',r'>\s*/etc/',r'>\s*/usr/',r'>\s*/var/lib/',r'>\s*/root/',r'\b(cp|mv|install)\b[^\n]*(/etc/|/usr/|/var/lib/|/root/)']


def _check_deny_patterns(text, label):
    """Check for unsafe patterns in text. Returns list of error strings."""
    errs = []
    for pat in DENY:
        if re.search(pat, text):
            errs.append(f'{label}: unsafe pattern: {pat}')
    return errs


def _check_timeout(text, label):
    """Check that a script uses timeout. Returns list of error strings."""
    if 'timeout' not in text:
        return [f'{label}: must use timeout']
    return []


def _validate_status_and_verification(data: dict, label: str) -> list[str]:
    errs = []
    status = data.get('status', '')
    verification = data.get('verification')
    if status not in {'Validated', 'draft'}:
        errs.append(f'{label}: manifest status must be Validated or draft (got {status})')
    elif status == 'draft':
        if verification != 'unverified':
            errs.append(f'{label}: draft manifest verification must be unverified')
    elif verification not in (None, '', 'verified'):
        errs.append(f'{label}: Validated manifest verification must be verified when present')
    return errs


def validate_language_variant(lang_dir: pathlib.Path, parent_finding_id: str, require_passed_run: bool = True):
    """Validate a single language variant directory.

    Args:
        lang_dir: directory containing the language variant
        parent_finding_id: the finding ID from the parent manifest
        is_draft: True if the parent finding is Needs Manual Review

    Returns:
        list of error strings
    """
    errs = []
    m = lang_dir / 'poc-manifest.json'
    desc = lang_dir / 'input-description.md'

    if not m.exists():
        errs.append(f'{lang_dir}: missing poc-manifest.json')
        return errs

    data = load_json(m, required=True)

    # Required keys
    for k in ['finding_id', 'status', 'safety_class', 'commands', 'expected_results',
              'artifacts', 'disclosure_level', 'language']:
        if k not in data:
            errs.append(f'{lang_dir}: manifest missing {k}')

    errs.extend(_validate_status_and_verification(data, str(lang_dir)))

    if data.get('safety_class') != 'local-validation-only':
        errs.append(f'{lang_dir}: safety_class not local-validation-only')

    # discovery_method_ref
    dmr = data.get('discovery_method_ref', '')
    if not dmr or not dmr.strip():
        errs.append(f'{lang_dir}: manifest discovery_method_ref is empty')

    # Check reproduce script exists and is safe
    artifacts = data.get('artifacts', {})
    script_name = artifacts.get('reproduce_script', '')
    if script_name:
        script_path = lang_dir / script_name
        if not script_path.exists():
            errs.append(f'{lang_dir}: missing reproduce script {script_name}')
        else:
            txt = script_path.read_text()
            errs.extend(_check_timeout(txt, f'{lang_dir}/{script_name}'))
            errs.extend(_check_deny_patterns(txt, f'{lang_dir}/{script_name}'))

    # input-description.md
    if not desc.exists():
        errs.append(f'{lang_dir}: missing input-description.md')
    else:
        desc_text = desc.read_text()
        if 'SHA256' not in desc_text and 'sha256' not in desc_text:
            errs.append(f'{lang_dir}: input-description.md missing SHA256')
        if 'Purpose' not in desc_text and 'purpose' not in desc_text.lower():
            errs.append(f'{lang_dir}: input-description.md missing purpose')

    # Testcase SHA256 check
    t = data.get('testcase', {})
    if t.get('path'):
        tp = lang_dir / t['path']
        if not tp.exists():
            errs.append(f'{lang_dir}: missing testcase {t["path"]}')
        elif t.get('sha256') and sha256_file(tp) != t['sha256']:
            errs.append(f'{lang_dir}: testcase sha256 mismatch')

    # Expected results
    er = data.get('expected_results', {})
    if not er.get('vulnerable') or not er.get('fixed'):
        errs.append(f'{lang_dir}: expected vulnerable/fixed behavior required')

    run_result = lang_dir / 'poc-run-result.json'
    if require_passed_run:
        if not run_result.exists():
            errs.append(f'{lang_dir}: missing poc-run-result.json')
        else:
            rr = json.loads(run_result.read_text())
            if rr.get('status') != 'passed':
                errs.append(f'{lang_dir}: poc-run-result status is not passed')
            if rr.get('exit_code') != 0:
                errs.append(f'{lang_dir}: poc-run-result exit_code is not 0')

    return errs


def validate_dir(d: pathlib.Path):
    """Validate a POC directory (supports both legacy single-language and multi-language)."""
    errs = []
    m = d / 'poc-manifest.json'
    s = d / 'reproduce.sh'
    desc = d / 'input-description.md'

    if not m.exists():
        return [f'{d}: missing poc-manifest.json']

    data = load_json(m, required=True)
    for k in ['finding_id', 'status', 'safety_class', 'commands', 'expected_results',
              'artifacts', 'disclosure_level']:
        if k not in data:
            errs.append(f'{d}: manifest missing {k}')

    errs.extend(_validate_status_and_verification(data, str(d)))
    if data.get('safety_class') != 'local-validation-only':
        errs.append(f'{d}: safety_class not local-validation-only')

    # discovery_method_ref
    dmr = data.get('discovery_method_ref', '')
    if not dmr or not dmr.strip():
        errs.append(f'{d}: manifest discovery_method_ref is empty')

    # Check for multi-language structure
    language_variants = data.get('language_variants', [])

    if language_variants:
        # Multi-language mode: validate each variant
        has_passed_variant = False

        for variant in language_variants:
            lang = variant.get('language', '')
            lang_dir = d / lang
            if not lang_dir.is_dir():
                errs.append(f'{d}: language variant directory missing: {lang}')
                continue

            variant_errs = validate_language_variant(lang_dir, data.get('finding_id', ''), require_passed_run=False)
            errs.extend(variant_errs)

            # Check if this variant passed
            run_result = lang_dir / 'poc-run-result.json'
            if run_result.exists():
                rr = json.loads(run_result.read_text())
                if rr.get('status') == 'passed':
                    has_passed_variant = True

        if not has_passed_variant:
            errs.append(f'{d}: no language variant has poc-run-result status=passed')

        main_run_result = d / 'poc-run-result.json'
        if not main_run_result.exists():
            errs.append(f'{d}: missing poc-run-result.json')
        else:
            rr = json.loads(main_run_result.read_text())
            if rr.get('status') != 'passed':
                errs.append(f'{d}: poc-run-result status is not passed')
            if rr.get('exit_code') != 0:
                errs.append(f'{d}: poc-run-result exit_code is not 0')

        # Main reproduce.sh checks
        if not s.exists():
            errs.append(f'{d}: missing reproduce.sh')
        else:
            txt = s.read_text()
            errs.extend(_check_timeout(txt, f'{d}/reproduce.sh'))
            errs.extend(_check_deny_patterns(txt, f'{d}/reproduce.sh'))

        # input-description.md
        if not desc.exists():
            errs.append(f'{d}: missing input-description.md')
        else:
            desc_text = desc.read_text()
            if 'SHA256' not in desc_text and 'sha256' not in desc_text:
                errs.append(f'{d}: input-description.md missing SHA256')
            if 'Purpose' not in desc_text and 'purpose' not in desc_text.lower():
                errs.append(f'{d}: input-description.md missing purpose')

    else:
        # Legacy single-language mode
        if not s.exists():
            errs.append(f'{d}: missing reproduce.sh')
        else:
            txt = s.read_text()
            errs.extend(_check_timeout(txt, f'{d}/reproduce.sh'))
            errs.extend(_check_deny_patterns(txt, f'{d}/reproduce.sh'))

        if not desc.exists():
            errs.append(f'{d}: missing input-description.md')
        else:
            desc_text = desc.read_text()
            if 'SHA256' not in desc_text and 'sha256' not in desc_text:
                errs.append(f'{d}: input-description.md missing SHA256')
            if 'Purpose' not in desc_text and 'purpose' not in desc_text.lower():
                errs.append(f'{d}: input-description.md missing purpose')

        t = data.get('testcase', {})
        if t.get('path'):
            tp = d / t['path']
            if not tp.exists():
                errs.append(f'{d}: missing testcase {t["path"]}')
            elif t.get('sha256') and sha256_file(tp) != t['sha256']:
                errs.append(f'{d}: testcase sha256 mismatch')

        er = data.get('expected_results', {})
        if not er.get('vulnerable') or not er.get('fixed'):
            errs.append(f'{d}: expected vulnerable/fixed behavior required')

        run_result = d / 'poc-run-result.json'
        if not run_result.exists():
            errs.append(f'{d}: missing poc-run-result.json')
        else:
            rr = json.loads(run_result.read_text())
            if rr.get('status') != 'passed':
                errs.append(f'{d}: poc-run-result status is not passed')
            if rr.get('exit_code') != 0:
                errs.append(f'{d}: poc-run-result exit_code is not 0')

    return errs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--poc-root', required=True)
    args = ap.parse_args()
    root = pathlib.Path(args.poc_root)
    errs = []
    for d in sorted([p for p in root.iterdir() if p.is_dir()]):
        errs.extend(validate_dir(d))
    if errs:
        print('\n'.join(errs), file=sys.stderr)
        return 2
    print('poc artifact validation passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

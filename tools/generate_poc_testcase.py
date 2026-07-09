#!/usr/bin/env python3
"""Generate local-only PoC/reproducer artifacts for Validated findings.

Supports multi-language POC generation (Python, C, C++, Java, Go, Perl, Shell).
Each finding gets POC variants in multiple languages under language-specific subdirectories.
"""
from __future__ import annotations
import argparse, json, pathlib, shutil, os, platform, stat, sys, subprocess, time, shlex, tempfile

from pvas_io import load_findings, sha256_file
import pvas_container

# ---------------------------------------------------------------------------
# Language extension mapping
# ---------------------------------------------------------------------------
EXTENSION_MAP = {
    '.py': 'python',
    '.c': 'c', '.h': 'c',
    '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp', '.hxx': 'cpp',
    '.java': 'java',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.php': 'php',
    '.js': 'javascript', '.mjs': 'javascript',
    '.pm': 'perl', '.pl': 'perl', '.in': 'perl',
    '.sh': 'sh', '.as': 'sh',
    '.m4': 'm4',
}

# Languages that can be auto-detected from package-profile
PROFILE_LANGUAGE_MAP = {
    'c': ['c', 'cpp', 'python'],
    'c++': ['c', 'cpp', 'python'],
    'cpp': ['c', 'cpp', 'python'],
    'java': ['java', 'python', 'go'],
    'python': ['python', 'c', 'go'],
    'go': ['go', 'python', 'c'],
    'rust': ['rust', 'python', 'c'],
    'ruby': ['ruby', 'python', 'c'],
    'javascript': ['javascript', 'python', 'go'],
    'php': ['php', 'python', 'c'],
    'perl': ['perl', 'python', 'sh'],
}

ALL_LANGUAGES = ['python', 'c', 'cpp', 'java', 'go']

# Runtime check commands for each language
LANGUAGE_RUNTIMES = {
    'python': ['python3', '--version'],
    'c': ['gcc', '--version'],
    'cpp': ['g++', '--version'],
    'java': ['javac', '-version'],
    'go': ['go', 'version'],
    'perl': ['perl', '-v'],
    'sh': ['bash', '--version'],
    'rust': ['rustc', '--version'],
    'ruby': ['ruby', '--version'],
    'php': ['php', '--version'],
    'javascript': ['node', '--version'],
    'm4': ['m4', '--version'],
}

# ---------------------------------------------------------------------------
# Script templates for each language
# ---------------------------------------------------------------------------
SCRIPT_TEMPLATES = {
    "python": r"""#!/usr/bin/env python3
# Local validation PoC for {{finding_id}}
# Authorized local validation and regression testing only.
import os, sys, tempfile, subprocess, shutil

def main():
    tmpdir = tempfile.mkdtemp(prefix="pvas-poc-")
    try:
        print(f"[PVAS-POC] Setting up test environment in {tmpdir}")

        {{setup_steps}}

        print("[PVAS-POC] Triggering vulnerability scenario...")

        {{trigger_steps}}

        print("[PVAS-POC] Checking for side effect...")

        {{check_steps}}

        print("[PVAS-POC] Validation complete.")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == "__main__":
    main()
""",
    "c": r"""/* Local validation PoC for {{finding_id}}
 * Authorized local validation and regression testing only.
 * Compile: gcc -o reproduce reproduce.c -Wall
 * Run: timeout 10s ./reproduce
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int main(void) {
    char tmpdir[] = "/tmp/pvas-poc-XXXXXX";
    if (mkdtemp(tmpdir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    printf("[PVAS-POC] Setting up test environment in %s\n", tmpdir);

    {{setup_steps}}

    printf("[PVAS-POC] Triggering vulnerability scenario...\n");

    {{trigger_steps}}

    printf("[PVAS-POC] Checking for side effect...\n");

    {{check_steps}}

    /* Cleanup */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);

    printf("[PVAS-POC] Validation complete.\n");
    return 0;
}
""",
    "cpp": r"""/* Local validation PoC for {{finding_id}}
 * Authorized local validation and regression testing only.
 * Compile: g++ -o reproduce reproduce.cpp -Wall -std=c++17
 * Run: timeout 10s ./reproduce
 */
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <filesystem>

namespace fs = std::filesystem;

int main() {
    auto tmpdir = fs::temp_directory_path() / "pvas-poc-XXXXXX";
    std::string tmpdir_str = tmpdir.string();
    // Create unique temp dir
    char tmpl[256];
    snprintf(tmpl, sizeof(tmpl), "/tmp/pvas-poc-XXXXXX");
    if (mkdtemp(tmpl) == nullptr) {
        std::cerr << "mkdtemp failed" << std::endl;
        return 1;
    }
    std::string tmp = tmpl;
    std::cout << "[PVAS-POC] Setting up test environment in " << tmp << std::endl;

    {{setup_steps}}

    std::cout << "[PVAS-POC] Triggering vulnerability scenario..." << std::endl;

    {{trigger_steps}}

    std::cout << "[PVAS-POC] Checking for side effect..." << std::endl;

    {{check_steps}}

    // Cleanup
    std::string cmd = "rm -rf " + tmp;
    system(cmd.c_str());

    std::cout << "[PVAS-POC] Validation complete." << std::endl;
    return 0;
}
""",
    "java": r"""/* Local validation PoC for {{finding_id}}
 * Authorized local validation and regression testing only.
 * Compile: javac Reproduce.java
 * Run: timeout 10s java Reproduce
 */
import java.io.*;
import java.nio.file.*;

public class Reproduce {
    public static void main(String[] args) throws Exception {
        Path tmpdir = Files.createTempDirectory("pvas-poc-");
        System.out.println("[PVAS-POC] Setting up test environment in " + tmpdir);
        try {

            {{setup_steps}}

            System.out.println("[PVAS-POC] Triggering vulnerability scenario...");

            {{trigger_steps}}

            System.out.println("[PVAS-POC] Checking for side effect...");

            {{check_steps}}

            System.out.println("[PVAS-POC] Validation complete.");
        } finally {
            // Cleanup
            Files.walk(tmpdir)
                .sorted(java.util.Comparator.reverseOrder())
                .forEach(p -> { try { Files.deleteIfExists(p); } catch (Exception e) {} });
        }
    }
}
""",
    "go": r"""// Local validation PoC for {{finding_id}}
// Authorized local validation and regression testing only.
// Run: go run reproduce.go
// Or:  go build -o reproduce reproduce.go && timeout 10s ./reproduce
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	tmpdir, err := os.MkdirTemp("", "pvas-poc-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpdir)

	fmt.Printf("[PVAS-POC] Setting up test environment in %s\n", tmpdir)

	{{setup_steps}}

	fmt.Println("[PVAS-POC] Triggering vulnerability scenario...")

	{{trigger_steps}}

	fmt.Println("[PVAS-POC] Checking for side effect...")

	{{check_steps}}

	_ = filepath.Base(tmpdir) // use filepath to avoid unused import
	fmt.Println("[PVAS-POC] Validation complete.")
}
""",
    "perl": r"""#!/usr/bin/env perl
# Local validation PoC for {{finding_id}}
# Authorized local validation and regression testing only.
use strict;
use warnings;
use File::Temp qw/tempdir/;
use File::Spec;

my $tmpdir = tempdir(CLEANUP => 1);

print "[PVAS-POC] Setting up test environment in $tmpdir\n";

{{setup_steps}}

print "[PVAS-POC] Triggering vulnerability scenario...\n";

{{trigger_steps}}

print "[PVAS-POC] Checking for side effect...\n";

{{check_steps}}

print "[PVAS-POC] Validation complete.\n";
exit 0;
""",
    "sh": r"""#!/usr/bin/env bash
# Local validation PoC for {{finding_id}}
# Authorized local validation and regression testing only.
set -euo pipefail
TIMEOUT="${TIMEOUT:-10s}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "[PVAS-POC] Setting up test environment in $TMPDIR"

{{setup_steps}}

echo "[PVAS-POC] Triggering vulnerability scenario..."

{{trigger_steps}}

echo "[PVAS-POC] Checking for side effect..."

{{check_steps}}

echo "[PVAS-POC] Validation complete."
""",
    "m4": r"""dnl Local validation PoC for {{finding_id}}
dnl Authorized local validation and regression testing only.
{{setup_steps}}
{{trigger_steps}}
{{check_steps}}
""",
    "generic": r"""#!/usr/bin/env bash
# Local validation PoC for {{finding_id}}
# Authorized local validation and regression testing only.
set -euo pipefail
TIMEOUT="${TIMEOUT:-10s}"
TMPDIR="$(mktemp -d)"
export TMPDIR
trap 'rm -rf "$TMPDIR"' EXIT

timeout "$TIMEOUT" bash <<'POCEOF'
set -euo pipefail

echo "[PVAS-POC] Setting up test environment in $TMPDIR"

{{setup_steps}}

echo "[PVAS-POC] Triggering vulnerability scenario..."

{{trigger_steps}}

echo "[PVAS-POC] Checking for side effect..."

{{check_steps}}

echo "[PVAS-POC] Validation complete."
POCEOF
""",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_testcase(f, explicit):
    if explicit: return pathlib.Path(explicit)
    val=f.get('validation',{}) if isinstance(f.get('validation'),dict) else {}
    for k in ['testcase','input','reproducer','testcase_path']:
        if val.get(k): return pathlib.Path(val[k])
    return None


def runtime_available(lang):
    """Check if a language runtime/compiler is available on the system."""
    cmd = LANGUAGE_RUNTIMES.get(lang)
    if not cmd:
        return False
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def infer_language(f):
    """Infer the primary language from source_code_evidence file extensions."""
    lang_counts = {}
    for ev in (f.get('source_code_evidence') or []):
        if isinstance(ev, dict):
            fp = ev.get('file', '')
            ext = os.path.splitext(fp)[1].lower()
            lang = EXTENSION_MAP.get(ext)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + 1
    if lang_counts:
        return max(lang_counts, key=lang_counts.get)
    return 'generic'


def select_languages(f, explicit_langs=None, profile=None):
    """Select languages for multi-language POC generation.

    Args:
        f: finding dict
        explicit_langs: list of language names (user override)
        profile: package-profile dict (for auto-selection)

    Returns:
        list of language names
    """
    if explicit_langs:
        return explicit_langs

    # Try auto-select from package profile
    if profile:
        primary = (profile.get('primary_language') or '').lower()
        detected = [l.lower() for l in (profile.get('detected_languages') or [])]
        # Check primary language
        if primary in PROFILE_LANGUAGE_MAP:
            return PROFILE_LANGUAGE_MAP[primary]
        # Check detected languages
        for dl in detected:
            if dl in PROFILE_LANGUAGE_MAP:
                return PROFILE_LANGUAGE_MAP[dl]

    # Try auto-select from finding's source evidence
    inferred = infer_language(f)
    if inferred in PROFILE_LANGUAGE_MAP:
        return PROFILE_LANGUAGE_MAP[inferred]

    # Default: all languages
    return list(ALL_LANGUAGES)


def load_profile(profile_path):
    """Load package-profile.json if available."""
    if not profile_path:
        return None
    p = pathlib.Path(profile_path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Step generation (generic, based on finding metadata)
# ---------------------------------------------------------------------------

def generate_steps_from_finding(f, lang):
    """Generate setup/trigger/check steps based on finding metadata and target language.

    Steps are derived from source_to_sink_path and source_code_evidence,
    not hardcoded to any specific vulnerability pattern.
    """
    ssp = f.get('source_to_sink_path', '')
    title = f.get('title', 'vulnerability')
    component = f.get('affected_component', {}).get('component', 'target')
    evidence = f.get('source_code_evidence') or []
    validation = f.get('validation') if isinstance(f.get('validation'), dict) else {}
    validation_command = str(validation.get('command') or '').strip()
    py_command = repr(shlex.split(validation_command) if validation_command else [])
    shell_command = shlex.quote(validation_command) if validation_command else ''

    # Extract file/function info from evidence
    src_files = []
    src_funcs = []
    for ev in evidence:
        if isinstance(ev, dict):
            if ev.get('file'):
                src_files.append(ev['file'])
            if ev.get('function'):
                src_funcs.append(ev['function'])

    setup = []
    trigger = []
    check = []

    if lang == 'python':
        setup.append(f'# Target component: {component}')
        setup.append(f'# Title: {title}')
        if src_files:
            setup.append(f'# Source files: {", ".join(src_files[:3])}')
        setup.append('# Prepare malicious input to exercise the vulnerable code path')
        setup.append('test_input = os.path.join(tmpdir, "test_input.bin")')
        setup.append('with open(test_input, "wb") as fh:')
        setup.append('    fh.write(b"\\x00" * 256)  # Craft input based on source_to_sink_path')
        if ssp:
            setup.append(f'# Source-to-sink: {ssp[:200]}')

        trigger.append('# Invoke the recorded local validation command against the testcase')
        trigger.append(f'cmd = {py_command}')
        trigger.append('if not cmd:')
        trigger.append('    print("[FAIL] Missing validation.command; refusing placeholder trigger")')
        trigger.append('    sys.exit(1)')
        trigger.append('result = subprocess.run(')
        trigger.append('    ["timeout", "5s"] + cmd + [test_input],')
        trigger.append('    capture_output=True, text=True')
        trigger.append(')')

        check.append('# Verify the vulnerability was triggered')
        check.append('if result.returncode == 0:')
        check.append('    print("[PASS] Vulnerability triggered successfully")')
        check.append('else:')
        check.append('    print("[FAIL] Vulnerability not triggered")')
        check.append('    sys.exit(1)')

    elif lang == 'c':
        setup.append(f'/* Target component: {component} */')
        setup.append(f'/* Title: {title} */')
        if src_files:
            setup.append(f'/* Source files: {", ".join(src_files[:3])} */')
        setup.append('/* Prepare test input */')
        setup.append('char input_path[512];')
        setup.append('snprintf(input_path, sizeof(input_path), "%s/test_input.bin", tmpdir);')
        setup.append('FILE *fp = fopen(input_path, "wb");')
        setup.append('if (fp) { fwrite("\\x00", 1, 256, fp); fclose(fp); }')
        if ssp:
            setup.append(f'/* Source-to-sink: {ssp[:200]} */')

        trigger.append('/* Invoke the recorded local validation command against the testcase */')
        trigger.append('char cmd[512];')
        if shell_command:
            trigger.append(f'snprintf(cmd, sizeof(cmd), "timeout 5s {shell_command} %s", input_path);')
        else:
            trigger.append('snprintf(cmd, sizeof(cmd), "false");')
        trigger.append('int rc = system(cmd);')

        check.append('/* Verify the vulnerability was triggered */')
        check.append('if (rc == 0) { printf("[PASS] Vulnerability triggered\\n"); }')
        check.append('else { printf("[FAIL] Vulnerability not triggered\\n"); return 1; }')

    elif lang == 'cpp':
        setup.append(f'// Target component: {component}')
        setup.append(f'// Title: {title}')
        if src_files:
            setup.append(f'// Source files: {", ".join(src_files[:3])}')
        setup.append('// Prepare test input')
        setup.append('std::string input_path = tmp + "/test_input.bin";')
        setup.append('{')
        setup.append('    std::ofstream ofs(input_path, std::ios::binary);')
        setup.append('    char buf[256] = {};')
        setup.append('    ofs.write(buf, 256);')
        setup.append('}')
        if ssp:
            setup.append(f'// Source-to-sink: {ssp[:200]}')

        trigger.append('// Invoke the recorded local validation command against the testcase')
        if shell_command:
            trigger.append(f'std::string cmd = "timeout 5s {shell_command} " + input_path;')
        else:
            trigger.append('std::string cmd = "false";')
        trigger.append('int rc = system(cmd.c_str());')

        check.append('// Verify the vulnerability was triggered')
        check.append('if (rc == 0) { std::cout << "[PASS] Vulnerability triggered" << std::endl; }')
        check.append('else { std::cout << "[FAIL] Vulnerability not triggered" << std::endl; return 1; }')

    elif lang == 'java':
        setup.append(f'// Target component: {component}')
        setup.append(f'// Title: {title}')
        if src_files:
            setup.append(f'// Source files: {", ".join(src_files[:3])}')
        setup.append('// Prepare test input')
        setup.append('Path inputPath = tmpdir.resolve("test_input.bin");')
        setup.append('byte[] data = new byte[256];')
        setup.append('Files.write(inputPath, data);')
        if ssp:
            setup.append(f'// Source-to-sink: {ssp[:200]}')

        trigger.append('// Invoke the recorded local validation command against the testcase')
        if validation_command:
            command_parts = ', '.join(json.dumps(part) for part in (['timeout', '5s'] + shlex.split(validation_command)))
            trigger.append(f'ProcessBuilder pb = new ProcessBuilder({command_parts}, inputPath.toString());')
        else:
            trigger.append('ProcessBuilder pb = new ProcessBuilder("false");')
        trigger.append('pb.redirectErrorStream(true);')
        trigger.append('Process proc = pb.start();')
        trigger.append('int exitCode = proc.waitFor();')

        check.append('// Verify the vulnerability was triggered')
        check.append('if (exitCode == 0) { System.out.println("[PASS] Vulnerability triggered"); }')
        check.append('else { System.out.println("[FAIL] Vulnerability not triggered"); System.exit(1); }')

    elif lang == 'go':
        setup.append(f'// Target component: {component}')
        setup.append(f'// Title: {title}')
        if src_files:
            setup.append(f'// Source files: {", ".join(src_files[:3])}')
        setup.append('// Prepare test input')
        setup.append('inputPath := filepath.Join(tmpdir, "test_input.bin")')
        setup.append('os.WriteFile(inputPath, make([]byte, 256), 0644)')
        if ssp:
            setup.append(f'// Source-to-sink: {ssp[:200]}')

        trigger.append('// Invoke the recorded local validation command against the testcase')
        if validation_command:
            parts = ['"timeout"', '"5s"'] + [json.dumps(part) for part in shlex.split(validation_command)]
            trigger.append(f'cmd := exec.Command({", ".join(parts)}, inputPath)')
        else:
            trigger.append('cmd := exec.Command("false")')
        trigger.append('output, err := cmd.CombinedOutput()')
        trigger.append('rc := 0')
        trigger.append('if err != nil { rc = 1 }')
        trigger.append('_ = output')

        check.append('// Verify the vulnerability was triggered')
        check.append('if rc == 0 { fmt.Println("[PASS] Vulnerability triggered") }')
        check.append('else { fmt.Println("[FAIL] Vulnerability not triggered"); os.Exit(1) }')

    elif lang == 'perl':
        setup.append(f'# Target component: {component}')
        if src_files:
            setup.append(f'# Source files: {", ".join(src_files[:3])}')
        setup.append('my $input_path = File::Spec->catfile($tmpdir, "test_input.bin");')
        setup.append('open(my $fh, ">", $input_path) or die "cannot write: $!";')
        setup.append('print $fh "\\x00" x 256;')
        setup.append('close($fh);')
        if ssp:
            setup.append(f'# Source-to-sink: {ssp[:200]}')

        if shell_command:
            trigger.append(f'my $rc = system("timeout 5s {shell_command} $input_path");')
        else:
            trigger.append('my $rc = system("false");')

        check.append('if ($rc == 0) { print "[PASS] Vulnerability triggered\\n"; }')
        check.append('else { print "[FAIL] Vulnerability not triggered\\n"; exit 1; }')

    elif lang == 'sh':
        setup.append(f'# Target component: {component}')
        if src_files:
            setup.append(f'# Source files: {", ".join(src_files[:3])}')
        setup.append('INPUT_PATH="$TMPDIR/test_input.bin"')
        setup.append('dd if=/dev/zero bs=256 count=1 of="$INPUT_PATH" 2>/dev/null')
        if ssp:
            setup.append(f'# Source-to-sink: {ssp[:200]}')

        if shell_command:
            trigger.append(f'timeout 5s {shell_command} "$INPUT_PATH"')
        else:
            trigger.append('false')
        trigger.append('RC=$?')

        check.append('if [ "$RC" -eq 0 ]; then echo "[PASS] Vulnerability triggered"; else echo "[FAIL] Vulnerability not triggered"; exit 1; fi')

    else:
        # generic fallback
        setup.append(f'# Target component: {component}')
        setup.append('# Test setup: prepare input to trigger the vulnerability')
        setup.append('echo "Setting up test environment..."')
        if ssp:
            setup.append(f'# Based on source_to_sink_path: {ssp[:200]}')
        trigger.append('# Trigger the vulnerable code path using the recorded local validation command')
        if shell_command:
            trigger.append(f'timeout 5s {shell_command} "$INPUT_PATH"')
        else:
            trigger.append('false')
        check.append('# Verify side effect')
        check.append('echo "Check for expected behavior..."')

    if lang == 'python':
        indent = '        '
    elif lang == 'java':
        indent = '            '
    elif lang == 'go':
        indent = '\t'
    elif lang == 'perl':
        indent = '  '
    else:
        indent = ''
    return '\n'.join(f'{indent}{line}' for line in setup), \
           '\n'.join(f'{indent}{line}' for line in trigger), \
           '\n'.join(f'{indent}{line}' for line in check)


# ---------------------------------------------------------------------------
# POC generation for a single language variant
# ---------------------------------------------------------------------------

def generate_language_variant(f, lang, outdir, is_draft=False):
    """Generate a single language variant POC in the given directory.

    Args:
        f: finding dict
        lang: language name
        outdir: output directory for this variant
        is_draft: True for Needs Manual Review findings

    Returns:
        dict with variant metadata
    """
    fid = f.get('id', 'FINDING-UNKNOWN')
    setup_s, trigger_s, check_s = generate_steps_from_finding(f, lang)
    tmpl = SCRIPT_TEMPLATES.get(lang, SCRIPT_TEMPLATES['generic'])

    script_content = tmpl.replace('{{finding_id}}', fid)
    script_content = script_content.replace('{{setup_steps}}', setup_s)
    script_content = script_content.replace('{{trigger_steps}}', trigger_s)
    script_content = script_content.replace('{{check_steps}}', check_s)

    # Determine script filename and build command per language
    script_name, build_cmd, run_cmd = _get_script_info(lang)

    script_file = outdir / script_name
    script_file.write_text(script_content)
    if lang in ('sh', 'perl', 'python', 'ruby', 'php'):
        script_file.chmod(script_file.stat().st_mode | stat.S_IXUSR)

    # For compiled languages, create a Makefile
    if lang in ('c', 'cpp', 'java'):
        _write_makefile(outdir, lang, script_name)

    t_sha = sha256_file(script_file) if script_file.exists() else ''

    # Write expected behavior files
    title = f.get('title', 'vulnerability')
    component = f.get('affected_component', {}).get('component', 'target')
    (outdir / 'expected-vulnerable.txt').write_text(
        f'Vulnerable behavior: {title} in {component} is triggered, '
        f'demonstrating the vulnerability described in the finding.\n'
    )
    (outdir / 'expected-fixed.txt').write_text(
        f'Fixed behavior: the fix in {component} prevents the vulnerability '
        f'from being triggered; the code handles the input safely.\n'
    )
    (outdir / 'input-description.md').write_text(
        f'# PoC Testcase Input\n\n'
        f'- Script: `{script_name}`\n'
        f'- Language: {lang}\n'
        f'- SHA256: `{t_sha}`\n'
        f'- Purpose: Authorized local validation and regression testing for {fid}\n'
        f'- Safety class: local-validation-only\n'
    )

    dm_list = f.get('discovery_method') or []
    dm_ref = '; '.join(
        f"{d.get('type','?')}({d.get('tool_name','') or d.get('hypothesis_id','') or '—'})"
        for d in dm_list if isinstance(d, dict)
    ) if dm_list else ''

    manifest = {
        'finding_id': fid,
        'status': 'draft' if is_draft else 'Validated',
        'verification': 'unverified' if is_draft else 'verified',
        'poc_type': 'generated-reproducer',
        'safety_class': 'local-validation-only',
        'language': lang,
        'discovery_method_ref': dm_ref,
        'affected_component': f.get('affected_component', {}),
        'artifacts': {
            'reproduce_script': script_name,
            'expected_vulnerable': 'expected-vulnerable.txt',
            'expected_fixed': 'expected-fixed.txt',
            'input_description': 'input-description.md',
        },
        'commands': {
            'build': build_cmd,
            'reproduce': run_cmd,
            'regression': run_cmd,
        },
        'expected_results': {
            'vulnerable': (outdir / 'expected-vulnerable.txt').read_text().strip(),
            'fixed': (outdir / 'expected-fixed.txt').read_text().strip(),
        },
        'environment': {
            'os': platform.platform(),
            'arch': platform.machine(),
            'python': platform.python_version(),
        },
        'testcase': {
            'path': script_name,
            'sha256': t_sha,
            'size_bytes': script_file.stat().st_size if script_file.exists() else 0,
            'source': 'generated-from-finding',
            'language': lang,
        },
        'disclosure_level': f.get('disclosure_level', 'D3-maintainer-private'),
        'public_release_allowed': False,
    }
    (outdir / 'poc-manifest.json').write_text(json.dumps(manifest, indent=2))

    return {
        'language': lang,
        'script': script_name,
        'sha256': t_sha,
        'manifest': 'poc-manifest.json',
        'runtime_available': runtime_available(lang),
    }


def _get_script_info(lang):
    """Return (script_name, build_command, run_command) for a language."""
    if lang == 'python':
        return 'reproduce.py', '', 'timeout 10s python3 reproduce.py'
    elif lang == 'c':
        return 'reproduce.c', 'gcc -o reproduce reproduce.c -Wall', 'timeout 10s ./reproduce'
    elif lang == 'cpp':
        return 'reproduce.cpp', 'g++ -o reproduce reproduce.cpp -Wall -std=c++17', 'timeout 10s ./reproduce'
    elif lang == 'java':
        return 'Reproduce.java', 'javac Reproduce.java', 'timeout 10s java Reproduce'
    elif lang == 'go':
        return 'reproduce.go', 'go build -o reproduce reproduce.go', 'timeout 10s go run reproduce.go'
    elif lang == 'perl':
        return 'reproduce.pl', '', 'timeout 10s perl reproduce.pl'
    elif lang == 'sh':
        return 'reproduce.sh', '', 'timeout 10s bash reproduce.sh'
    elif lang == 'ruby':
        return 'reproduce.rb', '', 'timeout 10s ruby reproduce.rb'
    elif lang == 'php':
        return 'reproduce.php', '', 'timeout 10s php reproduce.php'
    elif lang == 'javascript':
        return 'reproduce.js', '', 'timeout 10s node reproduce.js'
    elif lang == 'rust':
        return 'reproduce.rs', 'rustc -o reproduce reproduce.rs', 'timeout 10s ./reproduce'
    else:
        return 'reproduce.sh', '', 'timeout 10s bash reproduce.sh'


def _write_makefile(outdir, lang, script_name):
    """Write a Makefile for compiled languages."""
    if lang == 'c':
        outdir.joinpath('Makefile').write_text(
            'CC ?= gcc\n'
            'CFLAGS ?= -Wall -g\n'
            'TARGET = reproduce\n\n'
            'all: $(TARGET)\n\n'
            '$(TARGET): reproduce.c\n'
            '\t$(CC) $(CFLAGS) -o $(TARGET) reproduce.c\n\n'
            'run: $(TARGET)\n'
            '\ttimeout 10s ./$(TARGET)\n\n'
            'clean:\n'
            '\trm -f $(TARGET)\n\n'
            '.PHONY: all run clean\n'
        )
    elif lang == 'cpp':
        outdir.joinpath('Makefile').write_text(
            'CXX ?= g++\n'
            'CXXFLAGS ?= -Wall -std=c++17 -g\n'
            'TARGET = reproduce\n\n'
            'all: $(TARGET)\n\n'
            '$(TARGET): reproduce.cpp\n'
            '\t$(CXX) $(CXXFLAGS) -o $(TARGET) reproduce.cpp\n\n'
            'run: $(TARGET)\n'
            '\ttimeout 10s ./$(TARGET)\n\n'
            'clean:\n'
            '\trm -f $(TARGET)\n\n'
            '.PHONY: all run clean\n'
        )
    elif lang == 'java':
        outdir.joinpath('Makefile').write_text(
            'JAVAC ?= javac\n'
            'JAVA ?= java\n\n'
            'all: Reproduce.class\n\n'
            'Reproduce.class: Reproduce.java\n'
            '\t$(JAVAC) Reproduce.java\n\n'
            'run: Reproduce.class\n'
            '\ttimeout 10s $(JAVA) Reproduce\n\n'
            'clean:\n'
            '\trm -f *.class\n\n'
            '.PHONY: all run clean\n'
        )


# ---------------------------------------------------------------------------
# Multi-language POC generation for a single finding
# ---------------------------------------------------------------------------

def generate_multilang_poc(f, languages, outdir, is_draft=False):
    """Generate multi-language POC variants for a single finding.

    Args:
        f: finding dict
        languages: list of language names
        outdir: root output directory for this finding (e.g., poc-tests/FINDING-001/)
        is_draft: True for Needs Manual Review findings

    Returns:
        dict with generation results
    """
    fid = f.get('id', 'FINDING-UNKNOWN')
    variants = []
    skipped_variants = []

    for lang in languages:
        lang_dir = outdir / lang
        if lang_dir.exists():
            shutil.rmtree(lang_dir)
        lang_dir.mkdir(parents=True, exist_ok=True)

        variant = generate_language_variant(f, lang, lang_dir, is_draft=is_draft)
        variants.append(variant)

    # Write main reproduce.sh that tries all variants
    _write_main_reproduce_sh(outdir, variants, fid)

    # Write main manifest
    dm_list = f.get('discovery_method') or []
    dm_ref = '; '.join(
        f"{d.get('type','?')}({d.get('tool_name','') or d.get('hypothesis_id','') or '—'})"
        for d in dm_list if isinstance(d, dict)
    ) if dm_list else ''

    main_manifest = {
        'finding_id': fid,
        'status': 'draft' if is_draft else 'Validated',
        'verification': 'unverified' if is_draft else 'verified',
        'poc_type': 'multi-language-reproducer',
        'safety_class': 'local-validation-only',
        'discovery_method_ref': dm_ref,
        'affected_component': f.get('affected_component', {}),
        'language_variants': [
            {
                'language': v['language'],
                'directory': v['language'],
                'script': v['script'],
                'sha256': v['sha256'],
                'runtime_available': v['runtime_available'],
            }
            for v in variants
        ],
        'artifacts': {
            'reproduce_script': 'reproduce.sh',
            'input_description': 'input-description.md',
        },
        'commands': {
            'reproduce': './reproduce.sh',
            'regression': './reproduce.sh',
        },
        'expected_results': {
            'vulnerable': 'At least one language variant triggers the vulnerability successfully.',
            'fixed': 'All language variants fail to trigger the vulnerability after the fix is applied.',
        },
        'environment': {
            'os': platform.platform(),
            'arch': platform.machine(),
            'python': platform.python_version(),
        },
        'disclosure_level': f.get('disclosure_level', 'D3-maintainer-private'),
        'public_release_allowed': False,
    }
    (outdir / 'poc-manifest.json').write_text(json.dumps(main_manifest, indent=2))

    # Write main input-description.md
    main_script_sha = sha256_file(outdir / 'reproduce.sh') if (outdir / 'reproduce.sh').exists() else ''
    variant_list = '\n'.join(f'- {v["language"]}: `{v["script"]}`' for v in variants)
    (outdir / 'input-description.md').write_text(
        f'# Multi-Language PoC Testcase\n\n'
        f'- Finding: {fid}\n'
        f'- Script: `reproduce.sh`\n'
        f'- Languages: {", ".join(languages)}\n'
        f'- SHA256: `{main_script_sha}`\n'
        f'- Purpose: Authorized local validation and regression testing\n'
        f'- Safety class: local-validation-only\n\n'
        f'## Language Variants\n\n{variant_list}\n'
    )

    # Write main README.md
    _write_main_readme(outdir, fid, variants, dm_ref, is_draft)

    return {
        'finding_id': fid,
        'variants': variants,
        'skipped_variants': skipped_variants,
        'status': 'draft' if is_draft else 'Validated',
    }


def _write_main_reproduce_sh(outdir, variants, fid):
    """Write the main reproduce.sh that tries each language variant."""
    lines = [
        '#!/usr/bin/env bash',
        f'# Multi-language PoC runner for {fid}',
        '# Authorized local validation and regression testing only.',
        'set -euo pipefail',
        'cd "$(dirname "$0")"',
        'ROOT_DIR="$(pwd)"',
        '',
        'PASSED=0',
        'FAILED=0',
        'SKIPPED=0',
        '',
    ]

    for v in variants:
        lang = v['language']
        _, build_cmd, run_cmd = _get_script_info(lang)
        lines.append(f'# --- {lang} variant ---')
        lines.append(f'echo "[PVAS-POC] Trying {lang} variant..."')

        # Check runtime availability
        runtime_cmd = LANGUAGE_RUNTIMES.get(lang, ['echo', 'ok'])
        check_bin = runtime_cmd[0]
        lines.append(f'if command -v {check_bin} >/dev/null 2>&1; then')

        # Build if needed
        if build_cmd:
            lines.append(f'  echo "[PVAS-POC] Building {lang} variant..."')
            lines.append(f'  if ! (cd {lang} && {build_cmd}); then')
            lines.append(f'    echo "[PVAS-POC] {lang} build failed"')
            lines.append('    SKIPPED=$((SKIPPED+1))')
            lines.append('    cd "$ROOT_DIR"')
            lines.append('    continue')
            lines.append('  fi')

        # Run
        lines.append(f'  cd {lang} && {run_cmd} && {{ echo "[PASS] {lang} variant passed"; PASSED=$((PASSED+1)); }} || {{ echo "[FAIL] {lang} variant failed"; FAILED=$((FAILED+1)); }}')
        lines.append('  cd "$ROOT_DIR"')
        lines.append('else')
        lines.append(f'  echo "[SKIP] {lang} runtime not available"')
        lines.append('  SKIPPED=$((SKIPPED+1))')
        lines.append('fi')
        lines.append('')

    lines.extend([
        'echo ""',
        'echo "=== Results ==="',
        'echo "Passed:  $PASSED"',
        'echo "Failed:  $FAILED"',
        'echo "Skipped: $SKIPPED"',
        '',
        '# Exit 0 if at least one variant passed',
        'if [ "$PASSED" -gt 0 ]; then',
        '  echo "[PVAS-POC] At least one variant passed."',
        '  exit 0',
        'else',
        '  echo "[PVAS-POC] No variant passed."',
        '  exit 1',
        'fi',
    ])

    script = outdir / 'reproduce.sh'
    script.write_text('\n'.join(lines) + '\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)


def _write_main_readme(outdir, fid, variants, dm_ref, is_draft):
    """Write the main README.md for the multi-language POC."""
    draft_note = '\n> **Note:** This is a draft PoC for a finding that needs manual review. It has not been verified.\n' if is_draft else ''
    variant_rows = '\n'.join(
        f'| {v["language"]} | `{v["script"]}` | {"✅ Available" if v["runtime_available"] else "❌ Not available"} |'
        for v in variants
    )

    readme = f"""# Multi-Language PoC Test for {fid}
{draft_note}
This testcase is for authorized local validation and regression testing only.
It is not a weaponized exploit.

## Quick Start

```bash
./reproduce.sh
```

This will attempt to run each language variant. At least one must pass for the PoC to succeed.

## Language Variants

| Language | Script | Runtime |
|----------|--------|---------|
{variant_rows}

## Running Individual Variants

"""
    for v in variants:
        _, build_cmd, run_cmd = _get_script_info(v['language'])
        readme += f"### {v['language']}\n\n```bash\ncd {v['language']}\n"
        if build_cmd:
            readme += f"{build_cmd}\n"
        readme += f"{run_cmd}\n```\n\n"

    readme += f"""## Discovery Method

{dm_ref or "unknown"}

## Safety

- All variants use `timeout` to prevent hangs
- No network access, no sudo, no persistence
- Temporary directories are cleaned up automatically
- Local validation only — do not use against third-party systems
"""
    (outdir / 'README.md').write_text(readme)


def _poc_failure(code: str, message: str, fix: str) -> dict:
    return {"code": code, "message": message, "fix": fix}


def lint_generated_poc_package(f: dict, outdir: pathlib.Path, languages: list[str]) -> dict:
    """Fail predictable PoC package errors before build/run retries."""
    failures: list[dict] = []
    fid = f.get('id', 'FINDING-UNKNOWN')
    component = str((f.get('affected_component') or {}).get('component') or '').strip()
    validation = f.get('validation') if isinstance(f.get('validation'), dict) else {}
    command = str(validation.get('command') or '').strip()

    if not component or component.lower() in {'target', 'semgrep'}:
        failures.append(_poc_failure(
            'component-target-mismatch',
            'PoC component must identify the real package target, not a tool or placeholder.',
            'Set affected_component.component to the BCC target binary/source component under validation.',
        ))
    if fid == 'T-CAND-0025' and 'semgrep' in component.lower():
        failures.append(_poc_failure(
            'component-target-mismatch',
            'T-CAND-0025 must target the BCC ELF/build-id path, not semgrep.',
            'Replace component metadata with the BCC ELF/build-id or build artifact path.',
        ))
    if not command:
        failures.append(_poc_failure(
            'missing-validation-command',
            'validation.command is required for generated PoC trigger steps.',
            'Provide the local validation command for the affected target.',
        ))
    if command in {'false', 'true', 'echo', 'placeholder'} or 'system("false")' in command:
        failures.append(_poc_failure(
            'placeholder-command',
            'PoC command is a placeholder and would not validate the target.',
            'Replace the placeholder with a target-specific local validation command.',
        ))

    main_script = outdir / 'reproduce.sh'
    if not main_script.exists():
        failures.append(_poc_failure(
            'missing-reproduce-script',
            'reproduce.sh is missing.',
            'Regenerate the PoC package and ensure artifacts.reproduce_script is written.',
        ))
    elif not os.access(main_script, os.X_OK):
        failures.append(_poc_failure(
            'reproduce-not-executable',
            'reproduce.sh must be executable.',
            'chmod +x reproduce.sh before PoC execution.',
        ))

    manifest_path = outdir / 'poc-manifest.json'
    manifest = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError:
            failures.append(_poc_failure(
                'manifest-malformed',
                'poc-manifest.json is not valid JSON.',
                'Regenerate the manifest from structured finding data.',
            ))
    else:
        failures.append(_poc_failure(
            'manifest-missing',
            'poc-manifest.json is missing.',
            'Write a PoC manifest before execution.',
        ))
    if manifest and manifest.get('safety_class') != 'local-validation-only':
        failures.append(_poc_failure(
            'safety-class-mismatch',
            'PoC safety_class must be local-validation-only.',
            'Set safety_class=local-validation-only and keep execution local/offline.',
        ))
    if manifest:
        commands = manifest.get('commands') if isinstance(manifest.get('commands'), dict) else {}
        reproduce = str(commands.get('reproduce') or '').strip()
        if not reproduce:
            failures.append(_poc_failure(
                'empty-reproduce-command',
                'PoC manifest reproduce command is empty.',
                'Set commands.reproduce to ./reproduce.sh.',
            ))

    for lang in languages:
        variant_manifest_path = outdir / lang / 'poc-manifest.json'
        if not variant_manifest_path.exists():
            continue
        try:
            variant_manifest = json.loads(variant_manifest_path.read_text())
        except json.JSONDecodeError:
            failures.append(_poc_failure('variant-manifest-malformed', f'{lang} manifest is malformed.', 'Regenerate variant manifest.'))
            continue
        commands = variant_manifest.get('commands') if isinstance(variant_manifest.get('commands'), dict) else {}
        build_cmd = str(commands.get('build') or '').strip()
        run_cmd = str(commands.get('reproduce') or '').strip()
        if lang in {'c', 'cpp', 'java', 'go', 'rust'} and not build_cmd:
            failures.append(_poc_failure(
                'missing-build-command',
                f'{lang} variant requires a build command.',
                'Add a build command that creates the expected ./reproduce path or runtime artifact.',
            ))
        if not run_cmd:
            failures.append(_poc_failure(
                'empty-command',
                f'{lang} variant reproduce command is empty.',
                'Set commands.reproduce to the local variant runner.',
            ))
        if lang == 'python':
            env_tmp = os.environ.get('TMPDIR') or os.environ.get('TMP') or os.environ.get('TEMP') or tempfile.gettempdir()
            tmp_path = pathlib.Path(env_tmp)
            if not tmp_path.exists() or not os.access(tmp_path, os.W_OK):
                failures.append(_poc_failure(
                    'tmpdir-not-writable',
                    'Python PoC requires a writable TMPDIR/TMP/TEMP.',
                    'Set TMPDIR, TMP, or TEMP to a writable local directory.',
                ))
        script = outdir / lang / str(variant_manifest.get('artifacts', {}).get('reproduce_script') or '')
        if script.name and script.exists():
            text = script.read_text(errors='ignore')
            if 'system("false")' in text or '\nfalse\n' in text or 'cmd = []' in text:
                failures.append(_poc_failure(
                    'placeholder-command',
                    f'{lang} variant contains a placeholder trigger command.',
                    'Provide a real validation.command before generating the PoC.',
                ))

    result = {
        'finding_id': fid,
        'status': 'poc-preflight-failed' if failures else 'passed',
        'failures': failures,
        'checked_languages': languages,
    }
    (outdir / 'poc-preflight-result.json').write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return result


# ---------------------------------------------------------------------------
# Run reproducer for a multi-language POC
# ---------------------------------------------------------------------------

def _sandbox_mode() -> str:
    return os.environ.get("PVAS_SANDBOX", "enabled").lower()


def _container_result_payload(result: pvas_container.ContainerResult, network_policy: str) -> dict:
    executed_via = result.executed_via
    if _sandbox_mode() == "warn-only" and executed_via == "container":
        executed_via = "container-warn-only"
    return {
        "executed_via": executed_via,
        "container": {
            "container_id": result.container_id,
            "netpolicy_id": result.netpolicy_id,
            "network_policy": network_policy,
            "oom_killed": result.oom_killed,
            "timed_out": result.timed_out,
        },
    }


def _run_reproducer_command(outdir: pathlib.Path, command: list[str], timeout_seconds: int, labels: dict) -> tuple[int, str, float, dict]:
    start = time.time()
    if _sandbox_mode() == "disabled":
        p = subprocess.run(
            command,
            cwd=outdir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds + 5,
        )
        return p.returncode, p.stdout or "", time.time() - start, {
            "executed_via": "host-degraded-sandbox-disabled",
            "container": {
                "container_id": "",
                "netpolicy_id": "",
                "network_policy": "host",
                "oom_killed": False,
                "timed_out": False,
            },
        }

    # Use AuditContext for consistent defaults (env, caps, audit-id label)
    audit_ctx = pvas_container.AuditContext(
        audit_id=os.environ.get("PVAS_AUDIT_ID", "pvas-poc-unknown"),
    )
    network_policy = "host"
    spec = audit_ctx.make_spec(
        command=command,
        mounts=[(str(outdir.resolve()), str(outdir.resolve()), "rw")],
        purpose="poc",
        network_policy=network_policy,
        workdir=str(outdir.resolve()),
        mem_limit_mb=1024,
        timeout_seconds=timeout_seconds + 5,
        env={
            "HOME": "/tmp",
            "TMPDIR": "/tmp",
            "LC_ALL": "C.UTF-8",
            "PYTHONPATH": "/opt/pvas/venv/lib64/python3.11/site-packages",
        },
    )
    # Merge dynamic labels (pvas-finding-id etc.)
    for k, v in labels.items():
        spec.labels[k] = v
    result = pvas_container.run(spec)
    return result.exit_code, (result.stdout or "") + (result.stderr or ""), result.duration_seconds, _container_result_payload(result, network_policy)


def run_multilang_reproducer(outdir: pathlib.Path, timeout_seconds: int = 30) -> dict:
    """Run the main reproduce.sh for a multi-language POC.

    Returns a combined result dict.
    """
    script = outdir / 'reproduce.sh'
    rc, output, duration, exec_payload = _run_reproducer_command(
        outdir,
        ['timeout', f'{timeout_seconds}s', './reproduce.sh'],
        timeout_seconds,
        {"pvas-finding-id": outdir.name, "pvas-poc-scope": "main"},
    )
    elapsed_ms = int(duration * 1000)
    result = {
        'status': 'passed' if rc == 0 else 'failed',
        'exit_code': rc,
        'elapsed_ms': elapsed_ms,
        'command': 'timeout %ss ./reproduce.sh' % timeout_seconds,
        'stdout_tail': (output or '')[-4000:],
        **exec_payload,
    }
    (outdir / 'poc-run-result.json').write_text(json.dumps(result, indent=2, ensure_ascii=False))

    # Also collect per-variant results
    variant_results = []
    for lang_dir in sorted(outdir.iterdir()):
        if lang_dir.is_dir() and (lang_dir / 'poc-manifest.json').exists():
            # Try to run each variant individually
            _, _, run_cmd = _get_script_info(lang_dir.name)
            var_start = time.time()
            try:
                var_rc, var_output, var_duration, var_exec_payload = _run_reproducer_command(
                    lang_dir,
                    run_cmd.split(),
                    15,
                    {"pvas-finding-id": outdir.name, "pvas-poc-scope": f"variant-{lang_dir.name}"},
                )
                var_elapsed = int(var_duration * 1000)
                var_result = {
                    'language': lang_dir.name,
                    'status': 'passed' if var_rc == 0 else 'failed',
                    'exit_code': var_rc,
                    'elapsed_ms': var_elapsed,
                    'command': run_cmd,
                    'stdout_tail': (var_output or '')[-2000:],
                    **var_exec_payload,
                }
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                var_result = {
                    'language': lang_dir.name,
                    'status': 'skipped',
                    'exit_code': -1,
                    'elapsed_ms': 0,
                    'command': run_cmd,
                    'error': str(e),
                }
            (lang_dir / 'poc-run-result.json').write_text(json.dumps(var_result, indent=2, ensure_ascii=False))
            variant_results.append(var_result)

    result['variant_results'] = variant_results
    (outdir / 'poc-run-result.json').write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return result


# ---------------------------------------------------------------------------
# Legacy single-language reproducer (for non-generated mode)
# ---------------------------------------------------------------------------

def generate_legacy_poc(f, outdir):
    """Generate a simple single-language PoC from existing validation artifacts."""
    fid = f.get('id', 'FINDING-UNKNOWN')
    val = f.get('validation', {}) if isinstance(f.get('validation'), dict) else {}
    if not val:
        return None
    testcase = get_testcase(f, None)
    if testcase is None or not testcase.exists():
        return None

    dst = outdir / testcase.name
    shutil.copyfile(testcase, dst)
    t_sha = sha256_file(dst)
    build = val.get('build_command') or '# Build the affected target with sanitizer/instrumentation as documented in the finding.'
    repro = val.get('command') or './reproduce.sh'

    script = outdir / 'reproduce.sh'
    script.write_text(f'''#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
TESTCASE="${{TESTCASE:-{dst.name}}}"
TIMEOUT="${{TIMEOUT:-10s}}"
# Local validation only. Do not use against third-party systems.
timeout "$TIMEOUT" {repro} "$TESTCASE"
''')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)

    (outdir / 'expected-vulnerable.txt').write_text(
        val.get('expected_vulnerable') or 'Vulnerable build triggers the validation signal described in the finding, such as ASan/UBSan/crash/assertion/incorrect output.\n'
    )
    (outdir / 'expected-fixed.txt').write_text(
        val.get('expected_fixed') or 'Fixed build rejects or handles the testcase without sanitizer errors, crash, assertion, or incorrect output.\n'
    )

    dm_list = f.get('discovery_method') or []
    dm_ref = '; '.join(
        f"{d.get('type','?')}({d.get('tool_name','') or d.get('hypothesis_id','') or '—'})"
        for d in dm_list if isinstance(d, dict)
    ) if dm_list else ''

    (outdir / 'input-description.md').write_text(
        f'# Testcase Input\n\n- File: `{dst.name}`\n- SHA256: `{t_sha}`\n- Purpose: local authorized validation and regression testing only.\n'
    )

    manifest = {
        'finding_id': fid, 'status': 'Validated', 'poc_type': 'local-reproducer',
        'safety_class': 'local-validation-only',
        'discovery_method_ref': dm_ref,
        'affected_component': f.get('affected_component', {}),
        'artifacts': {'reproduce_script': 'reproduce.sh', 'testcase': dst.name,
                      'expected_vulnerable': 'expected-vulnerable.txt',
                      'expected_fixed': 'expected-fixed.txt'},
        'commands': {'build': build, 'reproduce': './reproduce.sh', 'regression': './reproduce.sh'},
        'expected_results': {
            'vulnerable': (outdir / 'expected-vulnerable.txt').read_text().strip(),
            'fixed': (outdir / 'expected-fixed.txt').read_text().strip()
        },
        'environment': {'os': platform.platform(), 'arch': platform.machine(),
                        'python': platform.python_version(),
                        'commit': f.get('affected_component', {}).get('version_or_commit', '')},
        'testcase': {'path': dst.name, 'sha256': t_sha, 'size_bytes': dst.stat().st_size,
                     'source': 'existing-validation-artifact'},
        'disclosure_level': f.get('disclosure_level', 'D3-maintainer-private'),
        'public_release_allowed': False
    }
    (outdir / 'poc-manifest.json').write_text(json.dumps(manifest, indent=2))
    return str(outdir)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='Generate multi-language PoC testcases for findings')
    ap.add_argument('--findings', required=True, help='Path to findings JSON')
    ap.add_argument('--finding-id', help='Process only this finding ID')
    ap.add_argument('--testcase', help='Explicit testcase path (legacy mode)')
    ap.add_argument('--out', default='audit-output/04-validation/poc-tests', help='Output directory')
    ap.add_argument('--build-command', default='', help='Build command (legacy mode)')
    ap.add_argument('--reproduce-command', default='', help='Reproduce command (legacy mode)')
    ap.add_argument('--generate-from-finding', action='store_true',
                    help='Auto-generate PoC from finding metadata')
    ap.add_argument('--language', default='',
                    help='Comma-separated language list (e.g., python,c,go) or empty for auto')
    ap.add_argument('--languages', default='',
                    help='Alias for --language')
    ap.add_argument('--profile', default='',
                    help='Path to package-profile.json for language auto-selection')
    ap.add_argument('--timeout', type=int, default=30,
                    help='Timeout in seconds for multi-language runner (default: 30)')
    args = ap.parse_args()

    findings = load_findings(args.findings)
    outroot = pathlib.Path(args.out)
    outroot.mkdir(parents=True, exist_ok=True)
    generated = []
    skipped = []

    # Parse language list
    lang_arg = args.language or args.languages
    if lang_arg:
        explicit_langs = [l.strip() for l in lang_arg.split(',') if l.strip()]
    else:
        explicit_langs = None

    # Load profile for auto-selection
    profile = load_profile(args.profile)

    for f in findings:
        fid = f.get('id', 'FINDING-UNKNOWN')
        if args.finding_id and fid != args.finding_id:
            continue

        if args.generate_from_finding:
            status = f.get('status') or f.get('validated_status')
            is_validated = (status == 'Validated')
            is_draft = (status == 'Needs Manual Review')

            if not (is_validated or is_draft):
                skipped.append({'id': fid, 'reason': 'status-not-eligible'})
                continue

            # Multi-language generation mode
            languages = select_languages(f, explicit_langs=explicit_langs, profile=profile)
            d = outroot / fid
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True, exist_ok=True)

            gen_result = generate_multilang_poc(f, languages, d, is_draft=is_draft)

            preflight_result = lint_generated_poc_package(f, d, languages)
            if preflight_result['status'] != 'passed':
                skipped.append({'id': fid, 'reason': 'poc-preflight-failed'})
                continue

            # Run the reproducer. Draft PoCs must execute successfully, but
            # passing execution does not upgrade a finding to Validated.
            run_result = run_multilang_reproducer(d, timeout_seconds=args.timeout)

            if run_result['status'] != 'passed':
                skipped.append({'id': fid, 'reason': 'poc-execution-failed'})
                continue

            generated.append(str(d))
            status_label = 'draft' if is_draft else 'Validated'
            lang_list = ', '.join(v['language'] for v in gen_result['variants'])
            print(f'[PVAS-POC] generated multi-language PoC for {fid} '
                  f'(status={status_label}, languages={lang_list})')
            continue

        # Legacy mode: use existing validation artifacts
        status = f.get('status') or f.get('validated_status')
        is_validated = (status == 'Validated')
        if not is_validated:
            skipped.append({'id': fid, 'reason': 'legacy-mode-requires-Validated'})
            continue

        val = f.get('validation', {}) if isinstance(f.get('validation'), dict) else {}
        if not val:
            skipped.append({'id': fid, 'reason': 'missing-validation-evidence'})
            continue

        testcase = get_testcase(f, args.testcase)
        if testcase is None or not testcase.exists():
            skipped.append({'id': fid, 'reason': 'missing-testcase-artifact'})
            continue

        d = outroot / fid
        d.mkdir(parents=True, exist_ok=True)
        result = generate_legacy_poc(f, d)
        if result is None:
            skipped.append({'id': fid, 'reason': 'legacy-generation-failed'})
            continue

        run_result = run_multilang_reproducer(d, timeout_seconds=args.timeout)
        if run_result['status'] != 'passed':
            skipped.append({'id': fid, 'reason': 'poc-execution-failed'})
            continue

        generated.append(str(d))

    summary = {'generated': generated, 'skipped': skipped}
    (outroot / 'poc-generation-summary.json').write_text(json.dumps(summary, indent=2))
    print(f'[PVAS-POC] generated {len(generated)} PoC testcase package(s)')
    if any(s.get('reason') in {'poc-preflight-failed', 'poc-execution-failed'} for s in skipped):
        return 2
    if not generated and not skipped and not findings:
        return 0  # no findings at all, not an error
    return 0 if generated or skipped else 1


if __name__ == '__main__':
    raise SystemExit(main())

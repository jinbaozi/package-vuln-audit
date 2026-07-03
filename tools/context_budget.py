#!/usr/bin/env python3
import argparse, fnmatch, json, os, pathlib, sys

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from budget_common import est_tokens, batch_packets

import manifest_io
from pvas_io import load_json, write_json

DEFAULT_AGENT_BUDGET=int(os.getenv('PVAS_AGENT_CONTEXT_BUDGET_TOKENS','200000'))
DEFAULT_TARGET=int(os.getenv('PVAS_AGENT_INPUT_TARGET_TOKENS','140000'))
DEFAULT_WARNING=int(os.getenv('PVAS_AGENT_INPUT_WARNING_TOKENS','170000'))
DEFAULT_HARD=int(os.getenv('PVAS_AGENT_HARD_INPUT_LIMIT_TOKENS','180000'))
DEFAULT_RESERVE=int(os.getenv('PVAS_AGENT_OUTPUT_RESERVE_TOKENS','20000'))
PACKET_BUDGET=int(os.getenv('PVAS_PACKET_BUDGET_TOKENS','8000'))
BATCH_BUDGET=int(os.getenv('PVAS_PACKET_REVIEW_BATCH_TOKENS','160000'))
MAX_PACKET_COUNT=int(os.getenv('PVAS_MAX_PACKET_COUNT_PER_REVIEW','20'))
LONG_CONTEXT_MODE=os.getenv('PVAS_LONG_CONTEXT_MODE','off')
CONTEXT_EFFICIENT_MODE=os.getenv('PVAS_CONTEXT_EFFICIENT','1').lower() not in {'0','false','no','off'}

ROLE_TARGETS={
  'coordinator': (40000, ['summary','index','profile','budget'], ['full_repository','raw_source_dump','raw_tool_log','raw_fuzz_log','full_build_log','all_candidate_packets']),
  'package-profiler': (80000, ['traversal_manifest','profile','build_summary','file_index_summary'], ['full_repository','raw_source_dump']),
  'tool-runner': (30000, ['tool_config','profile','budget'], ['raw_source_dump']),
  'result-normalizer': (100000, ['raw_tool_log','tool_result','summary'], ['full_repository','raw_source_dump']),
  'hypothesis-hunter': (120000, ['recipe','module_summary','code_slice','profile'], ['full_repository','raw_tool_log','raw_fuzz_log']),
  'candidate-reviewer': (140000, ['candidate_packet','code_slice','tool_evidence_summary'], ['full_repository','raw_tool_log','raw_fuzz_log']),
  'validator': (100000, ['likely_candidate','validation_log_summary','testcase_metadata'], ['full_repository','raw_tool_log']),
  'cvss-scorer': (50000, ['validated_finding','validation_summary','impact_summary'], ['raw_tool_log','raw_source_dump']),
  'report-writer': (100000, ['validated_finding','finding_index','cvss','evidence_summary'], ['raw_tool_log','raw_fuzz_log','full_build_log','raw_source_dump']),
  'disclosure-coordinator': (70000, ['validated_finding','maintainer_private_summary','disclosure_policy'], ['raw_tool_log','raw_fuzz_log','raw_source_dump'])
}

def count_tokens_file(path: pathlib.Path) -> int:
    try:
        return est_tokens(path.read_text(errors='ignore'))
    except Exception:
        return 0

def role_profiles():
    out={}
    for role,(target,allowed,forbidden) in ROLE_TARGETS.items():
        warning=min(DEFAULT_WARNING, max(target + 30000, int(target*1.25)))
        hard=min(DEFAULT_HARD, max(warning + 10000, int(target*1.35)))
        out[role]={
            'context_budget_tokens': DEFAULT_AGENT_BUDGET,
            'target_input_tokens': target,
            'warning_tokens': warning,
            'hard_input_limit_tokens': hard,
            'allowed_artifact_classes': allowed,
            'forbidden_artifact_classes': forbidden
        }
    return out

def load_traversal(profile_dir: pathlib.Path):
    manifest=profile_dir/'traversal-manifest.json'
    if manifest.exists():
        try: return load_json(manifest, default={})
        except Exception as e:
            print(f'[PVAS-BUDGET] Warning: failed to load traversal manifest: {e}', file=sys.stderr)
    all_files=(profile_dir/'all-files.txt').read_text(errors='ignore').splitlines() if (profile_dir/'all-files.txt').exists() else []
    source_files=(profile_dir/'source-files.txt').read_text(errors='ignore').splitlines() if (profile_dir/'source-files.txt').exists() else []
    return {'all_files_count':len(all_files),'source_files_count':len(source_files),'excluded_dirs':[], 'large_files_skipped':0, 'truncated':False}

def packet_entries(packet_dir: pathlib.Path):
    packets=[]
    if not packet_dir.exists(): return packets
    index_path = packet_dir / 'packet-index.json'
    if index_path.exists():
        try:
            data = load_json(index_path, default={})
            indexed = data.get('packets', [])
            if indexed:
                return indexed
        except Exception as e:
            print(f'[PVAS-BUDGET] Warning: failed to load packet-index.json: {e}', file=sys.stderr)
    for p in sorted(packet_dir.glob('*.md')):
        tokens=count_tokens_file(p)
        packets.append({'id':p.stem,'file':str(p),'estimated_tokens':tokens,'within_budget':tokens <= PACKET_BUDGET})
    return packets

def packet_index_metadata(packet_dir: pathlib.Path) -> dict:
    index_path = packet_dir / 'packet-index.json'
    if not index_path.exists():
        return {}
    try:
        data = load_json(index_path, default={})
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f'[PVAS-BUDGET] Warning: failed to load packet-index metadata: {e}', file=sys.stderr)
        return {}

def load_l4_patterns(root: pathlib.Path) -> list[str]:
    manifest = manifest_io.manifest_path(root)
    if not manifest.is_file():
        return []
    return manifest_io.l4_forbidden_patterns(manifest_io.load_manifest(manifest))

def path_hits_l4(path: str, patterns: list[str]) -> bool:
    norm = path.replace('\\', '/')
    parts = [p for p in norm.split('/') if p]
    basename = parts[-1] if parts else ''
    explicit = (
        basename in {'all-files.txt', 'source-files.txt'}
        or 'raw' in parts
        or basename == 'packets'
        or 'packet-full' in norm
    )
    return explicit or any(fnmatch.fnmatch(norm, p) for p in patterns)

def check_coordinator_paths(paths: list[str], root: pathlib.Path) -> list[str]:
    patterns = load_l4_patterns(root)
    if not patterns:
        return []
    issues = []
    for path in paths:
        if path_hits_l4(path, patterns):
            issues.append(f'coordinator packet contains L4 artifact: {path}')
    return issues

def decide(max_single, batches):
    if max_single > DEFAULT_AGENT_BUDGET:
        return 'blocked', 'A single invocation would exceed the per-agent 200K hard window.'
    if max_single > DEFAULT_HARD:
        return 'truncate-required', 'Reduce packet size, context lines, or attached artifacts before review.'
    if max_single > DEFAULT_WARNING:
        return 'warning', 'Proceed only if needed; prefer reducing attached context.'
    if len(batches) > 1:
        return 'split-required', 'Split candidate review across independent subagent invocations.'
    return 'safe', 'Proceed with current per-agent context budget.'

def build_budget(profile_dir, packet_dir, check_paths=None, root=None):
    traversal=load_traversal(profile_dir)
    packet_index=packet_index_metadata(packet_dir)
    packets=packet_entries(packet_dir)
    batches=batch_packets(packets, BATCH_BUDGET, MAX_PACKET_COUNT)
    max_batch=max([b['estimated_tokens'] for b in batches] or [0])
    total_packets=sum(p['estimated_tokens'] for p in packets)
    decision, action=decide(max_batch, batches)
    issues = []
    if packet_index.get('coverage_complete') is False:
        decision = 'blocked'
        action = 'Regenerate or split candidate packets; packet-index reports incomplete coverage.'
        issues.append('packet-index coverage_complete=false')
    blocked_packets = [
        str(p.get('id') or p.get('file') or '?') for p in packets
        if isinstance(p, dict) and p.get('within_budget') is False
    ]
    if blocked_packets:
        decision = 'blocked'
        action = 'Regenerate oversized packets with smaller source slices before review.'
        issues.extend(f'packet exceeds budget: {pid}' for pid in blocked_packets[:20])
    if check_paths and root is not None:
        l4_issues = check_coordinator_paths(check_paths, root)
        if l4_issues:
            issues.extend(l4_issues)
            decision = 'blocked'
            action = 'Remove L4 artifacts from the coordinator packet; coordinator must read L1 summaries only.'
    budget = {
      'policy': {
        'budget_model': 'per-agent-independent-context',
        'default_agent_context_budget_tokens': DEFAULT_AGENT_BUDGET,
        'agent_input_target_tokens': DEFAULT_TARGET,
        'agent_input_warning_tokens': DEFAULT_WARNING,
        'agent_hard_input_limit_tokens': DEFAULT_HARD,
        'agent_output_reserve_tokens': DEFAULT_RESERVE,
        'long_context_mode': LONG_CONTEXT_MODE,
        'context_efficient_mode': CONTEXT_EFFICIENT_MODE,
        'context_efficient_semantics': 'raw artifacts remain on disk; coordinator reads summaries; tool and candidate coverage are not reduced',
        'note': '200K is a per-agent hard context window, not a workflow-wide shared budget and not a target payload size.'
      },
      'agents': role_profiles(),
      'traversal': traversal,
      'candidate_packets': {
        'packet_budget_tokens': PACKET_BUDGET,
        'review_batch_tokens': BATCH_BUDGET,
        'max_packet_count_per_review': MAX_PACKET_COUNT,
        'expected_candidate_count': packet_index.get('expected_candidate_count', len(packets)),
        'packet_count': packet_index.get('packet_count', len(packets)),
        'batch_count': packet_index.get('batch_count', len(batches)),
        'deduplicated_slice_count': packet_index.get('deduplicated_slice_count', len(packets)),
        'coverage_complete': packet_index.get('coverage_complete', True),
        'estimated_total_tokens': total_packets,
        'packets': packets,
        'batches': batches,
        'summary_only_merge': True
      },
      'run_cost_telemetry': {
        'estimated_invocation_count': len(batches),
        'estimated_max_single_invocation_tokens': max_batch,
        'estimated_total_tokens_across_agents': total_packets,
        'note': 'This is cost telemetry, not a shared context-window limit.'
      },
      'decision': decision,
      'recommended_action': action
    }
    if issues:
        budget['issues'] = issues
    return budget

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--profile-dir', default='audit-output/01-profile')
    ap.add_argument('--packet-dir', default='audit-output/03-candidates/packets')
    ap.add_argument('--out', default='audit-output/01-profile/context-budget.json')
    ap.add_argument('--root', default=str(pathlib.Path(__file__).resolve().parents[1]))
    ap.add_argument('--check-paths', default='', help='Comma-separated artifact paths for coordinator packet L4 guard')
    args=ap.parse_args()
    check_paths = [p.strip() for p in args.check_paths.split(',') if p.strip()] if args.check_paths else None
    budget=build_budget(pathlib.Path(args.profile_dir), pathlib.Path(args.packet_dir), check_paths=check_paths, root=pathlib.Path(args.root))
    write_json(args.out, budget)
    summary = {'decision': budget['decision'], 'recommended_action': budget['recommended_action']}
    if budget.get('issues'):
        summary['issues'] = budget['issues']
    print(json.dumps(summary, indent=2))

if __name__=='__main__': main()

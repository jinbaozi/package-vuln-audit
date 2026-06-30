#!/usr/bin/env python3
import argparse, json, math, os, pathlib

DEFAULT_AGENT_BUDGET=int(os.getenv('PVAS_AGENT_CONTEXT_BUDGET_TOKENS','200000'))
DEFAULT_TARGET=int(os.getenv('PVAS_AGENT_INPUT_TARGET_TOKENS','140000'))
DEFAULT_WARNING=int(os.getenv('PVAS_AGENT_INPUT_WARNING_TOKENS','170000'))
DEFAULT_HARD=int(os.getenv('PVAS_AGENT_HARD_INPUT_LIMIT_TOKENS','180000'))
DEFAULT_RESERVE=int(os.getenv('PVAS_AGENT_OUTPUT_RESERVE_TOKENS','20000'))
PACKET_BUDGET=int(os.getenv('PVAS_PACKET_BUDGET_TOKENS','8000'))
BATCH_BUDGET=int(os.getenv('PVAS_PACKET_REVIEW_BATCH_TOKENS','160000'))
MAX_PACKET_COUNT=int(os.getenv('PVAS_MAX_PACKET_COUNT_PER_REVIEW','20'))
LONG_CONTEXT_MODE=os.getenv('PVAS_LONG_CONTEXT_MODE','off')

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

def est_tokens_text(s: str) -> int:
    return int(math.ceil(len(s) / 3.5))

def count_tokens_file(path: pathlib.Path) -> int:
    try:
        return est_tokens_text(path.read_text(errors='ignore'))
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
        try: return json.loads(manifest.read_text())
        except Exception: pass
    all_files=(profile_dir/'all-files.txt').read_text(errors='ignore').splitlines() if (profile_dir/'all-files.txt').exists() else []
    source_files=(profile_dir/'source-files.txt').read_text(errors='ignore').splitlines() if (profile_dir/'source-files.txt').exists() else []
    return {'all_files_count':len(all_files),'source_files_count':len(source_files),'excluded_dirs':[], 'large_files_skipped':0, 'truncated':False}

def packet_entries(packet_dir: pathlib.Path):
    packets=[]
    if not packet_dir.exists(): return packets
    index_path = packet_dir / 'packet-index.json'
    if index_path.exists():
        try:
            data = json.loads(index_path.read_text())
            indexed = data.get('packets', [])
            if indexed:
                return indexed
        except Exception:
            pass
    for p in sorted(packet_dir.glob('*.md')):
        tokens=count_tokens_file(p)
        packets.append({'id':p.stem,'file':str(p),'estimated_tokens':tokens,'within_budget':tokens <= PACKET_BUDGET})
    return packets

def batch_packets(packets):
    batches=[]; cur=[]; cur_tokens=0
    for pkt in packets:
        tok=int(pkt.get('estimated_tokens',0))
        if cur and (len(cur)>=MAX_PACKET_COUNT or cur_tokens + tok > BATCH_BUDGET):
            batches.append({'batch_id':f'batch-{len(batches)+1:03d}','packet_count':len(cur),'estimated_tokens':cur_tokens,'packets':[x['id'] for x in cur]})
            cur=[]; cur_tokens=0
        cur.append(pkt); cur_tokens += tok
    if cur:
        batches.append({'batch_id':f'batch-{len(batches)+1:03d}','packet_count':len(cur),'estimated_tokens':cur_tokens,'packets':[x['id'] for x in cur]})
    return batches

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

def build_budget(profile_dir, packet_dir):
    traversal=load_traversal(profile_dir)
    packets=packet_entries(packet_dir)
    batches=batch_packets(packets)
    max_batch=max([b['estimated_tokens'] for b in batches] or [0])
    total_packets=sum(p['estimated_tokens'] for p in packets)
    decision, action=decide(max_batch, batches)
    return {
      'policy': {
        'budget_model': 'per-agent-independent-context',
        'default_agent_context_budget_tokens': DEFAULT_AGENT_BUDGET,
        'agent_input_target_tokens': DEFAULT_TARGET,
        'agent_input_warning_tokens': DEFAULT_WARNING,
        'agent_hard_input_limit_tokens': DEFAULT_HARD,
        'agent_output_reserve_tokens': DEFAULT_RESERVE,
        'long_context_mode': LONG_CONTEXT_MODE,
        'note': '200K is a per-agent hard context window, not a workflow-wide shared budget and not a target payload size.'
      },
      'agents': role_profiles(),
      'traversal': traversal,
      'candidate_packets': {
        'packet_budget_tokens': PACKET_BUDGET,
        'review_batch_tokens': BATCH_BUDGET,
        'max_packet_count_per_review': MAX_PACKET_COUNT,
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

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--profile-dir', default='audit-output/01-profile')
    ap.add_argument('--packet-dir', default='audit-output/03-candidates/packets')
    ap.add_argument('--out', default='audit-output/01-profile/context-budget.json')
    args=ap.parse_args()
    budget=build_budget(pathlib.Path(args.profile_dir), pathlib.Path(args.packet_dir))
    out=pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(budget, indent=2))
    print(json.dumps({'decision':budget['decision'],'recommended_action':budget['recommended_action']}, indent=2))

if __name__=='__main__': main()

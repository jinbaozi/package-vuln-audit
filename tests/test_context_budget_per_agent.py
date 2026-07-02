#!/usr/bin/env python3
import os
import json, pathlib, subprocess, tempfile, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]

def test_profile_excludes_and_budget():
    print("[context-test] profile", flush=True)
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td); src=td/'src'; src.mkdir()
        (src/'.git').mkdir(); (src/'.git'/'ignored.c').write_text('int ignored;')
        (src/'build').mkdir(); (src/'build'/'ignored.c').write_text('int ignored;')
        (src/'main.c').write_text('int main(){return 0;}')
        out=td/'audit-output'/'01-profile'
        subprocess.check_call(['bash', str(ROOT/'tools/profile_project.sh'), str(src), str(out)])
        manifest=json.loads((out/'traversal-manifest.json').read_text())
        budget=json.loads((out/'context-budget.json').read_text())
        assert manifest['source_files_count'] == 1
        assert budget['policy']['budget_model'] == 'per-agent-independent-context'
        assert budget['policy']['default_agent_context_budget_tokens'] == 200000
        assert budget['agents']['coordinator']['target_input_tokens'] < budget['agents']['candidate-reviewer']['target_input_tokens']
        assert 'raw_tool_log' in budget['agents']['coordinator']['forbidden_artifact_classes']

def test_packet_batching_allows_aggregate_over_200k():
    print("[context-test] batching", flush=True)
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td); packets=td/'packets'; packets.mkdir(); profile=td/'profile'; profile.mkdir()
        (profile/'traversal-manifest.json').write_text(json.dumps({'all_files_count':1,'source_files_count':1,'excluded_dirs':[],'large_files_skipped':0,'truncated':False}))
        for i in range(60):
            (packets/f'CAND-{i:03d}.md').write_text('x' * 28000)  # ~8000 tokens each
        out=td/'context-budget.json'
        subprocess.check_call([sys.executable, str(ROOT/'tools/context_budget.py'), '--profile-dir', str(profile), '--packet-dir', str(packets), '--out', str(out)])
        budget=json.loads(out.read_text())
        assert budget['candidate_packets']['estimated_total_tokens'] > 200000
        assert budget['decision'] == 'split-required'
        assert budget['run_cost_telemetry']['estimated_max_single_invocation_tokens'] <= 200000
        assert len(budget['candidate_packets']['batches']) >= 3

def test_context_efficient_mode_is_reported_without_lowering_coverage():
    print("[context-test] context-efficient", flush=True)
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td); packets=td/'packets'; packets.mkdir(); profile=td/'profile'; profile.mkdir()
        (profile/'traversal-manifest.json').write_text(json.dumps({'all_files_count':1,'source_files_count':1,'excluded_dirs':[],'large_files_skipped':0,'truncated':False}))
        (packets/'CAND-001.md').write_text('x' * 1000)
        out=td/'context-budget.json'
        env=os.environ.copy()
        env['PVAS_CONTEXT_EFFICIENT']='1'
        subprocess.check_call([sys.executable, str(ROOT/'tools/context_budget.py'), '--profile-dir', str(profile), '--packet-dir', str(packets), '--out', str(out)], env=env)
        budget=json.loads(out.read_text())
        assert budget['policy']['context_efficient_mode'] is True
        assert budget['candidate_packets']['coverage_complete'] is True
        assert budget['candidate_packets']['max_packet_count_per_review'] == 20

def test_make_packets_emits_budget_metadata():
    print("[context-test] packets", flush=True)
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td); src=td/'src'; src.mkdir(); (src/'x.c').write_text('\n'.join('int a;' for _ in range(500)))
        cands=[]
        for i in range(25):
            cands.append({'id':f'T-CAND-{i:03d}','type':'T-CAND','status':'Candidate','title':'t','component':'c','source_locations':[{'file':'x.c','start_line':100,'end_line':101}], 'evidence':{}, 'missing_evidence':[]})
        cf=td/'cands.json'; cf.write_text(json.dumps({'candidates':cands}))
        out=td/'packets'
        subprocess.check_call([sys.executable, str(ROOT/'tools/make_ai_packets.py'), '--candidates', str(cf), '--source-root', str(src), '--out', str(out), '--max-packet-count-per-review', '10'])
        idx=json.loads((out/'packet-index.json').read_text())
        assert idx['budget_model'] == 'per-agent-independent-context'
        assert len(idx['batches']) == 3
        assert all('estimated_tokens' in p for p in idx['packets'])
        assert idx['expected_candidate_count'] == 25
        assert idx['packet_count'] == 25
        assert idx['batch_count'] == 3
        assert idx['coverage_complete'] is True
        assert idx['deduplicated_slice_count'] == 1

def test_strict_packet_budget_blocks_single_oversized_packet():
    print("[context-test] strict-packet-budget", flush=True)
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td); src=td/'src'; src.mkdir()
        long_line='A' * 20000
        (src/'x.c').write_text('\n'.join(long_line for _ in range(20)))
        cands=[{'id':'T-CAND-001','type':'T-CAND','status':'Candidate','title':'t','component':'c','source_locations':[{'file':'x.c','start_line':1,'end_line':20}], 'evidence':{'detail':'y' * 20000}, 'missing_evidence':[]}]
        cf=td/'cands.json'; cf.write_text(json.dumps({'candidates':cands}))
        out=td/'packets'
        env=os.environ.copy()
        env['PVAS_PACKET_STRICT_BUDGET']='1'
        p=subprocess.run([
            sys.executable, str(ROOT/'tools/make_ai_packets.py'),
            '--candidates', str(cf),
            '--source-root', str(src),
            '--out', str(out),
            '--packet-token-budget', '100',
        ], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 2
        idx=json.loads((out/'packet-index.json').read_text())
        assert idx['coverage_complete'] is False
        assert idx['blocked_packet_count'] == 1
        assert idx['packets'][0]['status'] == 'blocked-recovery-required'
        assert 'strict budget' in idx['packets'][0]['reason']

def test_candidate_review_summary_requires_complete_coverage():
    print("[context-test] review-coverage", flush=True)
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td); packets=td/'packets'; packets.mkdir()
        reviews=td/'reviews'
        ranked=td/'ranked.json'
        ranked.write_text(json.dumps({'candidates':[
            {'id':'T-CAND-001','missing_evidence':[]},
            {'id':'T-CAND-002','missing_evidence':[]},
        ]}))
        (packets/'T-CAND-001.md').write_text('```text\nint main(){return 0;}\n```')
        out=td/'candidate-summary.json'
        p=subprocess.run([
            sys.executable, str(ROOT/'tools/exec_candidate_review_agent.py'),
            '--ranked-candidates', str(ranked),
            '--packet-dir', str(packets),
            '--review-dir', str(reviews),
            '--summary-out', str(out),
            '--max-candidates', '2',
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert p.returncode == 2
        summary=json.loads(out.read_text())
        assert summary['expected_count'] == 2
        assert summary['reviewed_count'] == 1
        assert summary['coverage_complete'] is False
        assert summary['explicitly_skipped_count'] == 1

def test_coordinator_l4_path_blocked_when_manifest_present():
    print("[context-test] l4-path", flush=True)
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        profile = td / 'profile'
        profile.mkdir()
        packets = td / 'packets'
        packets.mkdir()
        (profile / 'traversal-manifest.json').write_text(json.dumps({
            'all_files_count': 1,
            'source_files_count': 1,
            'excluded_dirs': [],
            'large_files_skipped': 0,
            'truncated': False,
        }))
        out = td / 'context-budget.json'
        subprocess.check_call([
            sys.executable, str(ROOT / 'tools' / 'context_budget.py'),
            '--profile-dir', str(profile),
            '--packet-dir', str(packets),
            '--out', str(out),
            '--root', str(ROOT),
            '--check-paths', 'audit-output/02-tools/raw/semgrep.json',
        ])
        budget = json.loads(out.read_text())
        assert budget['decision'] == 'blocked'
        assert any('coordinator packet contains L4 artifact' in issue for issue in budget.get('issues', []))

def test_coordinator_l4_path_blocks_packet_directory():
    print("[context-test] l4-packet-dir", flush=True)
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        profile = td / 'profile'
        profile.mkdir()
        packets = td / 'packets'
        packets.mkdir()
        (profile / 'traversal-manifest.json').write_text(json.dumps({
            'all_files_count': 1,
            'source_files_count': 1,
            'excluded_dirs': [],
            'large_files_skipped': 0,
            'truncated': False,
        }))
        out = td / 'context-budget.json'
        subprocess.check_call([
            sys.executable, str(ROOT / 'tools' / 'context_budget.py'),
            '--profile-dir', str(profile),
            '--packet-dir', str(packets),
            '--out', str(out),
            '--root', str(ROOT),
            '--check-paths', 'audit-output/03-candidates/packets',
        ])
        budget = json.loads(out.read_text())
        assert budget['decision'] == 'blocked'
        assert any('packets' in issue for issue in budget.get('issues', []))

def test_docs_do_not_claim_shared_200k():
    print("[context-test] docs", flush=True)
    forbidden=['workflow shares one 200k','shared 200k context','global 200k context','total context budget: 200k']
    for p in list(ROOT.glob('*.md')) + list((ROOT/'docs').rglob('*.md')) + list((ROOT/'references').glob('*.md')):
        txt=p.read_text(errors='ignore').lower()
        assert not any(x in txt for x in forbidden), f'{p} contains shared-budget wording'

if __name__ == '__main__':
    test_profile_excludes_and_budget()
    test_packet_batching_allows_aggregate_over_200k()
    test_context_efficient_mode_is_reported_without_lowering_coverage()
    test_make_packets_emits_budget_metadata()
    test_strict_packet_budget_blocks_single_oversized_packet()
    test_candidate_review_summary_requires_complete_coverage()
    test_coordinator_l4_path_blocked_when_manifest_present()
    test_coordinator_l4_path_blocks_packet_directory()
    test_docs_do_not_claim_shared_200k()
    print('context budget per-agent tests passed', flush=True)
    os._exit(0)

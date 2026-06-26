#!/usr/bin/env python3
import json, pathlib, subprocess, tempfile, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]

def main():
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td); inp=td/'in.json'; out=td/'out.json'
        data={'candidates':[
            {'id':'T-CAND-low','type':'T-CAND','status':'Raw Tool Hit','title':'test fixture','component':'tests','source_locations':[{'file':'tests/example.c'}],'evidence':{},'confidence':'low','rank_score':0,'missing_evidence':[],'disclosure_level':'D0-internal-candidate'},
            {'id':'T-CAND-high','type':'T-CAND','status':'Raw Tool Hit','title':'elf offset memcpy','component':'bfd parser','source_locations':[{'file':'bfd/elf.c'}],'evidence':{'sink':'memcpy offset size count'},'confidence':'low','rank_score':0,'missing_evidence':[],'disclosure_level':'D0-internal-candidate'}]}
        inp.write_text(json.dumps(data))
        subprocess.check_call([sys.executable, str(ROOT/'tools/rank_candidates.py'), '--input', str(inp), '--out', str(out), '--top','2'])
        ranked=json.loads(out.read_text())['candidates']
        assert ranked[0]['id']=='T-CAND-high', ranked
    print('rank tests passed')
if __name__=='__main__':
    main()

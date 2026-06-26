#!/usr/bin/env python3
import json, pathlib, subprocess, tempfile, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]

def main():
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td); src=td/'src'; src.mkdir(); (src/'parser.c').write_text('\n'.join(f'int line_{i};' for i in range(1,400)))
        cand={'candidates':[{'id':'T-CAND-0001','type':'T-CAND','status':'Likely','title':'example','component':'parser','source_locations':[{'file':'parser.c','start_line':200,'end_line':200}],'evidence':{},'confidence':'medium','missing_evidence':['validation'],'rank_score':1,'disclosure_level':'D1-internal-likely'}]}
        cfile=td/'cand.json'; cfile.write_text(json.dumps(cand)); out=td/'packets'
        subprocess.check_call([sys.executable, str(ROOT/'tools/make_ai_packets.py'), '--candidates', str(cfile), '--source-root', str(src), '--out', str(out), '--context-lines','10','--max-lines','30'])
        packet=(out/'T-CAND-0001.md').read_text()
        assert '## Code Slice' in packet and 'parser.c' in packet
        assert len(packet.splitlines()) < 120
    print('packet tests passed')
if __name__=='__main__':
    main()

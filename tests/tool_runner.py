import runpy, sys, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]

def run_tool(rel, args):
    old=sys.argv[:]
    sys.argv=[str(ROOT/rel)] + list(map(str,args))
    try:
        try:
            runpy.run_path(str(ROOT/rel), run_name='__main__')
        except SystemExit as e:
            code=e.code if isinstance(e.code,int) else 0
            if code not in (0,None):
                raise AssertionError(f'{rel} exited with {code}')
    finally:
        sys.argv=old

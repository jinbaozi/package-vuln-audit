import runpy, sys, pathlib, subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
TOOLS=str((ROOT/'tools').resolve())

def run_tool(rel, args):
    old=sys.argv[:]
    old_path=sys.path[:]
    if TOOLS not in sys.path:
        sys.path.insert(0, TOOLS)
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
        sys.path[:] = old_path

def run_subprocess(rel, args=None, check=True):
    env = None
    import os
    env = os.environ.copy()
    cmd=[sys.executable, str(ROOT/rel)] + list(map(str, args or []))
    return subprocess.run(cmd, check=check, text=True, capture_output=True, cwd=ROOT)

def temp_audit_dir():
    import tempfile
    return tempfile.TemporaryDirectory(prefix='pvas-test-')

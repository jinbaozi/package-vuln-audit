#!/usr/bin/env python3
"""Tests for tools/pvas_netpolicy.py using a mock iptables."""
import contextlib
import os, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import pvas_netpolicy  # noqa: E402


# --- pytest-optional raises helper ---------------------------------------
try:
    import pytest  # noqa: F401

    def _raises(exc):
        return pytest.raises(exc)
except ImportError:  # pragma: no cover
    @contextlib.contextmanager
    def _raises(exc):
        try:
            yield
        except exc:
            return
        raise AssertionError(f'expected {exc.__name__} to be raised')


def _make_mock_iptables(tmpdir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Create a fake 'iptables' script in tmpdir/bin/ that records all invocations
    to a log file. Returns (bin_dir, log_path)."""
    bin_dir = tmpdir / 'bin'
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = tmpdir / 'iptables.log'
    log.write_text('')
    script = bin_dir / 'iptables'
    script.write_text(f"""#!/usr/bin/env bash
echo "$@" >> {log}
exit 0
""")
    script.chmod(0o755)
    return bin_dir, log


def _path_env(bin_dir: pathlib.Path) -> dict:
    return {'PATH': str(bin_dir) + os.pathsep + os.environ['PATH']}


def test_apply_creates_chain_and_returns_netpolicy_id():
    with tempfile.TemporaryDirectory() as td:
        bin_dir, log = _make_mock_iptables(pathlib.Path(td))
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            npid = pvas_netpolicy.apply('cgroup-abc', allowed_cidrs=[])
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        assert npid.startswith('pvas-poc-') or npid.startswith('pvas-tool-'), \
            f"unexpected prefix: {npid}"
        text = log.read_text()
        assert '-N PVAS_OUTPUT_' in text, f"expected chain create, log: {text}"
        assert '-j DROP' in text, f"expected DROP rule, log: {text}"


def test_remove_is_idempotent():
    with tempfile.TemporaryDirectory() as td:
        bin_dir, log = _make_mock_iptables(pathlib.Path(td))
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            npid = pvas_netpolicy.apply('cgroup-x', allowed_cidrs=[])
            pvas_netpolicy.remove(npid)
            pvas_netpolicy.remove(npid)  # idempotent — must not raise
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        # No exception raised = pass


def test_apply_with_cidrs_writes_return_rules():
    with tempfile.TemporaryDirectory() as td:
        bin_dir, log = _make_mock_iptables(pathlib.Path(td))
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            pvas_netpolicy.apply('cgroup-y', allowed_cidrs=['10.0.0.0/8', '192.168.0.0/16'])
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        text = log.read_text()
        assert '10.0.0.0/8' in text, f"expected first CIDR, log: {text}"
        assert '192.168.0.0/16' in text, f"expected second CIDR, log: {text}"


def test_flush_all_calls_iptables():
    with tempfile.TemporaryDirectory() as td:
        bin_dir, log = _make_mock_iptables(pathlib.Path(td))
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            pvas_netpolicy.flush_all()
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        text = log.read_text()
        # flush_all must at minimum invoke iptables to enumerate existing rules
        # (-S is the script-friendly listing flag). Accept any evidence of
        # listing or per-chain cleanup work.
        assert ('-S' in text) or ('PVAS_OUTPUT' in text) or ('-L' in text) \
            or ('-F' in text), \
            f"expected iptables list/flush, log: {text}"


def test_apply_raises_networkpolicyapplyfailed_when_iptables_fails():
    """If the underlying iptables binary exits non-zero, apply() must raise
    NetworkPolicyApplyFailed so the caller (Task 5) can degrade to host network."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir = td / 'bin'
        bin_dir.mkdir(parents=True, exist_ok=True)
        # Mock iptables that always fails (non-zero exit)
        (bin_dir / 'iptables').write_text('#!/usr/bin/env bash\nexit 1\n')
        (bin_dir / 'iptables').chmod(0o755)
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            with _raises(pvas_netpolicy.NetworkPolicyApplyFailed):
                pvas_netpolicy.apply('cgroup-z', allowed_cidrs=[])
        finally:
            os.environ.clear()
            os.environ.update(old_environ)


def test_apply_purpose_tool_uses_tool_prefix():
    """purpose='tool' must produce a netpolicy_id starting with pvas-tool-."""
    with tempfile.TemporaryDirectory() as td:
        bin_dir, log = _make_mock_iptables(pathlib.Path(td))
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            npid = pvas_netpolicy.apply('cgroup-tool', allowed_cidrs=[], purpose='tool')
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        assert npid.startswith('pvas-tool-'), f"expected tool prefix, got: {npid}"


def test_apply_purpose_poc_uses_poc_prefix():
    """purpose='poc' (default) must produce a netpolicy_id starting with pvas-poc-."""
    with tempfile.TemporaryDirectory() as td:
        bin_dir, log = _make_mock_iptables(pathlib.Path(td))
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            npid = pvas_netpolicy.apply('cgroup-poc', allowed_cidrs=[])
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        assert npid.startswith('pvas-poc-'), f"expected poc prefix, got: {npid}"


def test_apply_emits_cgroup_match_in_output_chain():
    """apply() must insert a rule into OUTPUT chain that matches the container's
    cgroup — this is what scopes the policy to PVAS containers only."""
    with tempfile.TemporaryDirectory() as td:
        bin_dir, log = _make_mock_iptables(pathlib.Path(td))
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            pvas_netpolicy.apply('docker-1234567890ab', allowed_cidrs=[])
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        text = log.read_text()
        assert '--cgroup' in text, f"expected --cgroup match, log: {text}"
        assert 'docker-1234567890ab' in text, f"expected container id, log: {text}"


def test_remove_purges_chain_and_jump():
    """remove() must invoke -F (flush) and -X (delete chain) on the PVAS chain."""
    with tempfile.TemporaryDirectory() as td:
        bin_dir, log = _make_mock_iptables(pathlib.Path(td))
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            npid = pvas_netpolicy.apply('cgroup-rm', allowed_cidrs=[])
            log.write_text('')  # reset log to focus on remove()
            pvas_netpolicy.remove(npid)
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        text = log.read_text()
        assert '-F' in text, f"expected -F flush, log: {text}"
        assert '-X' in text, f"expected -X delete chain, log: {text}"


if __name__ == '__main__':
    test_apply_creates_chain_and_returns_netpolicy_id()
    test_remove_is_idempotent()
    test_apply_with_cidrs_writes_return_rules()
    test_flush_all_calls_iptables()
    test_apply_raises_networkpolicyapplyfailed_when_iptables_fails()
    test_apply_purpose_tool_uses_tool_prefix()
    test_apply_purpose_poc_uses_poc_prefix()
    test_apply_emits_cgroup_match_in_output_chain()
    test_remove_purges_chain_and_jump()
    print('pvas_netpolicy tests passed')
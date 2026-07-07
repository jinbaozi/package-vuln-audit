#!/usr/bin/env python3
"""Tests for tools/pvas_container.py using mock docker."""
import json, os, pathlib, subprocess, sys, tempfile
from pathlib import Path

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import pvas_container as pc  # noqa: E402

C = pc.ContainerSpec


def _mock_iptables(tmpdir: pathlib.Path) -> pathlib.Path:
    """Mock iptables that just records calls and succeeds. Returned bin_dir
    must be prepended to PATH before invoking pvas_netpolicy / pvas_container."""
    bin_dir = tmpdir / 'iptbin'
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = tmpdir / 'iptables.log'
    log.write_text('')
    script = bin_dir / 'iptables'
    script.write_text(f"""#!/usr/bin/env bash
echo "$@" >> {log}
exit 0
""")
    script.chmod(0o755)
    return bin_dir


def _mock_docker(tmpdir, *, run_stdout='', run_exit=0, with_iptables=True):
    bin_dir = tmpdir / 'bin'
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = tmpdir / 'docker.log'
    log.write_text('')
    script = bin_dir / 'docker'
    # Use /bin/sh shebang so the mock works under a stripped PATH (the
    # netpolicy-degradation test sets PATH to only the docker bin).
    # Echo the full `docker <args>` invocation so assertions like
    # `'docker run' in text` actually match ($@ only sees args).
    script.write_text(f"""#!/bin/sh
echo "docker $@" >> {log}
cmd="$1"; shift
if [ "$cmd" = "run" ]; then
  cat <<'CID'
f3a8c0d1e2
CID
  echo "{run_stdout}"
  exit {run_exit}
fi
exit 0
""")
    script.chmod(0o755)
    if with_iptables:
        ipt_bin = _mock_iptables(tmpdir)
        return bin_dir, log, ipt_bin
    return bin_dir, log, None


def _path_env(bin_dir: pathlib.Path, ipt_bin: pathlib.Path = None) -> dict:
    """Prepend both docker and (optionally) iptables mock bins to PATH."""
    parts = [str(bin_dir)]
    if ipt_bin is not None:
        parts.append(str(ipt_bin))
    parts.append(os.environ['PATH'])
    return {'PATH': os.pathsep.join(parts)}


def test_max_tool_mem_mb_constant_is_4096():
    assert pc.MAX_TOOL_MEM_MB == 4096


def test_validate_mem_limits_raises_above_4096():
    spec = C(image='img', command=['x'], mounts=[], network_policy='bridge-deny',
             mem_limit_mb=8192)
    try:
        pc._validate_mem_limits(spec)
    except pc.ConfigurationError:
        return
    raise AssertionError('expected ConfigurationError for mem_limit_mb=8192')


def test_validate_mem_limits_passes_below_4096():
    spec = C(image='img', command=['x'], mounts=[], network_policy='bridge-deny',
             mem_limit_mb=2048)
    pc._validate_mem_limits(spec)  # must not raise


def test_compute_max_workers_caps_at_min_of_factors():
    specs = [
        C(image='i', command=['x'], mounts=[], network_policy='bridge-deny', mem_limit_mb=2048),
        C(image='i', command=['x'], mounts=[], network_policy='bridge-deny', mem_limit_mb=2048),
        C(image='i', command=['x'], mounts=[], network_policy='bridge-deny', mem_limit_mb=2048),
    ]
    # 4 CPUs, 8192 MB available, 3 specs, max=4 → min(3, 4, 4, 8192//2048=4) = 3
    assert pc.compute_max_workers(specs, available_mem_mb=8192, cpu_count=4) == 3


def test_compute_max_workers_floor_is_1_even_if_no_memory():
    specs = [C(image='i', command=['x'], mounts=[], network_policy='bridge-deny',
               mem_limit_mb=4096)]
    # 16 MB available → 16//4096=0, but must floor to 1
    result = pc.compute_max_workers(specs, available_mem_mb=16, cpu_count=1)
    assert result == 1


def test_compute_max_workers_respects_max_workers_cap():
    specs = [C(image='i', command=['x'], mounts=[], network_policy='bridge-deny',
               mem_limit_mb=256)] * 10
    result = pc.compute_max_workers(specs, available_mem_mb=8192, cpu_count=8,
                                     max_workers=2)
    assert result == 2


def test_run_invokes_docker_with_expected_args():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log, ipt_bin = _mock_docker(td, run_stdout='hello', run_exit=0)
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir, ipt_bin))
        try:
            spec = C(image='pvas-sandbox:v11-2503-runtime',
                     command=['echo', 'hello'],
                     mounts=[(td, '/workspace', 'ro')],
                     network_policy='bridge-deny',
                     timeout_seconds=30)
            result = pc.run(spec, backend='docker')
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        text = log.read_text()
        assert 'docker run' in text
        assert 'pvas-sandbox:v11-2503-runtime' in text
        assert '--read-only' in text
        # docker CLI uses space-separated --cap-drop ALL, not --cap-drop=ALL
        assert '--cap-drop' in text and 'ALL' in text, \
            f"expected --cap-drop ALL in docker args, got: {text!r}"
        assert '-u 65534:65534' in text or '--user 65534:65534' in text, \
            f"expected user 65534:65534, got: {text!r}"
        assert result.exit_code == 0
        assert 'hello' in result.stdout


def test_wrap_command_exists_and_returns_subprocess_argv():
    argv = pc.wrap_command(
        ['echo', 'hello'],
        mounts=[('/tmp/src', '/workspace', 'ro')],
        network_policy='host',
        backend='docker',
    )
    assert isinstance(argv, list)
    assert argv[0] == sys.executable
    assert pathlib.Path(argv[1]).name == 'pvas_container_exec.py'
    assert argv[2] == '--spec-json-b64'
    payload = pc._decode_payload(argv[3])
    assert payload['backend'] == 'docker'
    assert payload['spec']['command'] == ['echo', 'hello']
    assert payload['spec']['mounts'] == [['/tmp/src', '/workspace', 'ro']]
    assert payload['spec']['network_policy'] == 'host'


def test_wrap_command_runner_executes_with_mock_docker():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log, ipt_bin = _mock_docker(td, run_stdout='wrapped-ok', run_exit=0)
        result_json = td / 'result.json'
        env = os.environ.copy()
        env.update(_path_env(bin_dir, ipt_bin))
        env['PVAS_CONTAINER_RESULT_JSON'] = str(result_json)
        argv = pc.wrap_command(
            ['echo', 'wrapped-ok'],
            mounts=[(str(td), '/workspace', 'ro')],
            network_policy='host',
            backend='docker',
        )
        proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30)
        assert proc.returncode == 0, proc.stderr
        assert 'wrapped-ok' in proc.stdout
        assert 'docker run' in log.read_text()
        payload = json.loads(result_json.read_text())
        assert payload['exit_code'] == 0
        assert payload['executed_via'] == 'container'


def test_wrap_command_preserves_bridge_deny_default_in_encoded_spec():
    argv = pc.wrap_command(['true'])
    payload = pc._decode_payload(argv[3])
    assert payload['spec']['network_policy'] == 'bridge-deny'
    assert payload['spec']['image'] == os.environ.get(
        'PVAS_RUNTIME_IMAGE', 'pvas-sandbox:v11-2503-runtime'
    )
    assert payload['spec']['cap_drop'] == ['ALL']

def test_run_timeout_sets_timed_out_flag():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        # Mock docker that hangs (sleep 60)
        bin_dir = td / 'bin'
        bin_dir.mkdir()
        log = td / 'docker.log'
        log.write_text('')
        script = bin_dir / 'docker'
        script.write_text(f"""#!/usr/bin/env bash
echo "$@" >> {log}
cmd="$1"; shift
if [[ "$cmd" == "run" ]]; then
  sleep 60
fi
exit 0
""")
        script.chmod(0o755)
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            spec = C(image='img', command=['sleep', '60'], mounts=[],
                     network_policy='host', timeout_seconds=1)
            result = pc.run(spec, backend='docker')
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        assert result.timed_out is True


def test_run_netpolicy_failure_degrades_to_host():
    """When iptables is unavailable (no iptables on PATH), NetworkPolicyApplyFailed
    is raised by pvas_netpolicy.apply(); pvas_container.run() must catch this
    and degrade to network_policy='host' with netpolicy_id='degraded-no-netpolicy'
    and executed_via='host-degraded-sandbox-disabled' (must NOT raise)."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        # Only mock docker — no iptables in PATH at all so apply() raises
        bin_dir, log, _ = _mock_docker(td, run_stdout='hi', run_exit=0,
                                       with_iptables=False)
        old_path = os.environ['PATH']
        # Isolate PATH to ONLY the mocked docker bin — no iptables anywhere
        os.environ['PATH'] = str(bin_dir)
        try:
            spec = C(image='img', command=['echo', 'hi'], mounts=[],
                     network_policy='bridge-deny', timeout_seconds=30)
            result = pc.run(spec, backend='docker')
        finally:
            os.environ['PATH'] = old_path
        assert result.exit_code == 0
        assert result.netpolicy_id == 'degraded-no-netpolicy', result.netpolicy_id
        assert result.executed_via == 'host-degraded-sandbox-disabled', \
            result.executed_via
        # The actual docker invocation must use --network=host
        text = log.read_text()
        assert '--network host' in text, f"expected host network fallback, log: {text!r}"


def test_strict_mode_netpolicy_failure_blocks_instead_of_degrading():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log, _ = _mock_docker(td, run_stdout='hi', run_exit=0,
                                       with_iptables=False)
        old_environ = os.environ.copy()
        os.environ['PATH'] = str(bin_dir)
        os.environ['PVAS_STRICT_MODE'] = 'strict'
        os.environ['PVAS_ALLOW_DEGRADED'] = 'false'
        try:
            spec = C(image='img', command=['echo', 'hi'], mounts=[],
                     network_policy='bridge-deny', timeout_seconds=30)
            try:
                pc.run(spec, backend='docker')
            except pc.NetworkPolicyApplyFailed:
                pass
            else:
                raise AssertionError('strict mode must block netpolicy degradation')
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        assert 'docker run' not in log.read_text()


def test_run_parallel_returns_results_for_all_specs():
    """run_parallel must return one ContainerResult per spec, never raise."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log, ipt_bin = _mock_docker(td, run_stdout='hi', run_exit=0)
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir, ipt_bin))
        try:
            specs = [
                C(image='i', command=['x'], mounts=[], network_policy='host',
                  mem_limit_mb=128, timeout_seconds=10),
                C(image='i', command=['y'], mounts=[], network_policy='host',
                  mem_limit_mb=128, timeout_seconds=10),
                C(image='i', command=['z'], mounts=[], network_policy='host',
                  mem_limit_mb=128, timeout_seconds=10),
            ]
            results = pc.run_parallel(specs, max_workers=2, backend='docker')
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        assert len(results) == 3, results
        for r in results:
            assert isinstance(r, pc.ContainerResult)
            assert r.exit_code == 0


def test_run_parallel_oom_retries_with_doubled_mem():
    """If the first run returns oom_killed=True with mem_limit_mb=X and
    min(2*X, MAX_TOOL_MEM_MB) > X, run_parallel must retry exactly once with
    the doubled mem cap. We verify by counting docker invocations and
    inspecting the final mem_limit_mb used."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir = td / 'bin'
        bin_dir.mkdir()
        log = td / 'docker.log'
        log.write_text('')
        # Mock docker whose stdout/stderr signals OOM the first time, success
        # the second time. We use a state file in the temp dir.
        state = td / 'invocation'
        state.write_text('0')
        script = bin_dir / 'docker'
        script.write_text(f"""#!/usr/bin/env bash
echo "docker $@" >> {log}
n=$(cat {state})
echo $((n+1)) > {state}
if [[ "$1" == "run" ]]; then
  cat <<'CID'
aabbccddeeff
CID
  if [[ "$n" == "0" ]]; then
    echo "Out of memory: Killed process 1" >&2
    exit 137
  fi
  echo "ok"
  exit 0
fi
exit 0
""")
        script.chmod(0o755)
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir))
        try:
            specs = [C(image='i', command=['x'], mounts=[],
                       network_policy='host', mem_limit_mb=512,
                       timeout_seconds=10)]
            results = pc.run_parallel(specs, max_workers=1, backend='docker')
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        assert len(results) == 1
        r = results[0]
        assert r.exit_code == 0, f"retry should succeed: exit={r.exit_code}, stderr={r.stderr!r}"
        # Confirm the second invocation used 1024m (2*512)
        text = log.read_text()
        assert text.count('docker run') == 2, \
            f"expected exactly 2 invocations, log: {text!r}"
        assert '-m 1024m' in text, f"expected doubled mem on retry, log: {text!r}"


def test_run_parallel_worker_exception_does_not_propagate():
    """If a worker raises, run_parallel must still return one result per spec
    with the error captured as a -1 exit_code ContainerResult (must not raise)."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log, ipt_bin = _mock_docker(td, run_stdout='ok', run_exit=0)
        old_environ = os.environ.copy()
        os.environ.update(_path_env(bin_dir, ipt_bin))
        try:
            # mem_limit_mb above MAX_TOOL_MEM_MB → _validate_mem_limits raises
            bad = C(image='i', command=['x'], mounts=[], network_policy='host',
                    mem_limit_mb=99999, timeout_seconds=10)
            good = C(image='i', command=['x'], mounts=[], network_policy='host',
                     mem_limit_mb=128, timeout_seconds=10)
            results = pc.run_parallel([bad, good], max_workers=2, backend='docker')
        finally:
            os.environ.clear()
            os.environ.update(old_environ)
        assert len(results) == 2
        # bad → exit_code=-1 (worker caught the ConfigurationError)
        bad_result = next(r for r in results if r.exit_code == -1)
        assert 'ConfigurationError' in bad_result.stderr or 'mem_limit_mb' in bad_result.stderr, \
            bad_result.stderr
        # good → exit_code=0
        good_result = next(r for r in results if r.exit_code == 0)
        assert good_result.exit_code == 0

if __name__ == '__main__':
    test_max_tool_mem_mb_constant_is_4096()
    test_validate_mem_limits_raises_above_4096()
    test_validate_mem_limits_passes_below_4096()
    test_compute_max_workers_caps_at_min_of_factors()
    test_compute_max_workers_floor_is_1_even_if_no_memory()
    test_compute_max_workers_respects_max_workers_cap()
    test_run_invokes_docker_with_expected_args()
    test_wrap_command_exists_and_returns_subprocess_argv()
    test_wrap_command_runner_executes_with_mock_docker()
    test_wrap_command_preserves_bridge_deny_default_in_encoded_spec()
    test_run_timeout_sets_timed_out_flag()
    test_run_netpolicy_failure_degrades_to_host()
    test_run_parallel_returns_results_for_all_specs()
    test_run_parallel_oom_retries_with_doubled_mem()
    test_run_parallel_worker_exception_does_not_propagate()
    print('pvas_container tests passed')

#!/usr/bin/env python3
"""Tests for tools/pvas_image.py using a mock docker CLI."""
import contextlib
import hashlib
import io
import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import pvas_image  # noqa: E402


# --- pytest-optional raises helper ---------------------------------------
# The suite is stdlib-only and must run via `python3 tests/test_pvas_image.py`
# even when pytest is absent, so fall back to a local contextmanager.
try:
    import pytest  # noqa: F401

    def _raises(exc):
        return pytest.raises(exc)
except ImportError:  # pragma: no cover - exercised only without pytest
    @contextlib.contextmanager
    def _raises(exc):
        try:
            yield
        except exc:
            return
        raise AssertionError(f'expected {exc.__name__} to be raised')


# --- helpers --------------------------------------------------------------

def _make_mock_docker(tmpdir: pathlib.Path, behaviors: dict):
    """Create a fake 'docker' script in tmpdir/bin/ that records calls
    and returns canned outputs per behaviors dict."""
    bin_dir = tmpdir / 'bin'
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = tmpdir / 'docker.log'
    log.write_text('')
    script = bin_dir / 'docker'
    lines = ['#!/usr/bin/env bash',
             f'echo "$@" >> {log}',
             'cmd="$1"',
             'shift']
    for k, v in behaviors.items():
        if k == 'images_list':
            lines.append(f'if [[ "$cmd" == "images" ]]; then printf "%b\\n" "{v}"; exit 0; fi')
        elif k == 'images_empty':
            lines.append('if [[ "$cmd" == "images" ]]; then exit 0; fi')
        elif k == 'import_ok':
            lines.append('if [[ "$cmd" == "import" ]]; then echo "sha256:abc"; exit 0; fi')
        elif k == 'import_fail':
            lines.append('if [[ "$cmd" == "import" ]]; then echo "err" >&2; exit 1; fi')
        elif k == 'ps_list':
            lines.append(f'if [[ "$cmd" == "ps" ]]; then printf "%b\\n" "{v}"; exit 0; fi')
    lines.append('exit 0')
    script.write_text('\n'.join(lines))
    script.chmod(0o755)
    return bin_dir, log


def _path_env(bin_dir: pathlib.Path) -> dict:
    return {'PATH': str(bin_dir) + os.pathsep + os.environ['PATH']}


# --- tests ----------------------------------------------------------------

def test_verify_tar_matches():
    with tempfile.TemporaryDirectory() as td:
        tar = pathlib.Path(td) / 'rootfs.tar'
        tar.write_bytes(b'PVAS_ROOTFS_V11_2503')
        sha = hashlib.sha256(tar.read_bytes()).hexdigest()
        pvas_image.verify_tar(tar, sha)  # must not raise


def test_verify_tar_mismatch_raises():
    with tempfile.TemporaryDirectory() as td:
        tar = pathlib.Path(td) / 'rootfs.tar'
        tar.write_bytes(b'PVAS_ROOTFS_V11_2503')
        with _raises(pvas_image.ImageImportFailed):
            pvas_image.verify_tar(tar, '0' * 64)


def test_verify_tar_missing_raises():
    with tempfile.TemporaryDirectory() as td:
        tar = pathlib.Path(td) / 'does-not-exist.tar'
        with _raises(pvas_image.ImageImportFailed):
            pvas_image.verify_tar(tar, '0' * 64)


def test_is_imported_true_when_listed():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, _ = _make_mock_docker(td, {'images_list': 'pvas-sandbox:v11-2503-imported'})
        assert pvas_image.is_imported('pvas-sandbox:v11-2503-imported', 'docker',
                                      env_overrides=_path_env(bin_dir))


def test_is_imported_false_when_absent():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, _ = _make_mock_docker(td, {'images_empty': True})
        assert not pvas_image.is_imported('pvas-sandbox:missing', 'docker',
                                          env_overrides=_path_env(bin_dir))


def test_ensure_imported_skips_when_present():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'data')
        sha = hashlib.sha256(tar.read_bytes()).hexdigest()
        bin_dir, log = _make_mock_docker(td, {'images_list': 'pvas-sandbox:v11-2503-imported'})
        result = pvas_image.ensure_imported(
            tar, sha, 'pvas-sandbox:v11-2503-imported', 'docker',
            env_overrides=_path_env(bin_dir),
        )
        assert result == 'pvas-sandbox:v11-2503-imported'
        log_text = log.read_text()
        assert 'import' not in log_text, f'should not call docker import, log: {log_text}'


def test_ensure_imported_calls_import_when_absent():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'data')
        sha = hashlib.sha256(tar.read_bytes()).hexdigest()
        bin_dir, log = _make_mock_docker(td, {'images_empty': True, 'import_ok': True})
        result = pvas_image.ensure_imported(
            tar, sha, 'pvas-sandbox:v11-2503-imported', 'docker',
            env_overrides=_path_env(bin_dir),
        )
        assert result == 'pvas-sandbox:v11-2503-imported'
        log_text = log.read_text()
        assert 'import' in log_text, f'expected import call, log: {log_text}'


def test_ensure_imported_mismatch_raises():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'data')
        bin_dir, log = _make_mock_docker(td, {'images_empty': True, 'import_ok': True})
        with _raises(pvas_image.ImageImportFailed):
            pvas_image.ensure_imported(
                tar, 'a' * 64, 'pvas-sandbox:v11-2503-imported', 'docker',
                env_overrides=_path_env(bin_dir),
            )
        assert 'import' not in log.read_text()


def test_ensure_imported_placeholder_rejected_by_default():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'PVAS_ROOTFS_V11_2503')
        bin_dir, log = _make_mock_docker(td, {'images_empty': True, 'import_ok': True})
        with _raises(pvas_image.ImageImportFailed):
            pvas_image.ensure_imported(
                tar, '0' * 64, 'pvas-sandbox:v11-2503-imported', 'docker',
                env_overrides=_path_env(bin_dir),
            )
        assert 'import' not in log.read_text()


def test_ensure_imported_placeholder_compat_warns_but_proceeds():
    """Explicit compatibility mode can still test legacy placeholder behavior."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'PVAS_ROOTFS_V11_2503')  # actual sha != all-zeros
        bin_dir, log = _make_mock_docker(td, {'images_empty': True, 'import_ok': True})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            result = pvas_image.ensure_imported(
                tar, '0' * 64, 'pvas-sandbox:v11-2503-imported', 'docker',
                env_overrides=_path_env(bin_dir), allow_placeholder=True,
            )
        assert result == 'pvas-sandbox:v11-2503-imported'
        assert 'placeholder' in err.getvalue().lower(), err.getvalue()
        assert 'import' in log.read_text(), 'placeholder must not block import'


def test_list_containers_by_audit():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, _ = _make_mock_docker(td, {'ps_list': 'cid1\\ncid2'})
        ids = pvas_image.list_containers_by_audit('audit-xyz', 'docker',
                                                  env_overrides=_path_env(bin_dir))
        assert ids == ['cid1', 'cid2'], ids


def test_list_images_by_audit():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, _ = _make_mock_docker(td, {'images_list': 'pvas-sandbox:v11-2503-runtime'})
        imgs = pvas_image.list_images_by_audit('audit-xyz', 'docker',
                                               env_overrides=_path_env(bin_dir))
        assert imgs == ['pvas-sandbox:v11-2503-runtime'], imgs


def test_prompt_cleanup_never_policy_logs_and_leaves():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log = _make_mock_docker(td, {'ps_list': 'cid1', 'images_list': 'pvas-sandbox:v11-2503-runtime'})
        cleanup_log = td / 'cleanup.jsonl'
        old = os.environ.get('PVAS_CLEANUP_IMAGES')
        os.environ['PVAS_CLEANUP_IMAGES'] = 'never'
        try:
            pvas_image.prompt_cleanup('audit-xyz', 'docker',
                                      env_overrides=_path_env(bin_dir),
                                      log_path=cleanup_log)
        finally:
            if old is None:
                os.environ.pop('PVAS_CLEANUP_IMAGES', None)
            else:
                os.environ['PVAS_CLEANUP_IMAGES'] = old
        assert 'rm ' not in log.read_text(), 'never policy must not remove anything'
        assert cleanup_log.is_file()
        assert 'skipped-never' in cleanup_log.read_text()


def test_prompt_cleanup_always_policy_removes_containers_and_images():
    """PVAS_CLEANUP_IMAGES=always-prune-image must actually invoke `docker rm -f`
    for every discovered container and `docker rmi` for every discovered image,
    and the env_overrides PATH must reach those subprocess calls (mock log
    proves it). The `always` policy keeps the image; `always-prune-image`
    also removes it."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log = _make_mock_docker(
            td,
            {'ps_list': 'cid1\\ncid2', 'images_list': 'pvas-sandbox:v11-2503-runtime'},
        )
        cleanup_log = td / 'cleanup.jsonl'
        old = os.environ.get('PVAS_CLEANUP_IMAGES')
        os.environ['PVAS_CLEANUP_IMAGES'] = 'always-prune-image'
        try:
            pvas_image.prompt_cleanup('audit-xyz', 'docker',
                                      env_overrides=_path_env(bin_dir),
                                      log_path=cleanup_log)
        finally:
            if old is None:
                os.environ.pop('PVAS_CLEANUP_IMAGES', None)
            else:
                os.environ['PVAS_CLEANUP_IMAGES'] = old
        log_text = log.read_text()
        # Real CLI invocations for the discovered containers
        assert 'rm -f cid1' in log_text, f'must rm -f cid1, log: {log_text}'
        assert 'rm -f cid2' in log_text, f'must rm -f cid2, log: {log_text}'
        # Real CLI invocation for the discovered image
        assert 'rmi pvas-sandbox:v11-2503-runtime' in log_text, \
            f'must rmi image, log: {log_text}'
        # Cleanup log records the auto mode + the actions performed
        assert cleanup_log.is_file()
        cleanup_text = cleanup_log.read_text()
        assert '"mode": "auto"' in cleanup_text, cleanup_text
        assert 'rm-containers' in cleanup_text, cleanup_text
        assert 'rmi-images' in cleanup_text, cleanup_text


def test_prompt_cleanup_always_keeps_image():
    """PVAS_CLEANUP_IMAGES=always must rm containers but KEEP images."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log = _make_mock_docker(
            td,
            {'ps_list': 'cid1', 'images_list': 'pvas-sandbox:v11-2503-runtime'},
        )
        cleanup_log = td / 'cleanup.jsonl'
        old = os.environ.get('PVAS_CLEANUP_IMAGES')
        os.environ['PVAS_CLEANUP_IMAGES'] = 'always'
        try:
            pvas_image.prompt_cleanup('audit-xyz', 'docker',
                                      env_overrides=_path_env(bin_dir),
                                      log_path=cleanup_log)
        finally:
            if old is None:
                os.environ.pop('PVAS_CLEANUP_IMAGES', None)
            else:
                os.environ['PVAS_CLEANUP_IMAGES'] = old
        log_text = log.read_text()
        assert 'rm -f cid1' in log_text, f'must rm -f cid1, log: {log_text}'
        assert 'rmi' not in log_text, f'always policy must skip rmi, log: {log_text}'
        # Cleanup log only records the container removal, not image removal
        cleanup_text = cleanup_log.read_text()
        assert 'rm-containers' in cleanup_text, cleanup_text
        assert 'rmi-images' not in cleanup_text, cleanup_text


def test_default_image_constant():
    assert pvas_image.DEFAULT_IMAGE_IMPORTED == 'pvas-sandbox:v11-2503-imported'


# --- tests for build_runtime + ensure_runtime_image (Task 6) ----------
# These tests need a mock docker that *also* understands `docker build`,
# so we always extend the default mock by overwriting bin/docker with a
# build-aware variant. The default mock's unknown-command path falls
# through to `exit 0`, which is fine for the "skip" case where we assert
# that `build` was NOT invoked.


def test_build_runtime_invokes_docker_build():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log = _make_mock_docker(td, {'images_empty': True})
        # extend mock to handle 'build' command
        (bin_dir / 'docker').write_text(
            f"""#!/usr/bin/env bash
echo "$@" >> {log}
cmd="$1"; shift
if [[ "$cmd" == "images" ]]; then exit 0; fi
if [[ "$cmd" == "build" ]]; then echo "build ok"; exit 0; fi
exit 0
"""
        )
        (bin_dir / 'docker').chmod(0o755)
        # We need a Dockerfile
        df_dir = td / 'df'
        df_dir.mkdir()
        (df_dir / 'Dockerfile.runtime').write_text('FROM scratch\n')
        pvas_image.build_runtime(
            base_image='pvas-sandbox:v11-2503-imported',
            target_image='pvas-sandbox:v11-2503-runtime',
            dockerfile=df_dir / 'Dockerfile.runtime',
            backend='docker',
            env_overrides={'PATH': str(bin_dir) + os.pathsep + os.environ['PATH']},
        )
        text = log.read_text()
        assert 'build' in text
        assert 'pvas-sandbox:v11-2503-runtime' in text


def test_ensure_runtime_image_skips_when_present():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log = _make_mock_docker(td, {
            'images_list': 'pvas-sandbox:v11-2503-runtime\n'
        })
        df_dir = td / 'df'
        df_dir.mkdir()
        (df_dir / 'Dockerfile.runtime').write_text('FROM scratch\n')
        result = pvas_image.ensure_runtime_image(
            base_image='pvas-sandbox:v11-2503-imported',
            target_image='pvas-sandbox:v11-2503-runtime',
            dockerfile=df_dir / 'Dockerfile.runtime',
            backend='docker',
            env_overrides={'PATH': str(bin_dir) + os.pathsep + os.environ['PATH']},
        )
        assert result == 'pvas-sandbox:v11-2503-runtime'
        text = log.read_text()
        assert 'build' not in text, f'should not call build when present, log: {text}'


def test_ensure_runtime_image_calls_build_when_absent():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        bin_dir, log = _make_mock_docker(td, {'images_empty': True})
        (bin_dir / 'docker').write_text(
            f"""#!/usr/bin/env bash
echo "$@" >> {log}
cmd="$1"; shift
if [[ "$cmd" == "images" ]]; then exit 0; fi
if [[ "$cmd" == "build" ]]; then echo "build ok"; exit 0; fi
exit 0
"""
        )
        (bin_dir / 'docker').chmod(0o755)
        df_dir = td / 'df'
        df_dir.mkdir()
        (df_dir / 'Dockerfile.runtime').write_text('FROM scratch\n')
        result = pvas_image.ensure_runtime_image(
            base_image='pvas-sandbox:v11-2503-imported',
            target_image='pvas-sandbox:v11-2503-runtime',
            dockerfile=df_dir / 'Dockerfile.runtime',
            backend='docker',
            env_overrides={'PATH': str(bin_dir) + os.pathsep + os.environ['PATH']},
        )
        assert result == 'pvas-sandbox:v11-2503-runtime'
        text = log.read_text()
        assert 'build' in text, f'expected build call, log: {text}'


def test_cli_status_missing_tar_returns_not_ready_json():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        sums = td / 'SHA256SUMS'
        sums.write_text(f"{'a' * 64}  missing.tar\n")
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = pvas_image.main([
                'status',
                '--tar', str(td / 'missing.tar'),
                '--sha256sums', str(sums),
            ], env_overrides={'PATH': str(td)})
        payload = json.loads(out.getvalue())
        assert rc == 1
        assert payload['tar_exists'] is False
        assert payload['status'] == 'not-ready'


def test_cli_import_sha_mismatch_blocks_backend_import():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'data')
        sums = td / 'SHA256SUMS'
        sums.write_text(f"{'a' * 64}  rootfs.tar\n")
        bin_dir, log = _make_mock_docker(td, {'images_empty': True, 'import_ok': True})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = pvas_image.main([
                'import',
                '--tar', str(tar),
                '--sha256sums', str(sums),
                '--dockerfile', str(td / 'Dockerfile.runtime'),
            ], env_overrides=_path_env(bin_dir))
        assert rc == 2
        assert 'SHA256 mismatch' in err.getvalue()
        assert 'import' not in log.read_text()


def test_cli_import_skips_when_images_present():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'data')
        sha = hashlib.sha256(tar.read_bytes()).hexdigest()
        sums = td / 'SHA256SUMS'
        sums.write_text(f"{sha}  rootfs.tar\n")
        images = 'pvas-sandbox:v11-2503-imported\\npvas-sandbox:v11-2503-runtime'
        bin_dir, log = _make_mock_docker(td, {'images_list': images, 'import_ok': True})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = pvas_image.main([
                'import',
                '--tar', str(tar),
                '--sha256sums', str(sums),
                '--dockerfile', str(td / 'Dockerfile.runtime'),
            ], env_overrides=_path_env(bin_dir))
        payload = json.loads(out.getvalue())
        log_text = log.read_text()
        assert rc == 0
        assert payload['status'] == 'ready'
        assert 'import' not in log_text
        assert 'build' not in log_text


def test_cli_import_calls_backend_import_and_build_when_missing():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'data')
        sha = hashlib.sha256(tar.read_bytes()).hexdigest()
        sums = td / 'SHA256SUMS'
        sums.write_text(f"{sha}  rootfs.tar\n")
        dockerfile = td / 'Dockerfile.runtime'
        dockerfile.write_text('FROM scratch\n')
        bin_dir, log = _make_mock_docker(td, {'images_empty': True, 'import_ok': True})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = pvas_image.main([
                'import',
                '--tar', str(tar),
                '--sha256sums', str(sums),
                '--dockerfile', str(dockerfile),
            ], env_overrides=_path_env(bin_dir))
        log_text = log.read_text()
        assert rc == 0
        assert 'import' in log_text
        assert 'build' in log_text


def test_cli_import_rejects_placeholder_sha256():
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'data')
        sums = td / 'SHA256SUMS'
        sums.write_text(f"{'0' * 64}  rootfs.tar\n")
        bin_dir, log = _make_mock_docker(td, {'images_empty': True, 'import_ok': True})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = pvas_image.main([
                'import',
                '--tar', str(tar),
                '--sha256sums', str(sums),
            ], env_overrides=_path_env(bin_dir))
        assert rc == 2
        assert 'placeholder' in err.getvalue().lower()
        assert 'import' not in log.read_text()


if __name__ == '__main__':
    test_verify_tar_matches()
    test_verify_tar_mismatch_raises()
    test_verify_tar_missing_raises()
    test_is_imported_true_when_listed()
    test_is_imported_false_when_absent()
    test_ensure_imported_skips_when_present()
    test_ensure_imported_calls_import_when_absent()
    test_ensure_imported_mismatch_raises()
    test_ensure_imported_placeholder_rejected_by_default()
    test_ensure_imported_placeholder_compat_warns_but_proceeds()
    test_list_containers_by_audit()
    test_list_images_by_audit()
    test_prompt_cleanup_never_policy_logs_and_leaves()
    test_prompt_cleanup_always_policy_removes_containers_and_images()
    test_prompt_cleanup_always_keeps_image()
    test_default_image_constant()
    test_build_runtime_invokes_docker_build()
    test_ensure_runtime_image_skips_when_present()
    test_ensure_runtime_image_calls_build_when_absent()
    test_cli_status_missing_tar_returns_not_ready_json()
    test_cli_import_sha_mismatch_blocks_backend_import()
    test_cli_import_skips_when_images_present()
    test_cli_import_calls_backend_import_and_build_when_missing()
    test_cli_import_rejects_placeholder_sha256()
    print('pvas_image tests passed')

#!/usr/bin/env python3
"""Tests for tools/pvas_image.py using a mock docker CLI."""
import contextlib
import hashlib
import io
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


def test_ensure_imported_placeholder_warns_but_proceeds():
    """The shipped SHA256SUMS is an all-zeros placeholder (real rootfs tar is
    git-lfs deferred). ensure_imported must warn on the placeholder but still
    proceed to import rather than blocking the audit."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        tar = td / 'rootfs.tar'
        tar.write_bytes(b'PVAS_ROOTFS_V11_2503')  # actual sha != all-zeros
        bin_dir, log = _make_mock_docker(td, {'images_empty': True, 'import_ok': True})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            result = pvas_image.ensure_imported(
                tar, '0' * 64, 'pvas-sandbox:v11-2503-imported', 'docker',
                env_overrides=_path_env(bin_dir),
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


def test_default_image_constant():
    assert pvas_image.DEFAULT_IMAGE_IMPORTED == 'pvas-sandbox:v11-2503-imported'


if __name__ == '__main__':
    test_verify_tar_matches()
    test_verify_tar_mismatch_raises()
    test_verify_tar_missing_raises()
    test_is_imported_true_when_listed()
    test_is_imported_false_when_absent()
    test_ensure_imported_skips_when_present()
    test_ensure_imported_calls_import_when_absent()
    test_ensure_imported_mismatch_raises()
    test_ensure_imported_placeholder_warns_but_proceeds()
    test_list_containers_by_audit()
    test_list_images_by_audit()
    test_prompt_cleanup_never_policy_logs_and_leaves()
    test_default_image_constant()
    print('pvas_image tests passed')

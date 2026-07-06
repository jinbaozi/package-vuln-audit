#!/usr/bin/env python3
"""PVAS 镜像管理：import、缓存、清理。

Thin stdlib-only wrapper around the docker/podman CLI. No third-party SDK.
Image tags follow `pvas-sandbox:v11-2503-{imported,runtime}`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

DEFAULT_IMAGE_IMPORTED = "pvas-sandbox:v11-2503-imported"
DEFAULT_IMAGE_RUNTIME = "pvas-sandbox:v11-2503-runtime"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TAR_PATH = ROOT / "sandbox" / "rootfs" / "v11-2503-rootfs.tar"
DEFAULT_SHA256SUMS = ROOT / "sandbox" / "rootfs" / "SHA256SUMS"
DEFAULT_DOCKERFILE = ROOT / "sandbox" / "images" / "Dockerfile.runtime"

# The all-zeros value is recognized only as a legacy/test placeholder. Normal
# CLI and driver paths reject it because the rootfs tar is now expected to be
# pinned by a real checksum.
_PLACEHOLDER_SHA256 = "0" * 64


class ImageImportFailed(RuntimeError):
    """Image import / verification failed."""


def _run(cmd: list[str], env: Optional[dict] = None, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)


def _merged_env(env_overrides: Optional[dict]) -> dict:
    env = dict(os.environ)
    if env_overrides:
        env.update(env_overrides)
    return env


def _is_placeholder_sha256(expected_sha256: str) -> bool:
    """True only for the canonical all-zeros placeholder, never for a real hash."""
    return expected_sha256.strip().lower() == _PLACEHOLDER_SHA256


def _placeholder_allowed(allow_placeholder: bool = False) -> bool:
    return allow_placeholder or os.environ.get("PVAS_ALLOW_PLACEHOLDER_SHA256", "").lower() in {
        "1",
        "true",
        "yes",
        "compat",
    }


def read_expected_sha256(sums_path: Path, filename: str) -> str:
    """Read the expected SHA256 for filename from a SHA256SUMS file."""
    if not sums_path.is_file():
        raise ImageImportFailed(f"missing checksum file: {sums_path}")
    for line in sums_path.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == filename:
            return parts[0].strip().lower()
    raise ImageImportFailed(f"{filename} not found in {sums_path}")


def sha256_file(path: Path) -> str:
    """Hash a file without loading large rootfs tarballs into memory."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_tar(tar_path: Path, expected_sha256: str) -> None:
    """校验 tar 的 SHA256。失败抛 ImageImportFailed。"""
    if not tar_path.is_file():
        raise ImageImportFailed(f"missing tar: {tar_path}")
    actual = sha256_file(tar_path)
    if actual != expected_sha256:
        raise ImageImportFailed(
            f"SHA256 mismatch for {tar_path}: expected={expected_sha256} actual={actual}"
        )


def is_imported(image: str, backend: str, env_overrides: Optional[dict] = None) -> bool:
    """检查 image:tag 是否已在本地 image store。"""
    env = _merged_env(env_overrides)
    p = _run([backend, "images", "--format", "{{.Repository}}:{{.Tag}}"], env=env)
    if p.returncode != 0:
        return False
    for line in p.stdout.splitlines():
        if line.strip() == image:
            return True
    return False


def import_image(tar_path: Path, image: str, backend: str, env_overrides: Optional[dict] = None) -> None:
    """执行 docker/podman import。失败抛 ImageImportFailed。"""
    env = _merged_env(env_overrides)
    p = _run([backend, "import", str(tar_path), image], env=env)
    if p.returncode != 0:
        raise ImageImportFailed(f"{backend} import failed: {p.stderr.strip()}")


def ensure_imported(
    tar_path: Path,
    expected_sha256: str,
    image: str,
    backend: str,
    env_overrides: Optional[dict] = None,
    allow_placeholder: bool = False,
) -> str:
    """verify → is_imported? skip : import。返回 image tag。

    Production paths reject the all-zero checksum placeholder. Set
    allow_placeholder=True or PVAS_ALLOW_PLACEHOLDER_SHA256=1 only for explicit
    compatibility/testing scenarios.
    """
    if _is_placeholder_sha256(expected_sha256):
        if not _placeholder_allowed(allow_placeholder):
            raise ImageImportFailed(
                f"SHA256SUMS placeholder detected for {tar_path}; refusing to import. "
                "Pin the real checksum or run `python3 tools/pvas_image.py import` after "
                "placing the tracked rootfs tar."
            )
        print(f"[pvas][WARN] SHA256SUMS placeholder detected for {tar_path}; skipping integrity check",
              file=sys.stderr)
    else:
        verify_tar(tar_path, expected_sha256)
    if is_imported(image, backend, env_overrides=env_overrides):
        return image
    import_image(tar_path, image, backend, env_overrides=env_overrides)
    return image


def list_containers_by_audit(audit_id: str, backend: str,
                             env_overrides: Optional[dict] = None) -> list[str]:
    """返回 label pvas-audit-id=<audit_id> 的所有容器 id 列表。"""
    env = _merged_env(env_overrides)
    p = _run([backend, "ps", "-a", "--filter", f"label=pvas-audit-id={audit_id}",
              "--format", "{{.ID}}"], env=env)
    if p.returncode != 0:
        return []
    return [line.strip() for line in p.stdout.splitlines() if line.strip()]


def list_images_by_audit(audit_id: str, backend: str,
                         env_overrides: Optional[dict] = None) -> list[str]:
    """返回 label pvas-audit-id=<audit_id> 的所有镜像 tag 列表。"""
    env = _merged_env(env_overrides)
    p = _run([backend, "images", "--filter", f"label=pvas-audit-id={audit_id}",
              "--format", "{{.Repository}}:{{.Tag}}"], env=env)
    if p.returncode != 0:
        return []
    return [line.strip() for line in p.stdout.splitlines() if line.strip()]


def prompt_cleanup(audit_id: str, backend: str,
                   env_overrides: Optional[dict] = None,
                   log_path: Optional[Path] = None) -> None:
    """审计完成后根据 PVAS_CLEANUP_IMAGES 决定行为：
    ask（默认，TTY 交互）/ always / always-prune-image / never。
    非交互（无 TTY）时按 always 处理，保留镜像仅清容器。
    """
    containers = list_containers_by_audit(audit_id, backend, env_overrides=env_overrides)
    images = list_images_by_audit(audit_id, backend, env_overrides=env_overrides)
    if not containers and not images:
        return

    policy = os.environ.get("PVAS_CLEANUP_IMAGES", "ask").lower()
    action_log: list[dict] = []
    if policy == "never":
        _log_cleanup(log_path, audit_id, "skipped-never", action_log)
        return
    if policy in ("always", "always-prune-image") or not sys.stdin.isatty():
        keep_image = policy != "always-prune-image"
        _do_cleanup(containers, images, backend, keep_image, action_log,
                    env_overrides=env_overrides)
        _log_cleanup(log_path, audit_id, "auto", action_log)
        return

    print(f"\n[pvas] audit {audit_id} complete.")
    print(f"  containers: {len(containers)}")
    print(f"  images:     {len(images)}")
    if input("[pvas] Remove containers? [y/N]: ").strip().lower() in ("y", "yes"):
        _remove_containers(containers, backend, action_log, env_overrides=env_overrides)
    if input("[pvas] Remove pvas-sandbox:* images? [y/N]: ").strip().lower() in ("y", "yes"):
        _remove_images(images, backend, action_log, env_overrides=env_overrides)
    _log_cleanup(log_path, audit_id, "interactive", action_log)


def _remove_containers(containers: list[str], backend: str, action_log: list[dict],
                       env_overrides: Optional[dict] = None) -> None:
    env = _merged_env(env_overrides)
    for cid in containers:
        subprocess.run([backend, "rm", "-f", cid], capture_output=True, env=env)
    action_log.append({"action": "rm-containers", "items": containers})


def _remove_images(images: list[str], backend: str, action_log: list[dict],
                   env_overrides: Optional[dict] = None) -> None:
    env = _merged_env(env_overrides)
    for img in images:
        subprocess.run([backend, "rmi", img], capture_output=True, env=env)
    action_log.append({"action": "rmi-images", "items": images})


def _do_cleanup(containers: list[str], images: list[str], backend: str,
                keep_image: bool, action_log: list[dict],
                env_overrides: Optional[dict] = None) -> None:
    _remove_containers(containers, backend, action_log, env_overrides=env_overrides)
    if not keep_image:
        _remove_images(images, backend, action_log, env_overrides=env_overrides)


def _log_cleanup(log_path: Optional[Path], audit_id: str, mode: str,
                 actions: list[dict]) -> None:
    if not log_path:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "audit_id": audit_id, "mode": mode, "actions": actions}
    with log_path.open("a") as f:
        f.write(json.dumps(record) + "\n")


def build_runtime(base_image: str, target_image: str, dockerfile: Path,
                  backend: str, env_overrides: Optional[dict] = None) -> None:
    """从 imported image 构建 runtime image。"""
    env = dict(os.environ)
    if env_overrides:
        env.update(env_overrides)
    p = subprocess.run(
        [backend, "build", "-f", str(dockerfile),
         "--build-arg", f"BASE={base_image}",
         "-t", target_image, str(dockerfile.parent)],
        capture_output=True, text=True, env=env, timeout=300,
    )
    if p.returncode != 0:
        raise ImageImportFailed(f"{backend} build runtime failed: {p.stderr.strip()}")


def ensure_runtime_image(
    base_image: str,
    target_image: str,
    dockerfile: Path,
    backend: str,
    env_overrides: Optional[dict] = None,
) -> str:
    """如果 target_image 不存在则构建。返回 target tag。"""
    if is_imported(target_image, backend, env_overrides=env_overrides):
        return target_image
    build_runtime(base_image, target_image, dockerfile, backend,
                  env_overrides=env_overrides)
    return target_image


def detect_backend(env_overrides: Optional[dict] = None) -> str:
    """Return docker or podman from PATH, preferring docker."""
    env = _merged_env(env_overrides)
    for candidate in ("docker", "podman"):
        if shutil.which(candidate, path=env.get("PATH")):
            return candidate
    raise ImageImportFailed("no docker/podman backend found in PATH")


def status_payload(
    tar_path: Path = DEFAULT_TAR_PATH,
    sums_path: Path = DEFAULT_SHA256SUMS,
    imported_image: str = DEFAULT_IMAGE_IMPORTED,
    runtime_image: str = DEFAULT_IMAGE_RUNTIME,
    backend: Optional[str] = None,
    env_overrides: Optional[dict] = None,
) -> dict:
    """Return a JSON-serializable readiness payload for the sandbox images."""
    payload: dict = {
        "tar_path": str(tar_path),
        "tar_exists": tar_path.is_file(),
        "checksum_path": str(sums_path),
        "checksum_exists": sums_path.is_file(),
        "expected_sha256": "",
        "actual_sha256": "",
        "hash_matches": False,
        "hash_status": "unknown",
        "backend": "",
        "imported_image": imported_image,
        "imported_exists": False,
        "runtime_image": runtime_image,
        "runtime_exists": False,
        "status": "not-ready",
    }
    try:
        expected = read_expected_sha256(sums_path, tar_path.name)
        payload["expected_sha256"] = expected
        if _is_placeholder_sha256(expected):
            payload["hash_status"] = "placeholder"
        elif payload["tar_exists"]:
            actual = sha256_file(tar_path)
            payload["actual_sha256"] = actual
            payload["hash_matches"] = actual == expected
            payload["hash_status"] = "match" if actual == expected else "mismatch"
        else:
            payload["hash_status"] = "tar-missing"
    except ImageImportFailed as exc:
        payload["hash_status"] = f"error: {exc}"

    try:
        selected_backend = backend or detect_backend(env_overrides=env_overrides)
        payload["backend"] = selected_backend
        payload["imported_exists"] = is_imported(imported_image, selected_backend, env_overrides=env_overrides)
        payload["runtime_exists"] = is_imported(runtime_image, selected_backend, env_overrides=env_overrides)
    except ImageImportFailed:
        payload["backend"] = ""

    ready_hash = payload["tar_exists"] and payload["hash_matches"]
    ready_images = bool(payload["backend"]) and payload["imported_exists"] and payload["runtime_exists"]
    if ready_hash and ready_images:
        payload["status"] = "ready"
    elif ready_hash:
        payload["status"] = "import-required"
    return payload


def import_default_images(
    tar_path: Path = DEFAULT_TAR_PATH,
    sums_path: Path = DEFAULT_SHA256SUMS,
    imported_image: str = DEFAULT_IMAGE_IMPORTED,
    runtime_image: str = DEFAULT_IMAGE_RUNTIME,
    dockerfile: Path = DEFAULT_DOCKERFILE,
    backend: Optional[str] = None,
    env_overrides: Optional[dict] = None,
) -> dict:
    """Verify the rootfs tar, import the base image, and build the runtime image."""
    selected_backend = backend or detect_backend(env_overrides=env_overrides)
    expected = read_expected_sha256(sums_path, tar_path.name)
    imported = ensure_imported(
        tar_path,
        expected,
        imported_image,
        selected_backend,
        env_overrides=env_overrides,
    )
    runtime = ensure_runtime_image(
        imported,
        runtime_image,
        dockerfile,
        selected_backend,
        env_overrides=env_overrides,
    )
    return status_payload(
        tar_path=tar_path,
        sums_path=sums_path,
        imported_image=imported_image,
        runtime_image=runtime_image,
        backend=selected_backend,
        env_overrides=env_overrides,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage PVAS sandbox rootfs images")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "import"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--tar", type=Path, default=DEFAULT_TAR_PATH)
        cmd.add_argument("--sha256sums", type=Path, default=DEFAULT_SHA256SUMS)
        cmd.add_argument("--imported-image", default=DEFAULT_IMAGE_IMPORTED)
        cmd.add_argument("--runtime-image", default=DEFAULT_IMAGE_RUNTIME)
        cmd.add_argument("--backend", choices=("docker", "podman"))
        if name == "import":
            cmd.add_argument("--dockerfile", type=Path, default=DEFAULT_DOCKERFILE)
    return parser


def main(argv: Optional[list[str]] = None, env_overrides: Optional[dict] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "status":
            payload = status_payload(
                tar_path=args.tar,
                sums_path=args.sha256sums,
                imported_image=args.imported_image,
                runtime_image=args.runtime_image,
                backend=args.backend,
                env_overrides=env_overrides,
            )
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            return 0 if payload["status"] == "ready" else 1

        payload = import_default_images(
            tar_path=args.tar,
            sums_path=args.sha256sums,
            imported_image=args.imported_image,
            runtime_image=args.runtime_image,
            dockerfile=args.dockerfile,
            backend=args.backend,
            env_overrides=env_overrides,
        )
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    except ImageImportFailed as exc:
        print(f"[pvas_image] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

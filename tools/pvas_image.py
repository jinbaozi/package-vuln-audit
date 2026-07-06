#!/usr/bin/env python3
"""PVAS 镜像管理：import、缓存、清理。

Thin stdlib-only wrapper around the docker/podman CLI. No third-party SDK.
Image tags follow `pvas-sandbox:v11-2503-{imported,runtime}`.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

DEFAULT_IMAGE_IMPORTED = "pvas-sandbox:v11-2503-imported"
DEFAULT_IMAGE_RUNTIME = "pvas-sandbox:v11-2503-runtime"

# The shipped sandbox/rootfs/SHA256SUMS carries an all-zeros placeholder because
# the real rootfs tarball is delivered out-of-band (git-lfs). Treat that exact
# value as "integrity unknown, proceed with a warning" rather than a hard fail.
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


def verify_tar(tar_path: Path, expected_sha256: str) -> None:
    """校验 tar 的 SHA256。失败抛 ImageImportFailed。"""
    if not tar_path.is_file():
        raise ImageImportFailed(f"missing tar: {tar_path}")
    actual = hashlib.sha256(tar_path.read_bytes()).hexdigest()
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
) -> str:
    """verify → is_imported? skip : import。返回 image tag。

    当 expected_sha256 是全零占位符时（真实 rootfs tar 尚未随仓库分发），
    仅打印 warning 并跳过校验后继续 import，避免阻断审计。
    """
    if _is_placeholder_sha256(expected_sha256):
        print(
            f"[pvas][WARN] SHA256SUMS placeholder detected for {tar_path}; "
            "skipping integrity check (real rootfs tarball not yet pinned)",
            file=sys.stderr,
        )
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

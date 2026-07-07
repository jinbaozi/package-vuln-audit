#!/usr/bin/env python3
"""PVAS 容器沙盒核心抽象：spec / result / run / run_parallel。

为 Task 8 (`run_tool_matrix.py` 并行工具执行)、Task 9
(`generate_poc_testcase.py` POC 重现) 与 Task 10 (`enforced_audit_driver`
编排) 提供统一入口，把 `pvas_image` 与 `pvas_netpolicy` 串起来。

关键约束：
- 单工具内存硬上限 `MAX_TOOL_MEM_MB = 4096`（系统 8G 的 50%）。
- 默认 `--read-only` rootfs + `cap_drop=["ALL"]` + `user="65534:65534"`。
- `compute_max_workers` 永远 `>= 1`。
- `run_parallel` 内部用 `concurrent.futures.ThreadPoolExecutor`，单工具 OOM 时
  退避一次（`min(curr*2, MAX_TOOL_MEM_MB)`）。
- `NetworkPolicyApplyFailed` → 降级为 `network_policy="host"` 并把
  `result.netpolicy_id` 写成 `degraded-no-netpolicy`；strict 且
  allow_degraded=false 时阻断审计。
"""
from __future__ import annotations

import concurrent.futures
import base64
import dataclasses
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

MAX_TOOL_MEM_MB = 4096
MAX_WORKERS_DEFAULT = 4


class SandboxUnavailable(RuntimeError):
    """Neither docker nor podman is available."""


class NetworkPolicyApplyFailed(RuntimeError):
    """iptables rule could not be applied; default behavior is to block execution."""


class ConfigurationError(RuntimeError):
    """Invalid ContainerSpec (e.g. mem_limit_mb > MAX_TOOL_MEM_MB)."""


@dataclass
class ContainerSpec:
    image: str
    command: Sequence[str]
    mounts: list  # list[tuple[Path | str, str, str]]
    network_policy: str  # "bridge-deny" | "bridge-allow" | "host"
    allowed_cidrs: list = field(default_factory=list)
    env: Mapping[str, str] = field(default_factory=dict)
    workdir: str = "/workspace"
    timeout_seconds: int = 600
    cpu_limit: Optional[float] = None
    mem_limit_mb: Optional[int] = None
    read_only_rootfs: bool = True
    user: str = "65534:65534"
    cap_drop: list = field(default_factory=lambda: ["ALL"])
    cap_add: list = field(default_factory=list)
    labels: dict = field(default_factory=dict)


@dataclass
class ContainerResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    container_id: str
    oom_killed: bool
    timed_out: bool
    netpolicy_id: Optional[str] = None
    executed_via: str = "container"


DEFAULT_RUNTIME_IMAGE = "pvas-sandbox:v11-2503-runtime"


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def allow_netpolicy_degraded() -> bool:
    return _truthy(os.environ.get("PVAS_ALLOW_NETPOLICY_DEGRADED"))


def _spec_to_dict(spec: ContainerSpec) -> dict:
    return dataclasses.asdict(spec)


def _spec_from_dict(data: Mapping[str, object]) -> ContainerSpec:
    return ContainerSpec(
        image=str(data["image"]),
        command=list(data["command"]),
        mounts=list(data.get("mounts") or []),
        network_policy=str(data.get("network_policy", "bridge-deny")),
        allowed_cidrs=list(data.get("allowed_cidrs") or []),
        env=dict(data.get("env") or {}),
        workdir=str(data.get("workdir", "/workspace")),
        timeout_seconds=int(data.get("timeout_seconds", 600)),
        cpu_limit=data.get("cpu_limit"),
        mem_limit_mb=data.get("mem_limit_mb"),
        read_only_rootfs=bool(data.get("read_only_rootfs", True)),
        user=str(data.get("user", "65534:65534")),
        cap_drop=list(["ALL"] if data.get("cap_drop") is None else data.get("cap_drop")),
        cap_add=list(data.get("cap_add") or []),
        labels=dict(data.get("labels") or {}),
    )


def _result_to_dict(result: ContainerResult) -> dict:
    return dataclasses.asdict(result)


def _encode_payload(payload: Mapping[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_payload(encoded: str) -> dict:
    raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
    return json.loads(raw.decode("utf-8"))


def wrap_command(
    command: Sequence[str],
    *,
    image: str | None = None,
    mounts: list | None = None,
    network_policy: str = "bridge-deny",
    allowed_cidrs: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    workdir: str = "/workspace",
    timeout_seconds: int = 600,
    cpu_limit: float | None = None,
    mem_limit_mb: int | None = None,
    read_only_rootfs: bool = True,
    user: str = "65534:65534",
    cap_drop: Sequence[str] | None = None,
    cap_add: Sequence[str] | None = None,
    labels: Mapping[str, str] | None = None,
    backend: str | None = None,
) -> list[str]:
    """Return argv for a subprocess-compatible runner around pvas_container.run().

    This compatibility API intentionally does not expose raw docker arguments.
    The returned command launches ``pvas_container_exec.py``, which decodes the
    spec and reuses ``run()`` so network policy, cleanup, and result capture stay
    centralized.
    """
    spec = ContainerSpec(
        image=image or os.environ.get("PVAS_RUNTIME_IMAGE", DEFAULT_RUNTIME_IMAGE),
        command=list(command),
        mounts=mounts or [],
        network_policy=network_policy,
        allowed_cidrs=list(allowed_cidrs or []),
        env=dict(env or {}),
        workdir=workdir,
        timeout_seconds=timeout_seconds,
        cpu_limit=cpu_limit,
        mem_limit_mb=mem_limit_mb,
        read_only_rootfs=read_only_rootfs,
        user=user,
        cap_drop=list(["ALL"] if cap_drop is None else cap_drop),
        cap_add=list(cap_add or []),
        labels=dict(labels or {}),
    )
    payload = {"spec": _spec_to_dict(spec), "backend": backend}
    runner = Path(__file__).with_name("pvas_container_exec.py")
    return [sys.executable, str(runner), "--spec-json-b64", _encode_payload(payload)]


def detect_backend() -> str:
    """检测 docker 或 podman。都不可用抛 SandboxUnavailable。"""
    for backend in ("docker", "podman"):
        try:
            which = subprocess.run(
                ["command", "-v", backend],
                capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if which.returncode != 0:
            continue
        try:
            info = subprocess.run(
                [backend, "info"], capture_output=True, text=True, timeout=10,
            )
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            continue
        if info.returncode == 0:
            return backend
    raise SandboxUnavailable("neither docker nor podman is available and operational")


def _validate_mem_limits(spec: ContainerSpec) -> None:
    if spec.mem_limit_mb is not None and spec.mem_limit_mb > MAX_TOOL_MEM_MB:
        raise ConfigurationError(
            f"mem_limit_mb={spec.mem_limit_mb} exceeds MAX_TOOL_MEM_MB={MAX_TOOL_MEM_MB}"
        )


def _build_docker_args(spec: ContainerSpec, backend: str) -> list[str]:
    args = [backend, "run", "--rm"]
    if spec.read_only_rootfs:
        args.append("--read-only")
    if spec.user:
        args += ["-u", spec.user]
    for cap in spec.cap_drop:
        args += ["--cap-drop", cap]
    for cap in spec.cap_add:
        args += ["--cap-add", cap]
    if spec.mem_limit_mb is not None:
        args += ["-m", f"{spec.mem_limit_mb}m"]
    if spec.cpu_limit is not None:
        args += ["--cpus", str(spec.cpu_limit)]
    if spec.workdir:
        args += ["-w", spec.workdir]
    for k, v in spec.env.items():
        args += ["-e", f"{k}={v}"]
    for mount in spec.mounts:
        host_p, container_p, mode = mount[0], mount[1], mount[2]
        args += ["-v", f"{host_p}:{container_p}:{mode}"]
    for k, v in spec.labels.items():
        args += ["--label", f"{k}={v}"]
    if spec.network_policy == "host":
        args += ["--network", "host"]
    elif spec.network_policy in ("bridge-deny", "bridge-allow"):
        args += ["--network", "bridge"]
    # iptables 规则在 run() 内部按 network_policy 应用
    args += [spec.image]
    args += list(spec.command)
    return args


_OOM_TOKENS = ("OOM", "out of memory", "killed process")


def _detect_oom(stderr: str) -> bool:
    low = stderr.lower()
    return any(token.lower() in low for token in _OOM_TOKENS)


def _strict_no_degrade() -> bool:
    mode = os.environ.get("PVAS_STRICT_MODE") or os.environ.get("PVAS_ENV_PROFILE") or ""
    allow = os.environ.get("PVAS_ALLOW_DEGRADED", "false").lower()
    return mode.lower().startswith("strict") and allow not in {"1", "true", "yes", "on"}


def _parse_container_id(stdout: str) -> str:
    """从 docker stdout 中挑出 12 位十六进制的容器 id（mock 自定义时也可）。"""
    for line in stdout.splitlines():
        s = line.strip()
        if len(s) == 12 and all(c in "0123456789abcdef" for c in s):
            return s
    return ""


def _purpose_from_labels(labels: Mapping[str, str]) -> str:
    """根据 spec.labels 决定 pvas_netpolicy 的 purpose 前缀。"""
    p = labels.get("pvas-purpose", "")
    return "poc" if "poc" in p else "tool"


def _apply_network_policy(spec: ContainerSpec) -> Optional[str]:
    """对需要 network policy 的 spec 应用 iptables 规则。

    Returns the netpolicy_id. Raises NetworkPolicyApplyFailed if iptables is
    unavailable / rejected. Returns None for policies that don't need an iptables
    chain (host or bridge-allow without explicit CIDR scope).
    """
    if spec.network_policy == "host":
        return None
    if spec.network_policy == "bridge-allow":
        # bridge-allow 的语义是使用 docker bridge 但不在 PVAS 层做 iptables
        # 限制（相当于放行）；保留接口位以备日后加白名单。
        return None
    # bridge-deny / 其他：调用 pvas_netpolicy.apply。
    try:
        import pvas_netpolicy  # local import — 不强依赖 netpolicy 模块可独立单测
    except ImportError as exc:
        raise NetworkPolicyApplyFailed("pvas_netpolicy module not importable") from exc
    container_id = spec.labels.get("pvas-audit-id", "pvas-unknown")
    try:
        return pvas_netpolicy.apply(
            container_id,
            allowed_cidrs=list(spec.allowed_cidrs),
            purpose=_purpose_from_labels(spec.labels),
        )
    except pvas_netpolicy.NetworkPolicyApplyFailed as exc:
        # Re-raise as our local class so run() can `except NetworkPolicyApplyFailed`
        # without depending on the pvas_netpolicy module's class identity.
        raise NetworkPolicyApplyFailed(str(exc)) from exc


def _remove_network_policy(npid: Optional[str]) -> None:
    if not npid:
        return
    try:
        import pvas_netpolicy
    except ImportError:
        return
    try:
        pvas_netpolicy.remove(npid)
    except Exception:
        pass


def _run_with_subprocess(args: list[str], spec: ContainerSpec
                         ) -> tuple[int, str, str, bool, str]:
    """底层 Popen 启动 + 等待 + 收尸；返回 (exit_code, stdout, stderr, timed_out, cid)."""
    timed_out = False
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SandboxUnavailable(f"backend binary not found: {exc}") from exc

    try:
        stdout, stderr = proc.communicate(timeout=spec.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
            stdout, stderr = proc.communicate()
    cid = _parse_container_id(stdout)
    return proc.returncode, stdout, stderr, timed_out, cid


def run(spec: ContainerSpec, backend: Optional[str] = None) -> ContainerResult:
    """启动一个容器、等待、收集结果、销毁。严格 try/finally 清理。"""
    _validate_mem_limits(spec)
    if backend is None:
        backend = detect_backend()

    start = time.time()
    npid: Optional[str] = None
    applied_policy = spec.network_policy
    executed_via = "container"

    # 1. 网络策略
    try:
        npid = _apply_network_policy(spec)
    except NetworkPolicyApplyFailed:
        if _strict_no_degrade():
            raise
        # iptables 不可用 → 兼容模式下降级为 host
        applied_policy = "host"
        npid = "degraded-no-netpolicy"
        executed_via = "host-degraded-network-policy"

    # 2. 容器运行；spec 不可变（dataclass），所以重建一个应用降级后的策略版本
    actual_spec = spec
    if applied_policy != spec.network_policy:
        actual_spec = dataclasses.replace(spec, network_policy="host")

    args = _build_docker_args(actual_spec, backend)
    try:
        exit_code, stdout, stderr, timed_out, cid = _run_with_subprocess(args, spec)
    except SandboxUnavailable:
        # 即便 docker 也挂了也要清 netpolicy
        raise
    finally:
        if npid and npid != "degraded-no-netpolicy":
            _remove_network_policy(npid)

    oom = _detect_oom(stderr)
    return ContainerResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=time.time() - start,
        container_id=cid,
        oom_killed=oom,
        timed_out=timed_out,
        netpolicy_id=npid,
        executed_via=executed_via,
    )


def compute_max_workers(
    specs: list,
    available_mem_mb: int,
    cpu_count: Optional[int] = None,
    max_workers: Optional[int] = None,
) -> int:
    """min(applicable_count, cpu_count, max_workers, mem_budget)，floor=1。

    mem_budget 取所有 spec 里最大的 mem_limit_mb（None 时按 1024 估算）作为
    单位代价，确保不会因两个小 spec 错误地撑高并发。
    """
    if not specs:
        return 1
    if cpu_count is None:
        cpu_count = os.cpu_count() or 1
    if max_workers is None:
        max_workers = int(os.environ.get("PVAS_TOOL_MAX_WORKERS", MAX_WORKERS_DEFAULT))
    max_tool_mem = max((s.mem_limit_mb or 1024) for s in specs)
    if max_tool_mem <= 0:
        max_tool_mem = 1024
    mem_budget = available_mem_mb // max_tool_mem
    raw = min(len(specs), int(cpu_count), int(max_workers), int(mem_budget))
    return max(1, raw)


def _available_mem_mb() -> int:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError):
        pass
    return 8192


def run_parallel(
    specs: list,
    max_workers: Optional[int] = None,
    available_mem_mb: Optional[int] = None,
    backend: Optional[str] = None,
) -> list:
    """线程池并行跑 N 个独立 spec。

    单 spec OOM 后自动按 `min(curr*2, MAX_TOOL_MEM_MB)` 重试一次；其余异常
    都被捕获并写入一个 `exit_code=-1` 的占位 `ContainerResult`，绝不抛出。
    """
    if not specs:
        return []
    if available_mem_mb is None:
        available_mem_mb = _available_mem_mb()
    if max_workers is None:
        max_workers = compute_max_workers(specs, available_mem_mb)

    def _run_with_oom_retry(spec: ContainerSpec):
        result = run(spec, backend=backend)
        if not result.oom_killed:
            return result
        current = spec.mem_limit_mb or 1024
        new_limit = min(current * 2, MAX_TOOL_MEM_MB)
        if new_limit <= current:
            return result
        spec2 = dataclasses.replace(spec, mem_limit_mb=new_limit)
        return run(spec2, backend=backend)

    results: list = [None] * len(specs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_idx = {ex.submit(_run_with_oom_retry, s): i
                         for i, s in enumerate(specs)}
        for fut in concurrent.futures.as_completed(future_to_idx):
            i = future_to_idx[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:
                results[i] = ContainerResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"pvas_container.run_parallel worker error: {exc}",
                    duration_seconds=0.0,
                    container_id="",
                    oom_killed=False,
                    timed_out=False,
                    netpolicy_id=None,
                    executed_via="container",
                )
    return [r for r in results if r is not None]

#!/usr/bin/env python3
"""PVAS iptables 规则生命周期：apply / remove / flush_all。

每个 PVAS-managed 容器在启动前调用 `apply(container_id, allowed_cidrs, purpose)`
建一条 PV_<netpolicy_id> 自定义链，仅匹配该容器的 cgroup（`--cgroup`），
不动主机的 OUTPUT 链本体（除插入跳转）。`remove(netpolicy_id)` 幂等清理。
`flush_all()` 用于进程退出时扫尾，清除所有 PVAS 命名链。

异常语义：底层 iptables 失败 → 抛 `NetworkPolicyApplyFailed`，由
`pvas_container.run()` 捕获后降级为 `--network=host` 并把
`netpolicy_id` 写成 `degraded-no-netpolicy`，不阻断审计。
"""
from __future__ import annotations

import pathlib
import secrets
import subprocess
import uuid
from typing import Optional

_POLICY_PREFIX_POC = "pvas-poc"
_POLICY_PREFIX_TOOL = "pvas-tool"
# iptables chain-name hard limit is 29 chars (NF_CHAIN_NAMES_MAX-1 = 29-1=28
# but the loader rejects chain names longer than 29 octets). The full
# netpolicy_id is `<prefix>-<8hex>-<4hex>` (~22 chars) so we keep only a
# short "PV_" prefix to stay well under the limit while preserving
# uniqueness (8+4 hex = 12 hex chars = 48 bits of entropy per chain).
# flush_all() filters on the same prefix.
_CHAIN_PREFIX = "PV_"


class NetworkPolicyApplyFailed(RuntimeError):
    """iptables 不可用或拒绝操作。调用方应降级到 host 网络。"""


def _new_id(prefix: str) -> str:
    """生成形如 `<prefix>-<8 hex>-<4 hex>` 的 netpolicy_id。"""
    return f"{prefix}-{uuid.uuid4().hex[:8]}-{secrets.token_hex(2)}"


def _chain_name(netpolicy_id: str) -> str:
    """netpolicy_id → iptables 链名（把 '-' 换成 '_'，避免 chain 名解析问题）。"""
    return f"{_CHAIN_PREFIX}{netpolicy_id.replace('-', '_')}"


def _run_iptables(args: list[str]) -> subprocess.CompletedProcess:
    """Run iptables; raise NetworkPolicyApplyFailed on non-zero exit or when
    the binary is missing from PATH.

    We capture stderr so the caller (and the audit log) can see why the rule
    was rejected. A missing iptables binary must also surface as
    NetworkPolicyApplyFailed (not bare FileNotFoundError) so that
    `pvas_container.run()` can degrade to `--network=host`. The caller must
    propagate the exception so pvas_container can degrade to host networking
    rather than running with partial iptables.
    """
    try:
        proc = subprocess.run(["iptables", *args], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise NetworkPolicyApplyFailed(
            f"iptables binary not found: {exc}"
        ) from exc
    if proc.returncode != 0:
        raise NetworkPolicyApplyFailed(
            f"iptables {' '.join(args)} failed (rc={proc.returncode}): "
            f"{proc.stderr.strip()}"
        )
    return proc


def apply(container_id: str, allowed_cidrs: Optional[list[str]] = None,
          purpose: str = "poc",
          policy_template: Optional[str] = None) -> str:
    """启动容器前：建 iptables 链、写 DROP 规则。返回 netpolicy_id。

    Parameters
    ----------
    container_id : str
        cgroup 路径中标识 PVAS 容器的字符串（典型为 docker 容器 ID）。
    allowed_cidrs : list[str] | None
        白名单 CIDR；空/None 表示仅放行 loopback + 已建立连接，其余 DROP。
    purpose : 'poc' | 'tool'
        决定 netpolicy_id 前缀 (`pvas-poc-` / `pvas-tool-`)。
    policy_template : str | None
        Optional path to a custom netpolicy template (e.g.
        sandbox/netpolicy/bridge-deny.rules). If None, uses the built-in
        default rules below.
    """
    if purpose not in ("poc", "tool"):
        raise ValueError(f"purpose must be 'poc' or 'tool', got {purpose!r}")
    prefix = _POLICY_PREFIX_POC if purpose == "poc" else _POLICY_PREFIX_TOOL
    npid = _new_id(prefix)
    chain = _chain_name(npid)

    # 1. 自定义链 + 基础规则（loopback / established）
    _run_iptables(["-N", chain])
    _run_iptables(["-A", chain, "-o", "lo", "-j", "RETURN"])
    _run_iptables(["-A", chain, "-m", "state", "--state", "ESTABLISHED,RELATED",
                   "-j", "RETURN"])

    # 2. 白名单 CIDR（任意非空 list 才会写 RETURN 规则）
    for cidr in (allowed_cidrs or []):
        _run_iptables(["-A", chain, "-d", cidr, "-j", "RETURN"])

    # 3. 加载可选的 policy_template 中的附加规则
    if policy_template:
        template_path = pathlib.Path(policy_template)
        if template_path.is_file():
            for raw_line in template_path.read_text().splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                # 替换 <AUDIT_ID> 占位符为当前 npid 的简化版
                if "<AUDIT_ID>" in line:
                    line = line.replace("<AUDIT_ID>", npid.split("-")[-1][:8])
                # 解析为 iptables 参数（按空格分割，但引号保留）
                rule = line[2:].split() if line.startswith("-A") else line.split()
                if rule:
                    try:
                        _run_iptables(rule)
                    except NetworkPolicyApplyFailed:
                        pass
        else:
            print(f"[pvas-netpolicy] WARN: policy_template not found: {template_path}")

    # 4. 兜底 drop
    _run_iptables(["-A", chain, "-j", "DROP"])

    # 5. 在 OUTPUT 链顶部插入 cgroup 匹配跳转（仅匹配 PVAS 自己的 cgroup）
    _run_iptables(["-I", "OUTPUT", "1", "-m", "cgroup", "--cgroup", container_id,
                   "-j", chain])

    return npid


def remove(netpolicy_id: str) -> None:
    """清理 iptables 跳转 + 自定义链。幂等：链不存在不报错。

    实现：从 `iptables -S` 中挑出所有带 `-j <chain>` 的规则（包括 OUTPUT 链上
    的跳转和 PVAS 自定义链内的 RETURN/DROP），统一 `-A → -D` 后逐条删除，
    再 `-F` + `-X` 清空并删除自定义链。所有失败均吞掉（不影响幂等性）。
    """
    chain = _chain_name(netpolicy_id)
    listing = subprocess.run(["iptables", "-S"], capture_output=True, text=True)

    # 1. 收集所有提到该 chain 的规则行（iptables -S 输出统一为 -A 形式）
    rules_to_delete: list[list[str]] = []
    for line in listing.stdout.splitlines():
        parts = line.split()
        if not parts or parts[0] != "-A":
            continue
        # parts 形如: ['-A', chain_or_OUTPUT, ...optional flags..., '-j', target_chain]
        if chain in parts:
            # 重建为 iptables delete 命令：-A → -D，其他参数保持不变
            rules_to_delete.append(["-D"] + parts[1:])

    for rule in rules_to_delete:
        # 容忍 'rule不存在' 这类 race（链已被并发删除）
        try:
            _run_iptables(rule)
        except NetworkPolicyApplyFailed:
            pass

    # 2. -F 自定义链（容忍链已空 / 已不存在）
    try:
        _run_iptables(["-F", chain])
    except NetworkPolicyApplyFailed:
        pass
    try:
        _run_iptables(["-X", chain])
    except NetworkPolicyApplyFailed:
        pass


def flush_all() -> None:
    """进程退出前：清理所有 PVAS 链 + OUTPUT 链上指向它们的跳转。

    用于 `enforced_audit_driver` 在 atexit / 异常退出时扫尾：
    `iptables -S` 枚举规则，挑出链名以 `PV_` 开头的所有
    自定义链并删除，同时把 OUTPUT 链上指向这些链的跳转也删掉。
    """
    listing = subprocess.run(["iptables", "-S"], capture_output=True, text=True)

    # 1. 找出所有 PV_* 自定义链（line: '-N PV_pvas_poc_<hex>_<hex>'）
    pvas_chains: set[str] = set()
    for line in listing.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "-N" and parts[1].startswith(_CHAIN_PREFIX):
            pvas_chains.add(parts[1])

    # 2. 找出 OUTPUT 链上指向 PVAS 链的跳转，转成 -D 命令后逐条删除
    for line in listing.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "-A" or parts[1] != "OUTPUT":
            continue
        # 找 -j target
        if "-j" not in parts:
            continue
        target = parts[parts.index("-j") + 1]
        if target in pvas_chains:
            try:
                _run_iptables(["-D"] + parts[1:])
            except NetworkPolicyApplyFailed:
                pass

    # 3. 清空并删除所有 PVAS 自定义链
    for chain in pvas_chains:
        try:
            _run_iptables(["-F", chain])
        except NetworkPolicyApplyFailed:
            pass
        try:
            _run_iptables(["-X", chain])
        except NetworkPolicyApplyFailed:
            pass
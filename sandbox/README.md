# PVAS Sandbox Runtime

PVAS 在容器中执行 POC reproducer 和传统扫描工具所需的全部资产。

## 目录

- `rootfs/` — 离线 rootfs tarball（git-lfs 跟踪），由 `tools/pvas_image.py` 首次运行 `docker import` 进本地 image store
- `images/` — `Dockerfile.runtime`：在 imported image 之上加 `/workspace` 与 `/out` 目录、USER nobody
- `netpolicy/` — iptables 规则模板，被 `tools/pvas_netpolicy.py` 引用
- `scripts/` — 独立可执行的 bash 包装（`pvas-import-image.sh`、`pvas-check-backend.sh`）

## 工作流

1. `enforced_audit_driver.py` 启动后，调用 `tools/pvas_image.ensure_imported()` 触发首次 import
2. `tools/pvas_container.run(spec)` 启动容器（基于 `pvas-sandbox:v11-2503-runtime`）
3. `tools/pvas_netpolicy.apply(spec, container_id)` 装 iptables drop 规则
4. 容器退出后 `tools/pvas_netpolicy.remove(netpolicy_id)` 清规则
5. `enforced_audit_driver.py` 退出前 `tools/pvas_image.prompt_cleanup(audit_id)` 询问用户是否清容器/镜像

## 详细规范

参见 `docs/superpowers/specs/2026-07-06-sandbox-runtime-design.md`。
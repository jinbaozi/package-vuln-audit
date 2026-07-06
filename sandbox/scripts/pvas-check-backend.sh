#!/bin/bash
# 检测 docker 或 podman 哪个可用。
# 用法：pvas-check-backend.sh
# 退出码：0=找到并可执行，1=都不可用
# stdout：输出 backend 名称（docker|podman）
set -euo pipefail
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "docker"
  exit 0
fi
if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
  echo "podman"
  exit 0
fi
exit 1

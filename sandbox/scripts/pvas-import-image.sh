#!/bin/bash
# 首次导入 rootfs tar 到本地 image store。
# 用法：pvas-import-image.sh
# 依赖：pvas-check-backend.sh 在同一目录
set -euo pipefail
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOTFS_DIR="${SCRIPTS_DIR}/../rootfs"
TAR="${ROOTFS_DIR}/v11-2503-rootfs.tar"
VERSION=$(cat "${ROOTFS_DIR}/VERSION")
IMAGE_TAG="pvas-sandbox:${VERSION}-imported"

# 1. 校验 tar 存在
if [[ ! -f "$TAR" ]]; then
  echo "[pvas-import-image] missing $TAR" >&2
  exit 10
fi

# 2. SHA256 校验
ACTUAL=$(sha256sum "$TAR" | awk '{print $1}')
EXPECTED=$(awk -v f="v11-2503-rootfs.tar" '$2==f {print $1}' "${ROOTFS_DIR}/SHA256SUMS")
if [[ -z "$EXPECTED" ]]; then
  echo "[pvas-import-image] v11-2503-rootfs.tar not in SHA256SUMS" >&2
  exit 11
fi
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  echo "[pvas-import-image] SHA256 mismatch: expected=$EXPECTED actual=$ACTUAL" >&2
  exit 12
fi

# 3. 检测 backend
BACKEND=$("${SCRIPTS_DIR}/pvas-check-backend.sh" || true)
if [[ -z "$BACKEND" ]]; then
  echo "[pvas-import-image] no docker/podman available" >&2
  exit 13
fi

# 4. 检查是否已导入
if $BACKEND images --format '{{.Repository}}:{{.Tag}}' | grep -qF "$IMAGE_TAG"; then
  echo "[pvas-import-image] $IMAGE_TAG already imported, skipping"
  exit 0
fi

# 5. 导入
$BACKEND import "$TAR" "$IMAGE_TAG"
echo "[pvas-import-image] imported $IMAGE_TAG"

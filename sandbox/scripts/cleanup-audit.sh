#!/usr/bin/env bash
# Cleanup all resources tagged with the audit-id used during this audit.
#
# Removes:
#   - Containers with label pvas-audit-id=$AUDIT_ID
#   - Runtime image pvas-sandbox:v11-2503-runtime (NOT imported base)
#   - Dangling layers (image prune)
#   - Build cache >24h (builder prune)
#
# Preserves (per resources.json):
#   - pvas-sandbox:v11-2503-imported (base image)
#   - bbh-poc, bbh-base, fkiecad/* (external skills)
#
# Logs to ${PVAS_LOG_DIR}/cleanup-${AUDIT_ID}.log
#
# Env vars:
#   PVAS_AUDIT_ID         — tag for cleanup (default: default-audit-id)
#   PVAS_LOG_DIR          — where to write cleanup log
#   PVAS_KEEP_IMAGES      — 1 to keep pvas-sandbox:v11-2503-runtime
#   PVAS_KEEP_BUILDER_CACHE — 1 to skip builder prune

set -euo pipefail

AUDIT_ID="${PVAS_AUDIT_ID:-default-audit-id}"
KEEP_IMAGES="${PVAS_KEEP_IMAGES:-0}"
KEEP_BUILDER_CACHE="${PVAS_KEEP_BUILDER_CACHE:-0}"
LOG_DIR="${PVAS_LOG_DIR:-$(pwd)/audit-output/machine}"
LOG_FILE="$LOG_DIR/cleanup-${AUDIT_ID}.log"
mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

log "=== cleanup-audit start audit_id=$AUDIT_ID keep_images=$KEEP_IMAGES ==="

# Pre-state
log "[pre-state] containers matching label:"
docker ps -a --filter "label=pvas-audit-id=$AUDIT_ID" --format '  {{.ID}} {{.Image}} {{.Status}}' 2>&1 | tee -a "$LOG_FILE" || true

log "[pre-state] images matching label:"
docker images --filter "label=pvas-audit-id=$AUDIT_ID" --format '  {{.Repository}}:{{.Tag}} {{.Size}}' 2>&1 | tee -a "$LOG_FILE" || true

# 1. Remove audit-tagged containers
log "[step] rm containers with label pvas-audit-id=$AUDIT_ID"
CONTAINERS=$(docker ps -a --filter "label=pvas-audit-id=$AUDIT_ID" -q 2>/dev/null || true)
if [ -n "$CONTAINERS" ]; then
    docker rm -f $CONTAINERS 2>&1 | tee -a "$LOG_FILE" || true
else
    log "  no containers found"
fi

# 2. Remove audit runtime image (preserve imported base + external skills)
if [ "$KEEP_IMAGES" != "1" ]; then
    log "[step] rmi pvas-sandbox:v11-2503-runtime"
    docker rmi -f pvas-sandbox:v11-2503-runtime 2>&1 | tee -a "$LOG_FILE" || log "  image already absent"
    docker rmi -f pvas-sandbox:v11-2503-runtime-fixed 2>&1 | tee -a "$LOG_FILE" || log "  fixed image absent"
fi

# 3. Prune dangling images
log "[step] docker image prune -f"
docker image prune -f 2>&1 | tee -a "$LOG_FILE" || true

# 4. Optionally prune build cache (skip if PVAS_KEEP_BUILDER_CACHE=1)
if [ "$KEEP_BUILDER_CACHE" != "1" ]; then
    log "[step] docker builder prune --filter until=24h"
    docker builder prune -f --filter "until=24h" 2>&1 | tee -a "$LOG_FILE" || true
fi

# Post-state
log "[post-state] remaining images:"
docker images --format '  {{.Repository}}:{{.Tag}} {{.Size}}' 2>&1 | tee -a "$LOG_FILE"

log "[post-state] remaining containers:"
docker ps -a --format '  {{.ID}} {{.Image}} {{.Status}}' 2>&1 | tee -a "$LOG_FILE"

log "=== cleanup-audit complete ==="
exit 0
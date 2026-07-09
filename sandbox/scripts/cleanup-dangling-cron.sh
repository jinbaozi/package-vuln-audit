#!/usr/bin/env bash
# Periodic cleanup of dangling Docker resources (>24h old).
# Suitable for daily cron via /etc/cron.d/pvas-cleanup
#
# Removes:
#   - Containers stopped >24h
#   - Dangling images >24h
#   - Build cache >24h (keep 10GB reserve)

echo "[cleanup-dangling-cron] start at $(date)"
docker container prune -f --filter "until=24h" 2>&1 | head -10 || true
docker image prune -f --filter "until=24h" 2>&1 | head -10 || true
docker builder prune -f --filter "until=24h" --keep-storage=10GB 2>&1 | head -10 || true
echo "[cleanup-dangling-cron] complete at $(date)"
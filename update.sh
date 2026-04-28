#!/bin/sh
# Portal — update script
# Run this from the portal folder (e.g. /share/Container/ara-portal) to pull
# the latest code from GitHub and restart the portal with zero data loss.
#
# Usage:
#   cd /share/Container/ara-portal
#   ./update.sh

set -e

PORTAL_DIR="$(cd "$(dirname "$0")" && pwd)"
SSH_DIR="/share/Container/.ssh"

echo "=== Pulling latest code from GitHub ==="
docker run --rm \
  -v "$PORTAL_DIR:/repo" \
  -v "$SSH_DIR:/root/.ssh:ro" \
  alpine sh -c "apk add --no-cache git openssh && \
    GIT_SSH_COMMAND='ssh -i /root/.ssh/ara-portal-deploy -o UserKnownHostsFile=/root/.ssh/known_hosts' \
    git -C /repo pull"

echo "=== Rebuilding Docker image ==="
docker compose -f "$PORTAL_DIR/docker-compose.yml" build

echo "=== Restarting portal ==="
docker compose -f "$PORTAL_DIR/docker-compose.yml" up -d --force-recreate

echo "=== Done! Portal is up to date ==="

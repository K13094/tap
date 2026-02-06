#!/bin/bash
# nozyme-tap auto-update via git pull.
# Install as a cron job to pull updates and restart the service if files changed.
#
# Usage:
#   sudo crontab -e
#   # Add: */30 * * * * /home/tap/nozyme_tap/deploy/auto-update.sh >> /tmp/nozyme-update.log 2>&1
#
# This checks for updates every 30 minutes. Adjust as needed.

set -e

INSTALL_DIR="/home/tap/nozyme_tap"
SERVICE_NAME="nozyme-tap"
LOG_TAG="nozyme-update"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [$LOG_TAG] $1"; }

if [ ! -d "$INSTALL_DIR/.git" ]; then
    log "Not a git repo: $INSTALL_DIR — skipping"
    exit 0
fi

cd "$INSTALL_DIR"

# Record current commit
OLD_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

# Pull latest changes
if ! git fetch --quiet origin; then
    log "ERROR: git fetch failed"
    exit 1
fi
UPSTREAM=$(git rev-parse @{u} 2>/dev/null || echo "unknown")

if [ "$OLD_COMMIT" = "$UPSTREAM" ]; then
    # No changes
    exit 0
fi

log "Update available: $OLD_COMMIT -> $UPSTREAM"
if ! git pull --quiet origin; then
    log "ERROR: git pull failed"
    exit 1
fi

NEW_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
if [ "$OLD_COMMIT" != "$NEW_COMMIT" ]; then
    log "Updated to $NEW_COMMIT, restarting $SERVICE_NAME"

    # Reinstall Python deps if requirements changed (use venv)
    VENV_DIR="/home/tap/venv"
    if git diff --name-only "$OLD_COMMIT" "$NEW_COMMIT" | grep -q "requirements.txt"; then
        log "requirements.txt changed, installing dependencies"
        if [ -d "$VENV_DIR" ]; then
            if ! "$VENV_DIR/bin/pip" install -r deploy/requirements.txt; then
                log "ERROR: pip install failed"
            fi
        else
            log "WARNING: venv not found at $VENV_DIR, skipping pip install"
        fi
    fi

    systemctl restart "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Service restarted successfully"
    else
        log "ERROR: Service failed to restart"
    fi
else
    log "Pull completed but commit unchanged"
fi

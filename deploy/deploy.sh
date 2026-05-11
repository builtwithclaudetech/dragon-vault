#!/usr/bin/env bash
# Dragon Vault — Deploy Script
# REQ-063-L: git pull -> build -> test -> publish -> systemctl restart
# REQ-064-L: appsettings.Production.json preserved across deploys
set -euo pipefail

# --- Configuration (override via env vars) ---
REPO_DIR="${REPO_DIR:-"/path/to/dragon-vault"}"
PUBLISH_DIR="${PUBLISH_DIR:-"/var/opt/dragonvault/publish"}"
CONFIG_FILE="${CONFIG_FILE:-"/var/opt/dragonvault/appsettings.Production.json"}"
SERVICE_NAME="${SERVICE_NAME:-"dragonvault.service"}"
BACKUP_DIR="${BACKUP_DIR:-"/var/opt/dragonvault/backups"}"
# -------------------------------------------

echo "=== Dragon Vault Deploy — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# ---- Pre-flight checks ----
if [ ! -d "$REPO_DIR" ]; then
    echo "FATAL: REPO_DIR ($REPO_DIR) does not exist."
    exit 1
fi

# Ensure systemd is available (non-docker check)
if ! command -v systemctl &>/dev/null; then
    echo "WARNING: systemctl not found. Skipping service restart."
    SKIP_SERVICE_RESTART=true
else
    SKIP_SERVICE_RESTART=false
fi

# 1. Git pull
echo "[1/6] Pulling latest from master..."
cd "$REPO_DIR"
git checkout master
git pull origin master

# 2. Restore
echo "[2/6] Restoring packages..."
dotnet restore

# 3. Build
echo "[3/6] Building..."
dotnet build --no-restore -c Release

# 4. Test
echo "[4/6] Running tests..."
dotnet test --no-build -c Release

# 5. Publish
echo "[5/6] Publishing..."
# Clean old publish output but PRESERVE appsettings.Production.json (REQ-064-L)
if [ -d "$PUBLISH_DIR" ]; then
    # Remove everything except the production config file
    # The find pipe is safe because:
    #   -mindepth 1  ensures the directory itself is never matched
    #   -not -name   excludes the config file from deletion
    #   || true      prevents set -e from aborting on empty-directory errors
    find "$PUBLISH_DIR" -mindepth 1 ! -name 'appsettings.Production.json' -exec rm -rf {} + 2>/dev/null || true
fi
mkdir -p "$PUBLISH_DIR"

dotnet publish src/PasswordManager.Web/PasswordManager.Web.csproj \
    --no-build -c Release \
    -o "$PUBLISH_DIR"

# Ensure the production config is in place (REQ-064-L)
if [ ! -f "$PUBLISH_DIR/appsettings.Production.json" ] && [ -f "$CONFIG_FILE" ]; then
    cp "$CONFIG_FILE" "$PUBLISH_DIR/appsettings.Production.json"
    echo "  Copied appsettings.Production.json to publish dir"
fi

# Ensure required subdirectories exist
mkdir -p "$(dirname "$PUBLISH_DIR")/dpkeys"
mkdir -p "$(dirname "$PUBLISH_DIR")/logs"

# 6. Restart service
echo "[6/6] Restarting service..."
if [ "$SKIP_SERVICE_RESTART" = false ]; then
    sudo systemctl restart "$SERVICE_NAME"
    sleep 3
    sudo systemctl status "$SERVICE_NAME" --no-pager
else
    echo "  Skipped (systemctl not available)."
fi

echo "=== Deploy complete: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

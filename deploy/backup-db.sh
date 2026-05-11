#!/usr/bin/env bash
# Dragon Vault — Nightly Database Backup
# REQ-055-L: docker exec BACKUP DATABASE -> timestamped .bak -> rclone to Google Drive
#            prune to 7 newest .bak files
set -euo pipefail

# === Configuration (override via env vars) ===
BACKUP_DIR="${BACKUP_DIR:-"/var/opt/dragonvault/backups"}"
DB_NAME="${DB_NAME:-"DragonVault"}"
RETENTION_COUNT="${RETENTION_COUNT:-7}"
GDRIVE_BACKUP_TARGET="${GDRIVE_BACKUP_TARGET:-""}"  # e.g. "gdrive:/dragonvault-backups"

# SQL Server connection — used by both docker-exec and host sqlcmd paths
SQL_SERVER="${SQL_SERVER:-"."}"
SQL_USER="${SQL_USER:-"sa"}"
# SQL_PASSWORD must be set via environment variable or .env file
# Ideally loaded from /var/opt/dragonvault/.env or a secrets manager
SQL_PASSWORD="${SQL_PASSWORD:-}"

# Docker exec path: temporary location inside the container for the backup.
# After backup completes, docker cp pulls the file to the host.
SQLCMD_INTERNAL_PATH="${SQLCMD_INTERNAL_PATH:-"/var/opt/mssql/backups"}"
CONTAINER_NAME=""  # set after discovery

# SQL container auto-detection — names to try in order
SQL_CONTAINER_NAMES=("${SQL_CONTAINER:-mssql sqlserver mssql-server mssql2022}")

# sqlcmd binary path inside the container
SQLCMD_BIN="${SQLCMD_BIN:-"/opt/mssql-tools18/bin/sqlcmd"}"
# =============================================

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Generate timestamped filename
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
BACKUP_FILENAME="${DB_NAME}_${TIMESTAMP}.bak"
BACKUP_PATH_HOST="${BACKUP_DIR}/${BACKUP_FILENAME}"
BACKUP_PATH_INTERNAL="${SQLCMD_INTERNAL_PATH}/${BACKUP_FILENAME}"

echo "=== Dragon Vault DB Backup — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "Database:    $DB_NAME"
echo "Backup file: $BACKUP_PATH_HOST"
echo ""

# ---- Step 1: Discover SQL Server ----
SQLCMD_CMD=""
SQLMODE=""

# Look for a Docker container with SQL Server
for cname in $SQL_CONTAINER_NAMES; do
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qFx "$cname"; then
        echo "[1/4] SQL Server container found: $cname"
        SQLCMD_CMD="docker exec $cname $SQLCMD_BIN"
        SQLMODE="docker"
        CONTAINER_NAME="$cname"
        break
    fi
done

# Fall back to host sqlcmd if no docker container found
if [ -z "$SQLMODE" ]; then
    if command -v sqlcmd &>/dev/null; then
        echo "[1/4] No SQL container found. Using host sqlcmd."
        SQLCMD_CMD="sqlcmd"
        SQLMODE="host"
        # When running on the host, backup path is the host path directly
        BACKUP_PATH_INTERNAL="$BACKUP_PATH_HOST"
    else
        echo "ERROR: No SQL Server container found and host sqlcmd not available."
        echo "Checked container names: $SQL_CONTAINER_NAMES"
        echo "Install sqlcmd or start the Docker container."
        exit 1
    fi
fi

# Build connection args
SQLCMD_ARGS="-S $SQL_SERVER -U $SQL_USER -P $SQL_PASSWORD -C -b"  # -C = trust server cert (TLS 1.2+)

# ---- Step 2: Run BACKUP DATABASE ----
echo "[2/4] Running BACKUP DATABASE [$DB_NAME]..."
BACKUP_SQL="
BACKUP DATABASE [$DB_NAME]
TO DISK = N'${BACKUP_PATH_INTERNAL}'
WITH COMPRESSION, CHECKSUM, INIT, FORMAT, STATS=5;
"

# Check password was provided
if [ -z "$SQL_PASSWORD" ]; then
    echo "ERROR: SQL_PASSWORD is not set. Export it before running, or store in /var/opt/dragonvault/.env"
    exit 1
fi

if ! $SQLCMD_CMD $SQLCMD_ARGS -Q "$BACKUP_SQL"; then
    echo "ERROR: BACKUP DATABASE command failed."
    exit 1
fi

# ---- After Docker backup: copy from container to host ----
if [ "$SQLMODE" = "docker" ]; then
    echo "  Copying backup from container to host..."
    if ! docker cp "$CONTAINER_NAME:$BACKUP_PATH_INTERNAL" "$BACKUP_PATH_HOST" 2>/dev/null; then
        echo "ERROR: docker cp failed. Could not copy $BACKUP_PATH_INTERNAL from $CONTAINER_NAME."
        exit 1
    fi
    # Clean up the temp file inside the container
    docker exec "$CONTAINER_NAME" rm -f "$BACKUP_PATH_INTERNAL" 2>/dev/null || true
fi

if [ ! -f "$BACKUP_PATH_HOST" ]; then
    echo "ERROR: Backup file not found at $BACKUP_PATH_HOST after docker cp."
    exit 1
fi

BACKUP_SIZE=$(du -h "$BACKUP_PATH_HOST" | cut -f1)
echo "  Backup created: $BACKUP_PATH_HOST ($BACKUP_SIZE)"

# ---- Step 3: Prune old backups (retain newest N) ----
echo "[3/4] Pruning older backups (retaining $RETENTION_COUNT)..."
PRUNE_COUNT=0
# List .bak files by modification time (newest first), skip the first RETENTION_COUNT, remove the rest
while IFS= read -r OLD_FILE; do
    rm -f "$OLD_FILE"
    echo "  Removed: $OLD_FILE"
    PRUNE_COUNT=$((PRUNE_COUNT + 1))
done < <(find "$BACKUP_DIR" -maxdepth 1 -name '*.bak' -printf '%T@\t%p\n' | sort -t$'\t' -k1 -rn | tail -n +$((RETENTION_COUNT + 1)) | cut -f2-)

if [ "$PRUNE_COUNT" -eq 0 ]; then
    echo "  No backups to prune."
else
    echo "  Pruned $PRUNE_COUNT backup(s)."
fi

# ---- Step 4: rclone to Google Drive ----
echo "[4/4] Google Drive sync..."
if [ -n "$GDRIVE_BACKUP_TARGET" ]; then
    # Check rclone is configured
    if command -v rclone &>/dev/null; then
        # Copy only the newest backup to the remote (avoid re-uploading everything on each run)
        if rclone copy "$BACKUP_PATH_HOST" "$GDRIVE_BACKUP_TARGET" --progress 2>&1; then
            echo "  Uploaded to $GDRIVE_BACKUP_TARGET"

            # Prune remote to match local retention (keep same number)
            # List remote .bak files newest-first, skip the first N, delete the rest
            REMOTE_FILES=$(rclone lsf "$GDRIVE_BACKUP_TARGET" --include '*.bak' --format 't' --separator $'\t' --max-depth 1 2>/dev/null | sort -t$'\t' -k1 -rn | tail -n +$((RETENTION_COUNT + 1)) | cut -f2-)
            while IFS= read -r REMOTE_FILE; do
                if [ -n "$REMOTE_FILE" ]; then
                    rclone delete "$GDRIVE_BACKUP_TARGET/$REMOTE_FILE" 2>/dev/null || true
                    echo "  Removed remote: $REMOTE_FILE"
                fi
            done <<< "$REMOTE_FILES"
        else
            echo "  WARNING: rclone upload failed. Backup still exists locally."
        fi
    else
        echo "  WARNING: rclone not installed. Skipping Google Drive upload."
        echo "  Install rclone from https://rclone.org/ and configure: rclone config"
    fi
else
    echo "  GDRIVE_BACKUP_TARGET not set. Skipping remote sync."
    echo "  Set it to enable: GDRIVE_BACKUP_TARGET='gdrive:/dragonvault-backups'"
fi

echo ""
echo "=== Backup complete: $BACKUP_FILENAME ($BACKUP_SIZE) ==="

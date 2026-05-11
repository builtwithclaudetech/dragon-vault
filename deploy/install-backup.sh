#!/usr/bin/env bash
# Dragon Vault — Install Backup Service + Timer
# REQ-055-L: Copies scripts and systemd units to production paths,
#            loads SQL_PASSWORD from /var/opt/dragonvault/.env,
#            enables and starts the backup timer.
set -euo pipefail

# === Configuration ===
SCRIPT_SRC="/path/to/dragon-vault/deploy"
BACKUP_DIR="/var/opt/dragonvault/backups"
SERVICE_DIR="/etc/systemd/system"
ENV_FILE="/var/opt/dragonvault/.env"
USER="YOUR-USERNAME"
GROUP="YOUR-USERNAME"
# ======================

echo "=== Dragon Vault — Install Backup System ==="

# ---- Step 1: Create directories ----
echo "[1/6] Creating backup directory..."
sudo mkdir -p "$BACKUP_DIR"
sudo chown "$USER:$GROUP" "$BACKUP_DIR"
sudo chmod 750 "$BACKUP_DIR"

# ---- Step 2: Install backup script ----
echo "[2/6] Installing backup-db.sh..."
sudo cp "$SCRIPT_SRC/backup-db.sh" /var/opt/dragonvault/backup-db.sh
sudo chown "$USER:$GROUP" /var/opt/dragonvault/backup-db.sh
sudo chmod 750 /var/opt/dragonvault/backup-db.sh

# ---- Step 3: Install systemd units ----
echo "[3/6] Installing systemd service and timer..."
sudo cp "$SCRIPT_SRC/dragonvault-backup.service" "$SERVICE_DIR/dragonvault-backup.service"
sudo cp "$SCRIPT_SRC/dragonvault-backup.timer" "$SERVICE_DIR/dragonvault-backup.timer"
sudo chmod 644 "$SERVICE_DIR/dragonvault-backup.service"
sudo chmod 644 "$SERVICE_DIR/dragonvault-backup.timer"

# ---- Step 4: Create .env file if it doesn't exist ----
echo "[4/6] Checking environment file..."
if [ ! -f "$ENV_FILE" ]; then
    echo "  Creating $ENV_FILE (requires SQL_PASSWORD)."
    echo "  You will be prompted for the SQL Server sa password."
    read -rsp "  SQL Server sa password: " SQL_PWD
    echo ""
    if [ -n "$SQL_PWD" ]; then
        # Write env file
        sudo bash -c "cat > $ENV_FILE" <<ENVEOF
# Dragon Vault — Backup Environment
# Loaded by dragonvault-backup.service
# WARNING: This file contains secrets. Keep permissions at 600.

SQL_PASSWORD=$SQL_PWD

# Google Drive rclone target (optional — uncomment to enable)
# GDRIVE_BACKUP_TARGET=gdrive:/dragonvault-backups
ENVEOF
        sudo chmod 600 "$ENV_FILE"
        sudo chown "$USER:$GROUP" "$ENV_FILE"
        echo "  $ENV_FILE created with restricted permissions (600)."
    else
        echo "  WARNING: No password entered. $ENV_FILE was NOT created."
        echo "  Create it manually:"
        echo "    sudo tee $ENV_FILE <<'EOF'"
        echo "    SQL_PASSWORD=your_sa_password"
        echo "    EOF"
        echo "    sudo chmod 600 $ENV_FILE"
    fi
else
    echo "  $ENV_FILE already exists. Skipping."
fi

# ---- Step 5: Reload systemd ----
echo "[5/6] Reloading systemd daemon..."
sudo systemctl daemon-reload

# ---- Step 6: Enable and start timer ----
echo "[6/6] Enabling and starting backup timer..."
sudo systemctl enable dragonvault-backup.timer
sudo systemctl start dragonvault-backup.timer

# Verify
echo ""
echo "=== Verification ==="
echo "Timer status:"
sudo systemctl status dragonvault-backup.timer --no-pager 2>&1 || true
echo ""
echo "Service test (dry-run):"
sudo systemctl start dragonvault-backup.service --no-block 2>&1 || echo "(Timer will run at next scheduled time)"
echo ""
echo "=== Install complete ==="
echo ""
echo "Next steps:"
echo "  1. If you skipped the .env creation, run: sudo tee /var/opt/dragonvault/.env ..."
echo "  2. Verify the timer: systemctl list-timers dragonvault-backup.timer"
echo "  3. Test the backup manually: sudo /var/opt/dragonvault/backup-db.sh"
echo "  4. (Optional) Set GDRIVE_BACKUP_TARGET in /var/opt/dragonvault/.env for offsite backup"

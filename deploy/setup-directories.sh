#!/usr/bin/env bash
# Dragon Vault — Create directory structure and set permissions
#
# Run from the deploy/ directory:
#   cd /path/to/repo/deploy
#   sudo bash setup-directories.sh
#
# Creates the following directory layout under /var/opt/dragonvault/:
#
#   /var/opt/dragonvault/
#   ├── publish/     # dotnet publish output (DLLs, views, wwwroot)
#   ├── dpkeys/      # ASP.NET Core DataProtection keys
#   ├── logs/        # Serilog bootstrap log files
#   └── backups/     # SQL Server nightly backups (Phase N)
#
# All directories are owned by www-data:www-data with 750 permissions.

set -euo pipefail

BASE_DIR="/var/opt/dragonvault"
SUBDIRS=(
    "publish"
    "dpkeys"
    "logs"
    "backups"
)

echo "==> Dragon Vault — Directory setup"
echo "  Base: ${BASE_DIR}"

# ── Step 1: Create directories ──────────────────────────────────────────────
echo "  [1/3] Creating directories..."
for dir in "${SUBDIRS[@]}"; do
    target="${BASE_DIR}/${dir}"
    mkdir -p "${target}"
    echo "    ${target}"
done

# ── Step 2: Set ownership ────────────────────────────────────────────────────
echo "  [2/3] Setting ownership to www-data:www-data..."
chown -R www-data:www-data "${BASE_DIR}"

# ── Step 3: Set permissions ──────────────────────────────────────────────────
echo "  [3/3] Setting permissions (750)..."
chmod 750 "${BASE_DIR}"
for dir in "${SUBDIRS[@]}"; do
    chmod 750 "${BASE_DIR}/${dir}"
done

# ── Step 4: Create placeholder appsettings.Production.json ───────────────────
CONFIG_PATH="${BASE_DIR}/appsettings.Production.json"
if [ ! -f "${CONFIG_PATH}" ]; then
    echo "  Creating placeholder appsettings.Production.json..."
    cat > "${CONFIG_PATH}" <<'CONFIGEOF'
{
  /*
    Dragon Vault — Production configuration.
    This file lives OUTSIDE the publish tree so it survives deploys.
    It is loaded via ASPNETCORE_ENVIRONMENT=Production.

    WARNING: Do NOT overwrite this file during deploy.
    The deploy script (Phase N) preserves it.

    Required settings:
    - ConnectionStrings:DragonVault: connection string to SQL Server
    - Authentication:Google:ClientId and ClientSecret
    - Authentication:Google:AllowedEmails (comma-separated email allowlist)
    - Authentication:Google:ClientSecret comes from the secret store
      (Azure Key Vault / environment variable / encrypted config)
  */
  "ConnectionStrings": {
    "DragonVault": "Server=127.0.0.1,1433;Database=DragonVault;User Id=sa;Password=CHANGE_ME;TrustServerCertificate=True;Encrypt=True;"
  },
  "Authentication": {
    "Google": {
      "ClientId": "REPLACE_WITH_GOOGLE_CLIENT_ID",
      "ClientSecret": "REPLACE_WITH_GOOGLE_CLIENT_SECRET",
      "AllowedEmails": "phil@example.com"
    }
  }
}
CONFIGEOF
    chown www-data:www-data "${CONFIG_PATH}"
    chmod 640 "${CONFIG_PATH}"
    echo "    ${CONFIG_PATH}"
else
    echo "  appsettings.Production.json already exists — not overwritten."
fi

echo ""
echo "==> Directory setup complete."
echo ""
echo "Directory structure:"
ls -la "${BASE_DIR}"
echo ""
echo "Next step: deploy the application binaries:"
echo "  dotnet publish -c Release -o /var/opt/dragonvault/publish"
echo "  sudo chown -R www-data:www-data /var/opt/dragonvault/publish"
echo ""
echo "NOTE on DataProtection keys path:"
echo "  Program.cs currently stores DataProtection keys at"
echo "  AppContext.BaseDirectory/dpkeys = ${BASE_DIR}/publish/dpkeys"
echo "  which would be LOST ON EVERY DEPLOY."
echo "  Edit Program.cs to use ${BASE_DIR}/dpkeys before going live."

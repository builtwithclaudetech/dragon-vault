#!/usr/bin/env bash
# Dragon Vault — Install nginx site config (REQ-061-L, REQ-069, REQ-070, REQ-075-L)
#
# Run from the deploy/ directory:
#   cd /path/to/repo/deploy
#   sudo bash install-nginx.sh
#
# This script:
#   1. Copies nginx-dragonvault.conf to /etc/nginx/sites-available/
#   2. Symlinks to /etc/nginx/sites-enabled/
#   3. Removes the default site to avoid conflicts
#   4. Adds WebSocket map to nginx.conf http block if missing
#   5. Tests config with `nginx -t`
#   6. Reloads nginx

set -euo pipefail

CONFIG_SOURCE="nginx-dragonvault.conf"
CONFIG_NAME="dragonvault"
CONFIG_AVAILABLE="/etc/nginx/sites-available/${CONFIG_NAME}"
CONFIG_ENABLED="/etc/nginx/sites-enabled/${CONFIG_NAME}"
NGINX_CONF="/etc/nginx/nginx.conf"

echo "==> Installing nginx site config: ${CONFIG_NAME}"

# Check source exists
if [ ! -f "${CONFIG_SOURCE}" ]; then
    echo "ERROR: ${CONFIG_SOURCE} not found in current directory."
    echo "       Run this script from the deploy/ directory."
    exit 1
fi

# Step 1: Copy config to sites-available
cp "${CONFIG_SOURCE}" "${CONFIG_AVAILABLE}"
chmod 644 "${CONFIG_AVAILABLE}"
echo "  [1/5] Copied to ${CONFIG_AVAILABLE}"

# Step 2: Create symlink in sites-enabled
ln -sf "${CONFIG_AVAILABLE}" "${CONFIG_ENABLED}"
echo "  [2/5] Symlinked to ${CONFIG_ENABLED}"

# Step 3: Remove default site if present (avoids port 80 conflicts)
if [ -f "/etc/nginx/sites-enabled/default" ]; then
    rm -f "/etc/nginx/sites-enabled/default"
    echo "  [3/5] Removed default site"
else
    echo "  [3/5] No default site to remove"
fi

# Step 4: Add WebSocket map to nginx.conf http block if not present
MAP_BLOCK=$(cat <<'MAPEOF'
    # Dragon Vault: WebSocket connection upgrade map (required for SignalR / live updates)
    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }
MAPEOF
)

if grep -q "map \$http_upgrade \$connection_upgrade" "${NGINX_CONF}" 2>/dev/null; then
    echo "  [4/5] WebSocket map already present in ${NGINX_CONF}"
else
    # Insert after the first occurrence of "http {" in nginx.conf
    # Uses a sed marker to handle indentation correctly
    sed -i '/^http {/a\    # Dragon Vault: WebSocket connection upgrade map (required for SignalR / live updates)\n    map $http_upgrade $connection_upgrade {\n        default upgrade;\n        ""      close;\n    }\n' "${NGINX_CONF}"
    echo "  [4/5] Added WebSocket map to ${NGINX_CONF}"
fi

# Step 5: Test nginx configuration
echo "  [5/5] Testing nginx configuration..."
if nginx -t 2>&1; then
    echo ""
    echo "==> nginx config test PASSED"
else
    echo ""
    echo "ERROR: nginx config test FAILED. Review errors above."
    echo "       Restoring backup not available — fix manually."
    exit 1
fi

# Step 6: Reload nginx
echo ""
echo "==> Reloading nginx..."
systemctl reload nginx

echo ""
echo "==> nginx reloaded successfully."
echo ""
echo "Next steps:"
echo "  1. Obtain TLS certificates (run setup-certbot.sh):"
echo "       sudo bash setup-certbot.sh"
echo ""
echo "  2. Verify the site:"
echo "       curl -I https://pwm.YOUR-SERVER-IP.nip.io"
echo ""
echo "  3. Check for SSL Labs rating A+:"
echo "       https://www.ssllabs.com/ssltest/analyze.html?d=pwm.YOUR-SERVER-IP.nip.io"

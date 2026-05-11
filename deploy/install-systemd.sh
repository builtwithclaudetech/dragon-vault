#!/usr/bin/env bash
# Dragon Vault — Install systemd unit (REQ-061-L)
#
# Run from the deploy/ directory:
#   cd /path/to/repo/deploy
#   sudo bash install-systemd.sh
#
# Prerequisites:
#   - www-data user exists (created by nginx installation)
#   - /var/opt/dragonvault/publish/PasswordManager.Web.dll exists
#   - dotnet runtime is installed

set -euo pipefail

UNIT_SOURCE="dragonvault.service"
UNIT_NAME="dragonvault.service"
UNIT_DEST="/etc/systemd/system/${UNIT_NAME}"

echo "==> Installing systemd unit: ${UNIT_NAME}"

if [ ! -f "${UNIT_SOURCE}" ]; then
    echo "ERROR: ${UNIT_SOURCE} not found in current directory."
    echo "       Run this script from the deploy/ directory."
    exit 1
fi

cp "${UNIT_SOURCE}" "${UNIT_DEST}"
chmod 644 "${UNIT_DEST}"

systemctl daemon-reload

echo ""
echo "==> Unit installed at ${UNIT_DEST}"
echo ""
echo "Next steps:"
echo "  1. Ensure publish output is in place:"
echo "       sudo mkdir -p /var/opt/dragonvault/publish"
echo "       sudo cp -r publish/* /var/opt/dragonvault/publish/"
echo "       sudo chown -R www-data:www-data /var/opt/dragonvault"
echo ""
echo "  2. Enable and start the service:"
echo "       sudo systemctl enable --now dragonvault"
echo ""
echo "  3. Check status:"
echo "       sudo systemctl status dragonvault"
echo ""
echo "  4. View logs:"
echo "       sudo journalctl -u dragonvault -f"
echo ""
echo "  IMPORTANT: Before going live, fix the DataProtection keys path in"
echo "  Program.cs — see the comment at the top of dragonvault.service."

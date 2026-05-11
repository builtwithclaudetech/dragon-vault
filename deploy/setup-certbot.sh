#!/usr/bin/env bash
# Dragon Vault — Provision Let's Encrypt TLS certificates (REQ-062-L)
#
# Run from the deploy/ directory:
#   cd /path/to/repo/deploy
#   sudo bash setup-certbot.sh
#
# Prerequisites:
#   - nginx is installed and the dragonvault site config is in place
#     (run install-nginx.sh first)
#   - DNS for pwm.YOUR-SERVER-IP.nip.io resolves to this server's public IP
#     (nip.io handles wildcard DNS for the IP in the hostname)
#   - Port 80 is reachable from the internet (certbot validates via HTTP-01 challenge)
#
# What this script does:
#   1. Installs certbot via snap (recommended) or apt fallback
#   2. Runs certbot with the nginx plugin for pwm.YOUR-SERVER-IP.nip.io
#   3. Verifies the auto-renewal mechanism is active
#   4. Runs a dry-run renewal to confirm everything works

set -euo pipefail

DOMAIN="pwm.YOUR-SERVER-IP.nip.io"
EMAIL="admin@${DOMAIN}"   # Update this to a real email for expiration notices

echo "==> Dragon Vault — Let's Encrypt certificate setup for ${DOMAIN}"
echo ""

# ── Step 1: Install certbot ──────────────────────────────────────────────────
echo "==> [1/4] Checking for certbot..."

if command -v certbot &>/dev/null; then
    echo "  certbot already installed at $(which certbot)"
else
    echo "  certbot not found. Attempting installation..."

    # Prefer snap (official recommendation for Ubuntu)
    if command -v snap &>/dev/null; then
        echo "  Installing via snap..."
        snap install certbot --classic
    elif command -v apt-get &>/dev/null; then
        echo "  Installing via apt..."
        apt-get update -qq
        apt-get install -y certbot python3-certbot-nginx
    else
        echo "ERROR: No supported package manager (snap or apt) found."
        echo "       Install certbot manually: https://certbot.eff.org/"
        exit 1
    fi
fi

echo ""

# ── Step 2: Obtain certificate ───────────────────────────────────────────────
echo "==> [2/4] Obtaining certificate for ${DOMAIN}..."
echo "  (This requires port 80 to be reachable from the internet.)"
echo ""

certbot --nginx \
    --domain "${DOMAIN}" \
    --email "${EMAIL}" \
    --agree-tos \
    --non-interactive \
    --redirect \
    --keep-until-expiring

echo ""

# ── Step 3: Verify auto-renewal ──────────────────────────────────────────────
echo "==> [3/4] Verifying auto-renewal mechanism..."

# Check for snap-based certbot (Ubuntu standard)
if systemctl list-timers 2>/dev/null | grep -q certbot; then
    echo "  Systemd timer found:"
    systemctl list-timers --no-pager | grep certbot || true
    echo ""
    echo "  Timer details:"
    systemctl cat certbot.timer 2>/dev/null || systemctl cat snap.certbot.renew.timer 2>/dev/null || echo "  (check via: systemctl list-timers | grep certbot)"

# Check for snap service
elif systemctl list-units 2>/dev/null | grep -q "certbot.*timer"; then
    echo "  Snap certbot timer found:"
    systemctl list-timers --no-pager | grep certbot || true

else
    echo "  WARNING: No certbot systemd timer found."
    echo "  Check renewal status manually:"
    echo "    systemctl list-timers | grep certbot"
    echo "    certbot renew --dry-run"
    echo ""
    echo "  If missing, add a cron job:"
    echo "    0 3 * * * /usr/bin/certbot renew --quiet --no-self-upgrade"
    echo "    (installed via: crontab -e)"
fi

echo ""

# ── Step 4: Dry-run renewal ──────────────────────────────────────────────────
echo "==> [4/4] Running renewal dry-run..."
certbot renew --dry-run

echo ""
echo "==> Certificate setup complete!"
echo ""
echo "Certificate files:"
echo "  Fullchain: /etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
echo "  Privkey:   /etc/letsencrypt/live/${DOMAIN}/privkey.pem"
echo ""
echo "To manually test renewal:"
echo "  sudo certbot renew --dry-run"
echo ""
echo "To check certificate expiry:"
echo "  sudo openssl x509 -in /etc/letsencrypt/live/${DOMAIN}/fullchain.pem -noout -enddate"
echo "  sudo bash check-cert-expiry.sh"
echo ""
echo "For SSL Labs SSL test:"
echo "  https://www.ssllabs.com/ssltest/analyze.html?d=${DOMAIN}"
echo ""
echo "For simple SSL monitoring (recommended):"
echo "  UptimeRobot → Add SSL monitor → ${DOMAIN} → check every 5 min"
echo "  or: https://letsmonitor.io (free SSL monitoring)"

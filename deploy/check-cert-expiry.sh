#!/usr/bin/env bash
# Dragon Vault — Certificate expiry monitor
#
# Checks the Let's Encrypt certificate expiry date for
# pwm.YOUR-SERVER-IP.nip.io and warns if < 14 days remain.
#
# Usage:
#   sudo bash check-cert-expiry.sh
#   echo $?  # 0 = OK, 1 = expiring, 2 = error
#
# Can be run from cron:
#   0 9 * * * /var/opt/dragonvault/check-cert-expiry.sh
#
# Simpler alternative:
#   UptimeRobot → Add SSL Monitor → pwm.YOUR-SERVER-IP.nip.io → check every 5 min
#   (no cron needed, no script to maintain, free tier covers one site)

set -euo pipefail

DOMAIN="pwm.YOUR-SERVER-IP.nip.io"
WARN_DAYS=14
CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"

# ── Check cert file exists ───────────────────────────────────────────────────
if [ ! -f "${CERT_PATH}" ]; then
    echo "ERROR: Certificate not found at ${CERT_PATH}"
    echo "       Has certbot been run yet? (sudo bash setup-certbot.sh)"
    exit 2
fi

# ── Get expiry date ──────────────────────────────────────────────────────────
EXPIRY_DATE=$(openssl x509 -in "${CERT_PATH}" -noout -enddate 2>/dev/null | cut -d= -f2)
if [ -z "${EXPIRY_DATE}" ]; then
    echo "ERROR: Could not read certificate expiry date."
    exit 2
fi

EXPIRY_EPOCH=$(date -d "${EXPIRY_DATE}" +%s 2>/dev/null)
CURRENT_EPOCH=$(date +%s)
SECONDS_REMAINING=$(( EXPIRY_EPOCH - CURRENT_EPOCH ))
DAYS_REMAINING=$(( SECONDS_REMAINING / 86400 ))

EXPIRY_HUMAN=$(date -d "@${EXPIRY_EPOCH}" '+%Y-%m-%d %H:%M:%S %Z')

echo "Domain:        ${DOMAIN}"
echo "Expires:       ${EXPIRY_HUMAN}"
echo "Days left:     ${DAYS_REMAINING}"

# ── Warn if expiring soon ────────────────────────────────────────────────────
if [ ${DAYS_REMAINING} -lt 0 ]; then
    echo ""
    echo "CRITICAL: Certificate has ALREADY EXPIRED!"
    echo "  Renew immediately: sudo certbot renew --force-renewal"
    exit 1

elif [ ${DAYS_REMAINING} -lt ${WARN_DAYS} ]; then
    echo ""
    echo "WARNING: Certificate expires in less than ${WARN_DAYS} days!"
    echo "  Auto-renewal should handle this automatically."
    echo "  Check renewal timer: systemctl list-timers | grep certbot"
    echo ""
    echo "  To force renewal: sudo certbot renew"
    echo "  To check status:  sudo certbot certificates"
    exit 1

else
    echo ""
    echo "OK: ${DAYS_REMAINING} days until expiry."
    exit 0
fi

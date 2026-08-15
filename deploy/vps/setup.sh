#!/usr/bin/env bash
#
# websec-auditor VPS setup (Ubuntu/Debian)
# Usage (as root):  bash setup.sh websec-audit.site you@example.com
#
set -euo pipefail

DOMAIN="${1:-websec-audit.site}"
EMAIL="${2:-admin@$DOMAIN}"
APP_DIR=/opt/websec-auditor
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_USER=www-data

echo "==> [1/8] Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

echo "==> [2/8] Installing python3, nginx, certbot, ufw..."
apt-get install -y python3 nginx certbot python3-certbot-nginx ufw

echo "==> [3/8] Installing app to $APP_DIR..."
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR"/websec_auditor "$APP_DIR"/
cp -r "$SRC_DIR"/data "$APP_DIR"/
cp "$SRC_DIR"/websec_cli.py "$SRC_DIR"/requirements.txt "$APP_DIR"/
chown -R "$APP_USER":"$APP_USER" "$APP_DIR"

echo "==> [4/8] Installing systemd service..."
cp "$SRC_DIR"/websec-auditor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable websec-auditor
systemctl restart websec-auditor
sleep 2
if systemctl is-active --quiet websec-auditor; then
  echo "  -> service RUNNING"
else
  echo "  -> ERROR: service failed; check 'journalctl -u websec-auditor -e'" >&2
  systemctl --no-pager status websec-auditor || true
  exit 1
fi

echo "==> [5/8] Configuring nginx..."
cp "$SRC_DIR"/nginx-websec-auditor.conf /etc/nginx/sites-available/websec-auditor
ln -sf /etc/nginx/sites-available/websec-auditor /etc/nginx/sites-enabled/websec-auditor
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl reload nginx

echo "==> [6/8] Configuring firewall (allow 22, 80, 443)..."
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

echo "==> [7/8] Issuing free TLS certificate (Let's Encrypt)..."
certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" \
  --non-interactive --agree-tos -m "$EMAIL" --redirect || {
    echo "  -> certbot failed (DNS may not point here yet). HTTP-only still works." >&2
  }
systemctl reload nginx

echo "==> [8/8] Verify:"
echo "  - service:  systemctl status websec-auditor"
echo "  - app:      curl -s http://127.0.0.1:8000/ | head -c 120"
echo "  - public:   curl -s http://$DOMAIN/ | head -c 120"
echo
echo "DONE. App is live at:  https://$DOMAIN"

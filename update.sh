#!/bin/bash
set -e

REPO_DIR="/opt/wazuh-dashboard"
INTEGRATION_SRC="$REPO_DIR/wazuh_to_db.py"
INTEGRATION_DST="/var/ossec/integrations/wazuh_to_db"

echo "[*] Git'ten güncelleme çekiliyor..."
cd "$REPO_DIR"
git pull

echo "[*] Integration script güncelleniyor..."
cp "$INTEGRATION_SRC" "$INTEGRATION_DST"
chmod 750 "$INTEGRATION_DST"
chown root:wazuh "$INTEGRATION_DST"

echo "[*] Dashboard servisi yeniden başlatılıyor..."
systemctl restart wazuh-dashboard

echo "[*] Wazuh manager yeniden başlatılıyor..."
systemctl restart wazuh-manager

echo ""
echo "[OK] Güncelleme tamamlandı."
systemctl status wazuh-dashboard --no-pager -l

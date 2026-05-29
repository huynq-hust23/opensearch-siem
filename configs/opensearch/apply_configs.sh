#!/usr/bin/env bash
# Apply tất cả OpenSearch configs sau khi rebuild cluster
# Usage: bash configs/opensearch/apply_configs.sh

set -e

# Load .env
ENV_FILE="$(dirname "$0")/../../.env"
if [ -f "$ENV_FILE" ]; then
    export $(grep -v '^#' "$ENV_FILE" | grep '=' | xargs)
fi

OS="${OPENSEARCH_URL:-https://localhost:9200}"
USER="${OPENSEARCH_USER:-admin}"
PASS="${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-admin}"
AUTH="-u $USER:$PASS"

echo "========================================"
echo " OpenSearch Config Apply"
echo " Host: $OS"
echo "========================================"

# Chờ OpenSearch sẵn sàng
echo -n "Waiting for OpenSearch..."
until curl -sku $USER:$PASS "$OS/_cluster/health" 2>/dev/null | grep -q '"status"'; do
    echo -n "."
    sleep 3
done
echo " Ready!"

# 1. Index Template
echo
echo "[1/3] Applying index template siem-winlogbeat-template..."
curl -sk $AUTH -X PUT "$OS/_index_template/siem-winlogbeat-template" \
    -H 'Content-Type: application/json' \
    -d @"$(dirname "$0")/templates/siem-winlogbeat-template.json" \
    | python3 -c "import sys,json; r=json.load(sys.stdin); print('  OK' if r.get('acknowledged') else f'  FAIL: {r}')"

# 2. TheHive webhook
echo
echo "[2/3] Setting up TheHive webhook..."
# Kiểm tra đã tồn tại chưa
EXISTING=$(curl -sk $AUTH "$OS/_plugins/_notifications/configs?config_type=webhook" \
    | python3 -c "import sys,json; cfgs=json.load(sys.stdin).get('config_list',[]); print(next((c['config_id'] for c in cfgs if c.get('config',{}).get('name')=='TheHive-Webhook'),''))")

if [ -n "$EXISTING" ]; then
    echo "  TheHive webhook already exists: $EXISTING"
else
    WEBHOOK_PAYLOAD=$(python3 -c "
import json, os
with open('$(dirname "$0")/sa/thehive_webhook.json') as f:
    cfgs = json.load(f)
cfg = cfgs[0]['config']
# Inject real API key from env
cfg['webhook']['header_params']['Authorization'] = 'Bearer ' + os.environ.get('THEHIVE_API_KEY','')
print(json.dumps({'config': cfg}))
")
    curl -sk $AUTH -X POST "$OS/_plugins/_notifications/configs" \
        -H 'Content-Type: application/json' \
        -d "$WEBHOOK_PAYLOAD" \
        | python3 -c "import sys,json; r=json.load(sys.stdin); print(f'  Created: {r.get(\"config_id\",r)}')"
fi

# 3. Deploy Sigma rules + Detector
echo
echo "[3/3] Deploying Sigma rules and Detector..."
SCRIPT="$(dirname "$0")/../../test.py"
if [ -f "$SCRIPT" ]; then
    python3 "$SCRIPT"
else
    echo "  WARNING: test.py not found at $SCRIPT"
    echo "  Run manually: python3 test.py"
fi

echo
echo "========================================"
echo " Done! Check SA -> Detectors in UI."
echo "========================================"

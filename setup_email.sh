#!/bin/bash

set -euo pipefail

# OpenSearch 2.x: Alerting email actions are backed by the Notifications plugin.
# This script creates Notifications configs:
# - smtp_account (MailHog)
# - email_group (recipients)
# - email (channel) -> use its config_id as Alerting action destination_id

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -f "$SCRIPT_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/.env"
  set +a
fi

OPENSEARCH_URL="${OPENSEARCH_URL:-https://localhost:9200}"
OPENSEARCH_USER="${OPENSEARCH_USER:-admin}"
OPENSEARCH_PASSWORD="${OPENSEARCH_PASSWORD:-${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-}}"

if [[ -z "$OPENSEARCH_PASSWORD" ]]; then
  echo "[ERROR] Missing OPENSEARCH_PASSWORD or OPENSEARCH_INITIAL_ADMIN_PASSWORD (see .env)"
  exit 1
fi

AUTH=(-k -u "${OPENSEARCH_USER}:${OPENSEARCH_PASSWORD}")

get_config_id_by_name_type() {
  local want_name="$1"
  local want_type="$2"
  curl -s "${AUTH[@]}" "$OPENSEARCH_URL/_plugins/_notifications/configs" | \
  python3 -c 'import json,sys
want_name=sys.argv[1]
want_type=sys.argv[2]
d=json.load(sys.stdin)
for item in d.get("config_list",[]):
  cfg=item.get("config",{})
  if cfg.get("name")==want_name and cfg.get("config_type")==want_type:
    print(item.get("config_id",""))
    break
' "$want_name" "$want_type"
}

create_config() {
  curl -s "${AUTH[@]}" -XPOST "$OPENSEARCH_URL/_plugins/_notifications/configs" \
    -H 'Content-Type: application/json' \
    -d "$1" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("config_id",""))'
}

echo "[*] Creating/ensuring Notifications smtp_account (MailHog)..."
SMTP_ID="$(get_config_id_by_name_type "MailHog SMTP" "smtp_account")"
if [[ -z "$SMTP_ID" ]]; then
  SMTP_ID="$(create_config '{"config":{"name":"MailHog SMTP","config_type":"smtp_account","is_enabled":true,"smtp_account":{"host":"mailhog","port":1025,"method":"none","from_address":"alert@siem.lab"}}}')"
fi
echo "SMTP config_id: $SMTP_ID"

if [[ -z "$SMTP_ID" ]]; then
  echo "[ERROR] Failed to create smtp_account"
  exit 1
fi

echo "[*] Creating/ensuring Notifications email_group (recipients)..."
GROUP_ID="$(get_config_id_by_name_type "Admin Team" "email_group")"
if [[ -z "$GROUP_ID" ]]; then
  GROUP_ID="$(create_config '{"config":{"name":"Admin Team","config_type":"email_group","is_enabled":true,"email_group":{"recipient_list":[{"recipient":"admin@siem.lab"}]}}}')"
fi
echo "Email group config_id: $GROUP_ID"

echo "[*] Creating/ensuring Notifications email channel..."
EMAIL_ID="$(get_config_id_by_name_type "SIEM Email Channel" "email")"
if [[ -z "$EMAIL_ID" ]]; then
  EMAIL_ID="$(create_config '{"config":{"name":"SIEM Email Channel","config_type":"email","is_enabled":true,"email":{"email_account_id":"'"$SMTP_ID"'","recipient_list":[{"recipient":"admin@siem.lab"}]}}}')"
fi

if [[ -z "$EMAIL_ID" ]]; then
  echo "[ERROR] Failed to create email channel"
  exit 1
fi

echo ""
echo "[SUCCESS] Email destination ready for Alerting."
echo "Use this as destination_id in Alerting monitor actions: $EMAIL_ID"

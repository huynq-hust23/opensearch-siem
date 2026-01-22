#!/bin/bash

set -euo pipefail

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

# destination_id for Alerting email actions is the Notifications 'email' config_id.
DEST_ID=$(curl -s "${AUTH[@]}" "$OPENSEARCH_URL/_plugins/_notifications/configs" | \
  python3 -c 'import json,sys
d=json.load(sys.stdin)
for item in d.get("config_list",[]):
    cfg=item.get("config",{})
    if cfg.get("config_type")=="email" and cfg.get("name")=="SIEM Email Channel":
        print(item.get("config_id",""))
        break
'
)

echo "Found Notifications email destination_id: $DEST_ID"

if [[ -z "$DEST_ID" ]]; then
  echo "[ERROR] No Notifications email config found. Run ./setup_email.sh first."
  exit 1
fi

create_monitor() {
  NAME="$1"
  QUERY="$2"
  SEVERITY="$3"
  
  curl -s "${AUTH[@]}" -XPOST "$OPENSEARCH_URL/_plugins/_alerting/monitors" -H 'Content-Type: application/json' -d '{
    "type": "monitor",
    "name": "'"$NAME"'",
    "monitor_type": "query_level_monitor",
    "enabled": true,
    "schedule": { "period": { "interval": 1, "unit": "MINUTES" } },
    "inputs": [{
      "search": {
        "indices": ["siem-suricata-*"],
        "query": {
          "size": 0,
          "query": {
            "bool": {
              "filter": [
                { "range": { "@timestamp": { "from": "now-1m", "to": "now" } } },
                { "term": { "suricata.eve.event_type": "alert" } },
                '"$QUERY"'
              ]
            }
          }
        }
      }
    }],
    "triggers": [{
      "name": "General Trigger",
      "severity": "'"$SEVERITY"'",
      "condition": {
        "script": { "source": "ctx.results[0].hits.total.value > 0", "lang": "painless" }
      },
      "actions": [
        {
          "name": "Send Email",
          "destination_id": "'"$DEST_ID"'",
          "message_template": {
            "source": "Alert: {{ctx.monitor.name}}\nSeverity: '"$SEVERITY"'\nTotal Hits: {{ctx.results[0].hits.total.value}}",
            "lang": "mustache"
          }
        }
      ]
    }]
  }'
  echo " -> Created monitor: $NAME"
}

# 1. Critical Alert
create_monitor "[AUTO] Critical Security Alert" '{ "term": { "suricata.eve.alert.severity": 1 } }' "1"

# 0. Any Suricata alert (for end-to-end email verification)
create_monitor "[AUTO] Any Suricata Alert" '{ "exists": { "field": "suricata.eve.alert.signature" } }' "3"

# 2. Web Attack
create_monitor "[AUTO] Web Application Attack" '{ "match_phrase": { "suricata.eve.alert.category": "Web Application Attack" } }' "2"

# 3. Network Scan
create_monitor "[AUTO] Network Scanning" '{ "match_phrase": { "suricata.eve.alert.signature": "SCAN" } }' "3"

# 4. Anomaly (Threat Intel)
create_monitor "[AUTO] Threat Intel Hit" '{ "term": { "tags": "threat_matched" } }' "1"


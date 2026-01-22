#!/bin/bash

set -euo pipefail

# Safe validation script (NO real attacks):
# Sends synthetic Suricata-like alert events into Logstash TCP input (port 5000)
# to verify the full path: Logstash -> OpenSearch -> Alerting monitor -> MailHog email.

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
LOGSTASH_HOST="${LOGSTASH_HOST:-127.0.0.1}"
LOGSTASH_PORT="${LOGSTASH_PORT:-5000}"
MAILHOG_API="${MAILHOG_API:-http://127.0.0.1:8025}"

if [[ -z "$OPENSEARCH_PASSWORD" ]]; then
  echo "[ERROR] Missing OPENSEARCH_PASSWORD or OPENSEARCH_INITIAL_ADMIN_PASSWORD (see .env)"
  exit 1
fi

AUTH=(-k -u "${OPENSEARCH_USER}:${OPENSEARCH_PASSWORD}")

require_tcp() {
  if ! (echo >"/dev/tcp/${LOGSTASH_HOST}/${LOGSTASH_PORT}") >/dev/null 2>&1; then
    echo "[ERROR] Can't connect to Logstash TCP at ${LOGSTASH_HOST}:${LOGSTASH_PORT}"
    echo "        Ensure docker compose is up and Logstash exposes 5000/tcp."
    exit 1
  fi
}

mailhog_count() {
  curl -s "${MAILHOG_API}/api/v2/messages" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count",0))'
}

mailhog_clear() {
  # MailHog supports DELETE /api/v1/messages
  curl -s -XDELETE "${MAILHOG_API}/api/v1/messages" >/dev/null 2>&1 || true
}

get_destination_id() {
  curl -s "${AUTH[@]}" "$OPENSEARCH_URL/_plugins/_notifications/configs" | \
    python3 -c 'import json,sys
d=json.load(sys.stdin)
for item in d.get("config_list",[]):
    cfg=item.get("config",{})
    if cfg.get("config_type")=="email" and cfg.get("name")=="SIEM Email Channel":
        print(item.get("config_id",""))
        break
'
}

send_event() {
  local uc="$1"
  local signature="$2"
  local category="$3"
  local severity="$4"
  local tags_json="$5"

  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Logstash TCP input has codec json, newline-delimited.
  # Use fields consistent with Filebeat Suricata module + our monitors.
  local payload
  payload=$(cat <<JSON
{"@timestamp":"$ts","event":{"module":"suricata"},"tags":$tags_json,"suricata":{"eve":{"event_type":"alert","alert":{"signature":"$signature","category":"$category","severity":$severity}}},"message":"$uc synthetic alert"}
JSON
)

  printf '%s\n' "$payload" >"/dev/tcp/${LOGSTASH_HOST}/${LOGSTASH_PORT}"
}

echo "[*] Preflight: OpenSearch auth + required configs"
curl -s "${AUTH[@]}" "$OPENSEARCH_URL" >/dev/null

DEST_ID="$(get_destination_id)"
if [[ -z "$DEST_ID" ]]; then
  echo "[*] No Notifications email destination found. Running setup_email.sh..."
  bash "$SCRIPT_DIR/setup_email.sh" >/dev/null
  DEST_ID="$(get_destination_id)"
fi

if [[ -z "$DEST_ID" ]]; then
  echo "[ERROR] Still no Notifications email destination_id."
  exit 1
fi

echo "[*] Ensuring monitors exist (setup_monitors.sh)..."
bash "$SCRIPT_DIR/setup_monitors.sh" >/dev/null

echo "[*] Checking Logstash TCP connectivity..."
require_tcp

echo "[*] Clearing MailHog inbox..."
mailhog_clear
BEFORE=$(mailhog_count)
echo "MailHog count (before): $BEFORE"

echo "[*] Sending synthetic events for each use case (safe simulation)"

# Map each use case to a Suricata-like alert that should match at least one monitor.
send_event "UC01 SQLi" "ATTACK SQL Injection Attempt" "Web Application Attack" 1 '["security_alert"]'
send_event "UC02 XSS" "ATTACK XSS script tag" "Web Application Attack" 1 '["security_alert"]'
send_event "UC03 Path Traversal" "ATTACK Directory Traversal" "Web Application Attack" 1 '["security_alert"]'
send_event "UC04 Webshell Upload" "ATTACK Webshell Upload" "Web Application Attack" 1 '["security_alert"]'
send_event "UC05 Web Scanner" "SCAN Nikto Web Scanner" "Web Application Attack" 2 '["security_alert"]'
send_event "UC06 Port Scan" "SCAN Port Scan" "Attempted Information Leak" 3 '["scan"]'
send_event "UC07 Host Sweep" "SCAN Host Sweep" "Attempted Information Leak" 3 '["scan"]'
send_event "UC08 SSH Brute" "ATTACK SSH Brute Force" "Attempted Administrator Privilege Gain" 1 '["security_alert"]'
send_event "UC09 DoS Flood" "ATTACK DOS Flood" "Denial of Service" 1 '["security_alert"]'
send_event "UC10 C2 Beacon" "MALWARE C2 Beacon" "A Network Trojan was Detected" 1 '["security_alert"]'
send_event "UC11 DNS Tunnel" "ATTACK DNS TUNNEL" "A Network Trojan was Detected" 1 '["security_alert"]'
send_event "UC12 Threat Intel IP" "TI Match" "Potentially Bad Traffic" 1 '["threat_matched"]'
send_event "UC13 Geofencing" "GEOFENCE VIOLATION" "Policy Violation" 2 '["anomaly"]'
send_event "UC14 Impossible Travel" "IMPOSSIBLE TRAVEL" "Anomaly Detection" 2 '["anomaly"]'
send_event "UC15 Data Exfil" "ATTACK Data Exfil" "Data Loss Prevention" 1 '["security_alert"]'

echo "[*] Executing monitors immediately (no scheduler wait)"

sleep 2

MON_IDS=$(curl -s "${AUTH[@]}" -XPOST "$OPENSEARCH_URL/_plugins/_alerting/monitors/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":200,"query":{"match_all":{}}}' | \
  python3 -c 'import json,sys
d=json.load(sys.stdin)
want={"[AUTO] Critical Security Alert","[AUTO] Web Application Attack","[AUTO] Network Scanning","[AUTO] Threat Intel Hit"}
ids=[]
for h in d.get("hits",{}).get("hits",[]):
    src=h.get("_source",{})
    name=src.get("name") or src.get("monitor",{}).get("name")
    if name in want:
        ids.append(h.get("_id",""))
print(" ".join([i for i in ids if i]))
')

if [[ -z "$MON_IDS" ]]; then
  echo "[WARN] Could not find [AUTO] monitors to execute."
else
  for id in $MON_IDS; do
    curl -s "${AUTH[@]}" -XPOST "$OPENSEARCH_URL/_plugins/_alerting/monitors/$id/_execute" \
      -H 'Content-Type: application/json' -d '{}' >/dev/null || true
  done
fi

sleep 2

AFTER=$(mailhog_count)
echo "MailHog count (after): $AFTER"

if [[ "$AFTER" -le "$BEFORE" ]]; then
  echo "[WARN] No new emails detected yet. You can re-run with longer wait (e.g. sleep 120)."
  exit 2
fi

echo "[SUCCESS] Emails generated. Open MailHog UI: http://localhost:8025"

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

os_count_synthetic_alerts_last_2m() {
  curl -s "${AUTH[@]}" -XPOST "$OPENSEARCH_URL/siem-suricata-*/_count" \
    -H 'Content-Type: application/json' \
    -d '{
      "query": {
        "bool": {
          "filter": [
            {"range": {"@timestamp": {"gte": "now-10m", "lte": "now"}}},
            {"term": {"suricata.eve.event_type": "alert"}},
            {"match_phrase": {"message": "synthetic alert"}}
          ]
        }
      }
    }' | python3 -c 'import json,sys
try:
  print(json.load(sys.stdin).get("count",0))
except Exception:
  print(0)
'
}

wait_for_ingest() {
  local max_wait_s="${1:-30}"
  local waited=0
  while [[ $waited -lt $max_wait_s ]]; do
    local c
    c="$(os_count_synthetic_alerts_last_2m)"
    if [[ "$c" -gt 0 ]]; then
      return 0
    fi
    sleep 1
    waited=$((waited+1))
  done
  return 1
}

mailhog_count() {
  curl -s "${MAILHOG_API}/api/v2/messages" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count",0))'
}

mailhog_clear() {
  # MailHog supports DELETE /api/v1/messages
  curl -s -XDELETE "${MAILHOG_API}/api/v1/messages" >/dev/null 2>&1 || true
}

mailhog_dump_json() {
  curl -s "${MAILHOG_API}/api/v2/messages"
}

mailhog_has_text() {
  local needle="$1"
  mailhog_dump_json | python3 -c 'import json,sys
needle=sys.argv[1]
d=json.load(sys.stdin)
items=d.get("items",[]) or []
def get_str(x):
  if x is None:
    return ""
  if isinstance(x,str):
    return x
  try:
    return json.dumps(x, ensure_ascii=False)
  except Exception:
    return str(x)
hay=[]
for it in items:
  content=(it.get("Content") or {})
  hay.append(get_str(content.get("Body")))
  hay.append(get_str(content.get("Headers")))
text="\n".join(hay)
sys.exit(0 if needle in text else 1)
' "$needle"
}

wait_for_email_text() {
  local needle="$1"
  local max_wait_s="${2:-120}"
  local waited=0
  while [[ $waited -lt $max_wait_s ]]; do
    if mailhog_has_text "$needle"; then
      return 0
    fi
    sleep 1
    waited=$((waited+1))
  done
  return 1
}

wait_for_email() {
  local before="$1"
  local max_wait_s="${2:-30}"
  local waited=0
  while [[ $waited -lt $max_wait_s ]]; do
    local now
    now="$(mailhog_count)"
    if [[ "$now" -gt "$before" ]]; then
      echo "$now"
      return 0
    fi
    sleep 1
    waited=$((waited+1))
  done
  echo "$(mailhog_count)"
  return 1
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
  local source_ip="${6:-172.30.10.10}"
  local destination_ip="${7:-172.30.20.10}"
  local destination_port="${8:-80}"

  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Logstash TCP input has codec json, newline-delimited.
  # Use fields consistent with Filebeat Suricata module + our monitors.
  local payload
  payload=$(cat <<JSON
{"@timestamp":"$ts","event":{"module":"suricata"},"tags":$tags_json,"source":{"ip":"$source_ip"},"destination":{"ip":"$destination_ip","port":$destination_port},"suricata":{"eve":{"event_type":"alert","alert":{"signature":"$signature","category":"$category","severity":$severity}}},"message":"$uc synthetic alert"}
JSON
)

  printf '%s\n' "$payload" >"/dev/tcp/${LOGSTASH_HOST}/${LOGSTASH_PORT}"
}

echo "[*] Preflight: OpenSearch auth + required configs"
curl -s "${AUTH[@]}" "$OPENSEARCH_URL" >/dev/null

if [[ -x "$SCRIPT_DIR/setup_index_templates.sh" ]]; then
  echo "[*] Ensuring OpenSearch index templates..."
  bash "$SCRIPT_DIR/setup_index_templates.sh" >/dev/null
fi

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
send_event "UC05 Web Scanner" "SCAN Nmap Scripting Engine User-Agent" "Web Application Attack" 2 '["security_alert"]'
echo "[*] UC06 Port Scan: generating distinct ports"
for p in $(seq 1001 1020); do
  send_event "UC06 Port Scan" "SCAN Port Scan" "Attempted Information Leak" 3 '["scan"]' "172.30.10.10" "172.30.20.10" "$p"
done
send_event "UC07 Host Sweep" "SCAN Host Sweep" "Attempted Information Leak" 3 '["scan"]'
echo "[*] UC08 SSH Brute: generating many hits to port 22"
for i in $(seq 1 25); do
  send_event "UC08 SSH Brute" "ATTACK SSH Brute Force" "Attempted Administrator Privilege Gain" 1 '["security_alert"]' "172.30.10.10" "172.30.20.10" 22
done

echo "[*] UC09 DoS/DDoS: generating burst"
for i in $(seq 1 60); do
  send_event "UC09 DoS Flood" "ATTACK DOS Flood" "Denial of Service" 1 '["security_alert"]' "172.30.10.10" "172.30.20.10" 80
done
send_event "UC10 C2 Beacon" "MALWARE C2 Beacon" "A Network Trojan was Detected" 1 '["security_alert"]'
send_event "UC11 DNS Tunnel" "ATTACK DNS TUNNEL" "A Network Trojan was Detected" 1 '["security_alert"]'
send_event "UC13 Geofencing" "GEOFENCE VIOLATION" "Policy Violation" 2 '["anomaly"]'
send_event "UC14 Impossible Travel" "IMPOSSIBLE TRAVEL" "Anomaly Detection" 2 '["anomaly"]'
send_event "UC15 Data Exfil" "ATTACK Data Exfil" "Data Loss Prevention" 1 '["security_alert"]'

echo "[*] Executing monitors immediately (no scheduler wait)"

echo "[*] Waiting for events to be indexed in OpenSearch..."
if ! wait_for_ingest 45; then
  echo "[WARN] Synthetic events not visible in OpenSearch yet; executing monitors anyway."
fi

MON_IDS=$(curl -s "${AUTH[@]}" -XPOST "$OPENSEARCH_URL/_plugins/_alerting/monitors/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":200,"query":{"match_all":{}}}' | \
  python3 -c 'import json,sys
d=json.load(sys.stdin)
want={"[AUTO] UC01 SQLi (threshold)","[AUTO] UC02 XSS (threshold)","[AUTO] UC03 Path Traversal (threshold)","[AUTO] UC04 Webshell Upload (threshold)","[AUTO] UC05 Web Scanner (threshold)","[AUTO] UC06 Port Scan (threshold)","[AUTO] UC08 SSH Brute (threshold)","[AUTO] UC09 DoS/DDoS (threshold)"}
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

echo "[*] Waiting for MailHog to receive emails..."
AFTER="$(wait_for_email "$BEFORE" 120)"
echo "MailHog count (after): $AFTER"

if [[ "$AFTER" -le "$BEFORE" ]]; then
  echo "[WARN] No new emails detected yet. You can re-run with longer wait (e.g. sleep 120)."
  exit 2
fi

echo "[*] Asserting UC03/UC04 emails exist in MailHog..."
if ! wait_for_email_text "Alert: [AUTO] UC03 Path Traversal (threshold)" 120; then
  echo "[ERROR] Missing expected email for UC03 monitor: [AUTO] UC03 Path Traversal (threshold)"
  exit 3
fi
if ! wait_for_email_text "Alert: [AUTO] UC04 Webshell Upload (threshold)" 120; then
  echo "[ERROR] Missing expected email for UC04 monitor: [AUTO] UC04 Webshell Upload (threshold)"
  exit 3
fi
echo "[OK] UC03/UC04 email assertions passed."

echo "[SUCCESS] Emails generated. Open MailHog UI: http://localhost:8025"

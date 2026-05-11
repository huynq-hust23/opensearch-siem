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

get_monitor_ids_by_exact_name() {
  local want_name="$1"
  curl -s "${AUTH[@]}" -XPOST "$OPENSEARCH_URL/_plugins/_alerting/monitors/_search" \
    -H 'Content-Type: application/json' \
    -d '{"size":1000,"query":{"match_all":{}}}' | \
    python3 -c 'import json,sys
want=sys.argv[1]
d=json.load(sys.stdin)
ids=[]
for h in d.get("hits",{}).get("hits",[]):
  src=h.get("_source",{})
  name=src.get("name") or src.get("monitor",{}).get("name")
  if name==want:
    ids.append(h.get("_id",""))
print(" ".join([i for i in ids if i]))
' "$want_name"
}

delete_monitors_by_exact_name() {
  local name="$1"
  local ids
  ids="$(get_monitor_ids_by_exact_name "$name")"
  if [[ -z "$ids" ]]; then
    return 0
  fi
  echo "[*] Removing existing monitors named: $name"
  local id
  for id in $ids; do
    curl -s "${AUTH[@]}" -XDELETE "$OPENSEARCH_URL/_plugins/_alerting/monitors/$id" >/dev/null || true
  done
}

# If you previously created a broader/noisier monitor set, remove deprecated monitors
# so you truly end up with fewer monitors/emails.
delete_monitors_by_exact_name "[AUTO] Any Suricata Alert"
delete_monitors_by_exact_name "[AUTO] Any Suricata Event"
delete_monitors_by_exact_name "[AUTO] Network Scanning"
delete_monitors_by_exact_name "[AUTO] UC06 Port Scan (threshold)"
delete_monitors_by_exact_name "[AUTO] UC08 SSH Brute (threshold)"
delete_monitors_by_exact_name "[AUTO] UC09 DoS/DDoS (threshold)"
delete_monitors_by_exact_name "[AUTO] UC01 SQLi (threshold)"
delete_monitors_by_exact_name "[AUTO] UC02 XSS (threshold)"
delete_monitors_by_exact_name "[AUTO] UC05 Web Scanner (threshold)"
delete_monitors_by_exact_name "[AUTO] UC03 Path Traversal (threshold)"
delete_monitors_by_exact_name "[AUTO] UC04 Webshell Upload (threshold)"

create_monitor() {
  NAME="$1"
  QUERY="$2"
  SEVERITY="$3"
  LOOKBACK_MINUTES="${4:-10}"
  SCHEDULE_MINUTES="${5:-5}"
  CONDITION_SOURCE="${6:-ctx.results[0].hits.total.value > 0}"
  CONDITION_DESC="${7:-}" 

  # Keep script idempotent: avoid duplicates and fix any older monitors created with
  # empty destination_id or mismatched query fields.
  delete_monitors_by_exact_name "$NAME"
  
  curl -s "${AUTH[@]}" -XPOST "$OPENSEARCH_URL/_plugins/_alerting/monitors" -H 'Content-Type: application/json' -d '{
    "type": "monitor",
    "name": "'"$NAME"'",
    "monitor_type": "query_level_monitor",
    "enabled": true,
    "schedule": { "period": { "interval": '"$SCHEDULE_MINUTES"', "unit": "MINUTES" } },
    "inputs": [{
      "search": {
        "indices": ["siem-suricata-*"],
        "query": {
          "size": 0,
          "query": {
            "bool": {
              "filter": [
                { "range": { "@timestamp": { "gte": "now-'"$LOOKBACK_MINUTES"'m", "lte": "now" } } },
                { "term": { "event.module": "suricata" } },
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
        "script": { "source": "'"$CONDITION_SOURCE"'", "lang": "painless" }
      },
      "actions": [
        {
          "name": "Send Email",
          "destination_id": "'"$DEST_ID"'",
          "message_template": {
            "source": "Alert: {{ctx.monitor.name}}\nSeverity: '"$SEVERITY"'\n'"$CONDITION_DESC"'\nTotal Hits: {{ctx.results[0].hits.total.value}}",
            "lang": "mustache"
          }
        }
      ]
    }]
  }'
  echo " -> Created monitor: $NAME"
}

# Business-logic mode: multiple monitors (threshold-based, volume)
SCHEDULE_MINUTES=1
LOOKBACK_MINUTES=2

# UC01: SQL Injection
# For SQLi, a single IDS alert is usually meaningful, so threshold is >= 1.
create_monitor \
  "[AUTO] UC01 SQLi (threshold)" \
  '{ "bool": { "filter": [
      { "term": { "suricata.eve.event_type": "alert" } },
      { "bool": { "should": [
        { "match_phrase": { "suricata.eve.alert.signature": "SQL Injection" } },
        { "match_phrase": { "suricata.eve.alert.signature": "SQLi" } }
      ], "minimum_should_match": 1 } }
  ] } }' \
  "2" "$LOOKBACK_MINUTES" "$SCHEDULE_MINUTES" \
  "ctx.results[0].hits.total.value >= 1" \
  "Condition: >=1 SQLi alert in window"

# UC02: Cross-Site Scripting (XSS)
create_monitor \
  "[AUTO] UC02 XSS (threshold)" \
  '{ "bool": { "filter": [
      { "term": { "suricata.eve.event_type": "alert" } },
      { "bool": { "should": [
        { "match_phrase": { "suricata.eve.alert.signature": "ATTACK XSS script tag" } },
        { "match_phrase": { "suricata.eve.alert.signature": "ATTACK XSS encoded" } },
        { "match_phrase": { "suricata.eve.alert.signature": "ATTACK XSS" } }
      ], "minimum_should_match": 1 } }
  ] } }' \
  "2" "$LOOKBACK_MINUTES" "$SCHEDULE_MINUTES" \
  "ctx.results[0].hits.total.value >= 1" \
  "Condition: >=1 XSS alert in window"

# UC05: Web Scanner (Nikto/Nmap UA)
create_monitor \
  "[AUTO] UC05 Web Scanner (threshold)" \
  '{ "bool": { "filter": [
      { "term": { "suricata.eve.event_type": "alert" } },
      { "bool": { "should": [
        { "match_phrase": { "suricata.eve.alert.signature": "SCAN Nikto Web Scanner" } },
        { "match_phrase": { "suricata.eve.alert.signature": "SCAN Nmap Scripting Engine User-Agent" } },
        { "match_phrase": { "suricata.eve.alert.signature": "Web Scanner" } },
        { "match_phrase": { "suricata.eve.alert.signature": "SCAN" } }
      ], "minimum_should_match": 1 } }
  ] } }' \
  "3" "$LOOKBACK_MINUTES" "$SCHEDULE_MINUTES" \
  "ctx.results[0].hits.total.value >= 1" \
  "Condition: >=1 web scanner alert in window"

# UC03: Path Traversal / File Inclusion
create_monitor \
  "[AUTO] UC03 Path Traversal (threshold)" \
  '{ "bool": { "filter": [
      { "term": { "suricata.eve.event_type": "alert" } },
      { "bool": { "should": [
        { "match_phrase": { "suricata.eve.alert.signature": "ATTACK Directory Traversal" } },
        { "match_phrase": { "suricata.eve.alert.signature": "Directory Traversal" } }
      ], "minimum_should_match": 1 } }
  ] } }' \
  "2" "$LOOKBACK_MINUTES" "$SCHEDULE_MINUTES" \
  "ctx.results[0].hits.total.value >= 1" \
  "Condition: >=1 traversal alert in window"

# UC04: Webshell Upload
create_monitor \
  "[AUTO] UC04 Webshell Upload (threshold)" \
  '{ "bool": { "filter": [
      { "term": { "suricata.eve.event_type": "alert" } },
      { "bool": { "should": [
        { "match_phrase": { "suricata.eve.alert.signature": "ATTACK Webshell Upload" } },
        { "match_phrase": { "suricata.eve.alert.signature": "Webshell Upload" } }
      ], "minimum_should_match": 1 } }
  ] } }' \
  "1" "$LOOKBACK_MINUTES" "$SCHEDULE_MINUTES" \
  "ctx.results[0].hits.total.value >= 1" \
  "Condition: >=1 webshell upload alert in window"

# UC06: Port Scan (volume)
create_monitor \
  "[AUTO] UC06 Port Scan (threshold)" \
  '{ "bool": { "filter": [
      { "term": { "suricata.eve.event_type": "alert" } },
      { "match_phrase": { "suricata.eve.alert.signature": "Port Scan" } }
  ] } }' \
  "3" "$LOOKBACK_MINUTES" "$SCHEDULE_MINUTES" \
  "ctx.results[0].hits.total.value >= 20" \
  "Condition: >=20 scan alerts in window"

# UC08: SSH Brute Force (volume)
create_monitor \
  "[AUTO] UC08 SSH Brute (threshold)" \
  '{ "bool": { "filter": [
      { "term": { "suricata.eve.event_type": "alert" } },
      { "match_phrase": { "suricata.eve.alert.signature": "SSH Brute" } }
  ] } }' \
  "2" "$LOOKBACK_MINUTES" "$SCHEDULE_MINUTES" \
  "ctx.results[0].hits.total.value >= 20" \
  "Condition: >=20 SSH brute alerts in window"

# UC09: DoS/DDoS (volume)
create_monitor \
  "[AUTO] UC09 DoS/DDoS (threshold)" \
  '{ "bool": { "filter": [
      { "term": { "suricata.eve.event_type": "alert" } },
      { "bool": { "should": [
        { "match_phrase": { "suricata.eve.alert.category": "Denial of Service" } },
        { "match_phrase": { "suricata.eve.alert.signature": "DOS" } }
      ], "minimum_should_match": 1 } }
  ] } }' \
  "1" "$LOOKBACK_MINUTES" "$SCHEDULE_MINUTES" \
  "ctx.results[0].hits.total.value >= 50" \
  "Condition: >=50 DoS alerts in window"


#!/bin/bash

set -euo pipefail

# Ensures OpenSearch index templates needed by this lab exist.
# Currently: siem-suricata-* must accept ISO8601 @timestamp.

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

curl -s "${AUTH[@]}" -XPUT "$OPENSEARCH_URL/_index_template/siem-suricata-template" \
  -H 'Content-Type: application/json' \
  -d '{
    "index_patterns": ["siem-suricata-*"],
    "priority": 200,
    "template": {
      "mappings": {
        "properties": {
          "@timestamp": {
            "type": "date",
            "format": "strict_date_optional_time||epoch_millis"
          }
        }
      }
    }
  }' >/dev/null

echo "[SUCCESS] Index template ensured: siem-suricata-template"
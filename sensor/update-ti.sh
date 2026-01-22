#!/bin/bash
# Script cập nhật Threat Intelligence
# Chạy hàng ngày qua cron: 0 2 * * * /path/to/update-ti.sh

set -e

TI_DIR="/var/lib/threat-intel"
SENSOR_DIR="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$TI_DIR"

echo "[$(date)] Updating Threat Intelligence..."

# Download Spamhaus DROP
curl -s https://www.spamhaus.org/drop/drop.txt > "$TI_DIR/spamhaus_drop.txt"
curl -s https://www.spamhaus.org/drop/edrop.txt >> "$TI_DIR/spamhaus_drop.txt"

# Download blocklist.de
curl -s https://lists.blocklist.de/lists/all.txt > "$TI_DIR/blocklist_de.txt"

# Build YAML dictionary for Logstash translate filter
# Format: "<ip>: malicious"
awk 'NF { gsub(/\r/, ""); print $1 ": malicious" }' "$TI_DIR/blocklist_de.txt" > "$TI_DIR/blocklist_de.yml"

# Count IPs
SPAMHAUS_COUNT=$(grep -v "^;" "$TI_DIR/spamhaus_drop.txt" | grep -c "." || echo 0)
BLOCKLIST_COUNT=$(wc -l < "$TI_DIR/blocklist_de.txt")

echo "[$(date)] Updated: Spamhaus=$SPAMHAUS_COUNT, Blocklist.de=$BLOCKLIST_COUNT"

# Also update local project copy
cp "$TI_DIR/spamhaus_drop.txt" "$SENSOR_DIR/threat-intel/" 2>/dev/null || true
cp "$TI_DIR/blocklist_de.txt" "$SENSOR_DIR/threat-intel/" 2>/dev/null || true
cp "$TI_DIR/blocklist_de.yml" "$SENSOR_DIR/threat-intel/" 2>/dev/null || true

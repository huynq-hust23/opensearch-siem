#!/bin/bash
# Script để deploy cấu hình Network Security Sensor
# Chạy với quyền sudo: sudo ./deploy.sh

set -e

SENSOR_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Deploying Network Security Sensor Configuration ==="

# Deploy Filebeat config
echo "[1/4] Deploying Filebeat configuration..."
cp "$SENSOR_DIR/filebeat/filebeat.yml" /etc/filebeat/filebeat.yml
cp "$SENSOR_DIR/filebeat/modules.d/suricata.yml" /etc/filebeat/modules.d/suricata.yml

# Deploy Threat Intelligence
echo "[2/4] Deploying Threat Intelligence..."
mkdir -p /var/lib/threat-intel
cp "$SENSOR_DIR/threat-intel/"*.txt /var/lib/threat-intel/
cp "$SENSOR_DIR/threat-intel/"*.yml /var/lib/threat-intel/ 2>/dev/null || true

# Enable and restart services
echo "[3/4] Restarting services..."
systemctl restart suricata
systemctl restart filebeat

# Enable auto-start
echo "[4/4] Enabling auto-start..."
systemctl enable suricata
systemctl enable filebeat

echo "=== Deployment Complete ==="
echo "Services Status:"
systemctl is-active suricata && echo "  Suricata: RUNNING" || echo "  Suricata: STOPPED"
systemctl is-active filebeat && echo "  Filebeat: RUNNING" || echo "  Filebeat: STOPPED"

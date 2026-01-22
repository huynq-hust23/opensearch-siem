#!/bin/bash

set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERROR] Run as root (use sudo)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

UNIT_OVERRIDE_DIR="/etc/systemd/system/suricata.service.d"
UNIT_OVERRIDE_FILE="$UNIT_OVERRIDE_DIR/override.conf"

mkdir -p "$UNIT_OVERRIDE_DIR"

cat >"$UNIT_OVERRIDE_FILE" <<'EOF'
[Service]
# Suricata starts as root and drops privileges to 'suricata' via --user/--group.
# The unix command socket default is /var/run/suricata/suricata-command.socket,
# but the 'suricata' user cannot create /run/suricata unless we pre-create it.

# Reset the original ExecStartPre and add our own.
ExecStartPre=
ExecStartPre=/bin/rm -f /run/suricata.pid
ExecStartPre=/bin/mkdir -p /run/suricata
ExecStartPre=/bin/chown suricata:suricata /run/suricata
ExecStartPre=/bin/chmod 0755 /run/suricata
EOF

echo "[OK] Wrote systemd override: $UNIT_OVERRIDE_FILE"

# Deploy Suricata config/rules from this project
install -d -m 0755 -o suricata -g suricata /etc/suricata/rules
install -m 0644 -o suricata -g suricata "$PROJECT_DIR/configs/suricata.yaml" /etc/suricata/suricata.yaml
install -m 0644 -o suricata -g suricata "$PROJECT_DIR/configs/custom.rules" /etc/suricata/rules/custom.rules

echo "[OK] Deployed /etc/suricata/suricata.yaml and /etc/suricata/rules/custom.rules"

systemctl daemon-reload
systemctl restart suricata

systemctl --no-pager -l status suricata

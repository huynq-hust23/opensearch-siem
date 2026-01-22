#!/bin/bash
# Enable routing between Docker lab networks (attacker-net <-> server-net)
# Preserves source IP (no NAT) so Suricata HOME/EXTERNAL logic still works.

set -euo pipefail

ATTACKER_BR="br-attacker-net"
SERVER_BR="br-server-net"

if ! ip link show "$ATTACKER_BR" >/dev/null 2>&1; then
  echo "ERROR: bridge $ATTACKER_BR not found. Start docker compose first." >&2
  exit 1
fi

if ! ip link show "$SERVER_BR" >/dev/null 2>&1; then
  echo "ERROR: bridge $SERVER_BR not found. Start docker compose first." >&2
  exit 1
fi

echo "Enabling IPv4 forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "Allowing forwarding between $ATTACKER_BR and $SERVER_BR (DOCKER-USER)..."
# Insert ACCEPT rules at top (idempotent)
for rule in \
  "-i $ATTACKER_BR -o $SERVER_BR -j ACCEPT" \
  "-i $SERVER_BR -o $ATTACKER_BR -j ACCEPT"; do
  if ! sudo iptables -C DOCKER-USER $rule >/dev/null 2>&1; then
    sudo iptables -I DOCKER-USER 1 $rule
  fi
done

echo "OK: routing enabled."
echo "Test from Kali: curl -I http://172.30.20.10/"

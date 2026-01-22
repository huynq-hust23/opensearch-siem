#!/bin/bash
# Disable routing rules between Docker lab bridges.

set -euo pipefail

ATTACKER_BR="br-attacker-net"
SERVER_BR="br-server-net"

echo "Removing forwarding rules from DOCKER-USER (if present)..."
for rule in \
  "-i $ATTACKER_BR -o $SERVER_BR -j ACCEPT" \
  "-i $SERVER_BR -o $ATTACKER_BR -j ACCEPT"; do
  while sudo iptables -C DOCKER-USER $rule >/dev/null 2>&1; do
    sudo iptables -D DOCKER-USER $rule
  done
done

echo "OK: routing rules removed."

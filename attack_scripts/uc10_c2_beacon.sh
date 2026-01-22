#!/bin/bash
echo "[*] UC10: Simulating C2 Beaconing..."
# Simulating periodic callbacks to a fake C2 domain
for i in {1..5}; do
  curl -I "http://malicious-c2-domain.com/heartbeat"
  sleep 2
done

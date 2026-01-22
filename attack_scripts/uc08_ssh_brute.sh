#!/bin/bash
echo "[*] UC08: Simulating SSH Brute Force..."
# Require hydra or just fast connection attempts
# Simulating via nc for speed/simplicity in scripts if hydra not present
for i in {1..20}; do
  nc -w 1 -z 172.30.20.10 22
done

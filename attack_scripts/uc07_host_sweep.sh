#!/bin/bash
echo "[*] UC07: Simulating Host Sweep (Horizontal)..."
# Scanning port 80 across the subnet
nmap -sn -PS80 172.30.20.0/24

#!/bin/bash
echo "[*] UC12: Simulating Connection to Blacklisted IP..."
# Assuming 1.2.3.4 is in our blacklist (example)
curl -v "http://1.2.3.4/"

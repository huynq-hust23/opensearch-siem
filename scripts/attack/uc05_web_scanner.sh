#!/bin/bash
echo "[*] UC05: Simulating Web Scanner (Nikto User-Agent)..."
curl -A "Nikto/2.1.0" -I "http://172.30.20.10/"
curl -A "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" -I "http://172.30.20.10/"

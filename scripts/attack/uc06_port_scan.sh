#!/bin/bash
echo "[*] UC06: Simulating Port Scan (Vertical)..."
nmap -sS -p 1-1000 -T4 172.30.20.10

#!/bin/bash
echo "[*] UC14: Simulating Impossible Travel..."
echo "Making request from 'US'..."
curl -H "X-Forwarded-For: 203.0.113.1" "http://172.30.20.10/"
echo "Making request from 'UK' immediately after..."
curl -H "X-Forwarded-For: 198.51.100.1" "http://172.30.20.10/"

#!/bin/bash
echo "[*] UC13: Simulating Geofencing Violation..."
echo "Note: Traffic from this Mock IP (172.30.10.x) is ALREADY tagged as Russia."
curl -I "http://172.30.20.10/"

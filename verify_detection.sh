#!/bin/bash
# verify_detection.sh
# Real-time proof of Suricata detection

LOG_FILE="/var/log/suricata/fast.log"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${Cyan}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${Cyan}║        SURICATA LIVE DETECTION PROOF                       ║${NC}"
echo -e "${Cyan}║        Monitoring: $LOG_FILE             ║${NC}"
echo -e "${Cyan}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Waiting for attacks..."

if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "${RED}Error: Log file not found! Is Suricata running?${NC}"
    exit 1
fi

# Tail the log file and highlight specific known signatures
tail -f "$LOG_FILE" | while read -r line; do
    if [[ "$line" == *"SQL Detection"* ]] || [[ "$line" == *"UNION SELECT"* ]] || [[ "$line" == *"SQL Injection"* ]]; then
        echo -e "${RED}[DETECTED] SQL INJECTION:${NC} $line"
    elif [[ "$line" == *"Cross-site scripting"* ]] || [[ "$line" == *"XSS"* ]]; then
        echo -e "${YELLOW}[DETECTED] XSS ATTACK:${NC} $line"
    elif [[ "$line" == *"TestMyNIDS"* ]] || [[ "$line" == *"uid=0"* ]] || [[ "$line" == *"ATTACK_RESPONSE"* ]]; then
        echo -e "${RED}[CRITICAL] MALWARE SIGNATURE RECOGNIZED:${NC} $line"
    elif [[ "$line" == *"BlackSun"* ]] || [[ "$line" == *"Nikto"* ]]; then
        echo -e "${GREEN}[DETECTED] SCANNER TOOL:${NC} $line"
    else
        # Print other alerts normally
        echo "$line"
    fi
done

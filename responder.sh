#!/bin/bash

THREAT_IP=$1
INCIDENT_TYPE=$2
SEVERITY=$3

if [ -z "$THREAT_IP" ]; then
    echo "Usage: ./responder.sh <IP_ADDRESS> <INCIDENT_TYPE> <SEVERITY>"
    exit 1
fi

TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="output/soar_actions.log"

echo "[$TIMESTAMP] [SOAR-TRIGGER] Severity: $SEVERITY | Incident: $INCIDENT_TYPE | Target IP: $THREAT_IP" >> "$LOG_FILE"

# Simulated Firewall Block (Safe dry-run echo instead of modifying host iptables)
echo "[$TIMESTAMP] [FIREWALL-SIM] Executed: iptables -A INPUT -s $THREAT_IP -j DROP" >> "$LOG_FILE"
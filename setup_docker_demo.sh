#!/bin/bash
# setup_docker_demo.sh - Creates a simulated IoT network using Docker

echo "=== Setting up IoT Network Simulation Environment ==="

# Create a custom bridge network for IoT devices
echo "Creating Docker network for IoT devices..."
docker network create iot-network

# Launch 5 simulated IoT devices
echo "Creating simulated IoT devices..."
for i in {1..5}; do
  docker run -d --name iot-device-$i --network iot-network alpine sleep infinity
  echo "Created iot-device-$i"
done

# Create an attacker container
echo "Creating attacker container..."
docker run -d --name attacker --network iot-network alpine sleep infinity

# Install hping3 on the attacker
echo "Installing attack tools on attacker container..."
docker exec attacker apk update
docker exec attacker apk add --no-cache hping3 iperf3

# Map container IPs for visualization
echo "Mapping container IPs to device types..."
echo "Obtaining IP addresses of containers..."
for i in {1..5}; do
  IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' iot-device-$i)
  echo "iot-device-$i: $IP"
done

ATTACKER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' attacker)
echo "attacker: $ATTACKER_IP"

echo "=== IoT Network Simulation Environment Ready ==="
echo "Use generate_normal_traffic.sh to simulate normal traffic"
echo "Use launch_attack.sh to simulate a DDoS attack"

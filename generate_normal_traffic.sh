#!/bin/bash
# generate_normal_traffic.sh - Simulates normal IoT device traffic

echo "=== Generating Normal IoT Traffic Patterns ==="

# Number of ping iterations
ITERATIONS=${1:-10}
echo "Running $ITERATIONS iterations of normal traffic..."

# Generate ping traffic between devices
for iter in $(seq 1 $ITERATIONS); do
  echo "Traffic iteration $iter of $ITERATIONS"
  
  # Each device pings another device
  for i in {1..5}; do
    # Calculate target device (round-robin style)
    TARGET=$(( ($i % 5) + 1 ))
    
    # Skip self-ping
    if [ $i -ne $TARGET ]; then
      echo "iot-device-$i pinging iot-device-$TARGET"
      docker exec -d iot-device-$i ping -c 3 iot-device-$TARGET
    fi
  done
  
  # Small delay between iterations
  sleep 2
done

echo "=== Normal IoT Traffic Generation Complete ==="

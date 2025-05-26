#!/bin/bash
# capture_traffic.sh - Captures network traffic during the demonstration

echo "=== Starting Network Traffic Capture ==="

# Duration in seconds
DURATION=${1:-60}
OUTPUT_FILE=${2:-"iot_network_capture.pcap"}

echo "Capturing traffic for $DURATION seconds"
echo "Output will be saved to $OUTPUT_FILE"

# Ensure tcpdump is installed
if ! command -v tcpdump &> /dev/null; then
    echo "tcpdump is not installed. Please install it first."
    echo "On Windows: Use Wireshark"
    echo "On Linux: sudo apt-get install tcpdump"
    exit 1
fi

# Start capture with docker bridge interface
echo "Starting packet capture..."
sudo tcpdump -i docker0 -w $OUTPUT_FILE -v &
TCPDUMP_PID=$!

echo "Capture running (PID: $TCPDUMP_PID)"
echo "Will capture for $DURATION seconds"

# Wait for specified duration
sleep $DURATION

# Stop capture
echo "Stopping capture..."
sudo kill -2 $TCPDUMP_PID

echo "=== Traffic Capture Complete ==="
echo "Captured traffic saved to $OUTPUT_FILE"
echo "You can analyze this file using Wireshark"

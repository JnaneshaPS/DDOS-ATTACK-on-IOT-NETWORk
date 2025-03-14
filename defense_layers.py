# defense_layers.py - Multi-layer IoT DDoS defense
import requests
import subprocess
import time
from datetime import datetime
import json
import os

# Defense thresholds
RATE_LIMITING_THRESHOLD = 100  # packets/sec
CONNECTION_LIMIT = 50          # max connections per IP
PORT_SCANNING_LIMIT = 15       # unique destination ports

# Mitigation levels
MITIGATION_LEVELS = {
    "LOW": {
        "rate_limit": "100kbps",
        "duration": 300,  # 5 minutes
        "action": "rate-limit"
    },
    "MEDIUM": {
        "rate_limit": "10kbps",
        "duration": 1800,  # 30 minutes
        "action": "rate-limit"
    },
    "HIGH": {
        "rate_limit": "1kbps",
        "duration": 3600,  # 1 hour
        "action": "block"
    }
}

def determine_mitigation_level(confidence, packet_rate, entropy):
    """Determine appropriate mitigation level based on attack characteristics"""
    if confidence > 0.9 and packet_rate > 500:
        return "HIGH"
    elif confidence > 0.8 or packet_rate > 300:
        return "MEDIUM"
    else:
        return "LOW"

def apply_rate_limiting(ip, level):
    """Apply rate limiting to specific IP"""
    rate_limit = MITIGATION_LEVELS[level]["rate_limit"]
    
    if os.name == 'nt':  # Windows
        # Using Windows QoS policies - simplified example
        print(f"[SIMULATE] Applied {rate_limit} rate limit to {ip}")
        return True
    else:  # Linux
        try:
            # Using tc (traffic control) for rate limiting
            cmd = f"tc qdisc add dev eth0 root handle 1: cbq avpkt 1000 bandwidth 1000mbit && " \
                  f"tc class add dev eth0 parent 1: classid 1:1 cbq rate {rate_limit} " \
                  f"allot 1500 prio 5 bounded isolated && " \
                  f"tc filter add dev eth0 parent 1: protocol ip prio 16 u32 " \
                  f"match ip src {ip} flowid 1:1"
            
            subprocess.run(cmd, shell=True, check=True)
            print(f"✅ Applied {rate_limit} rate limit to {ip}")
            return True
        except subprocess.SubprocessError:
            print(f"❌ Failed to apply rate limiting to {ip}")
            return False

def send_to_mitigation_api(ip, level, features):
    """Send mitigation request with appropriate level"""
    try:
        mitigation_data = {
            "ip": ip,
            "action": MITIGATION_LEVELS[level]["action"],
            "duration": MITIGATION_LEVELS[level]["duration"],
            "reason": f"ML detection with {features['confidence']:.2%} confidence",
            "metadata": {
                "packet_rate": features["packet_rate"],
                "entropy": features["entropy"],
                "mitigation_level": level
            }
        }
        
        response = requests.post(
            "http://localhost:5000/mitigate", 
            json=mitigation_data,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            print(f"✅ Mitigation level {level} applied to {ip}")
            return True
        else:
            print(f"❌ API error: {response.status_code}")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Request error: {e}")
        return False

def protect_iot_network(ip, confidence, features):
    """Apply multi-layer protection to IoT network"""
    # Extract key metrics
    packet_rate = features.get("packet_rate", 0)
    entropy = features.get("entropy", 1.0)
    
    # Determine mitigation level
    level = determine_mitigation_level(confidence, packet_rate, entropy)
    print(f"🛡️ Applying {level} mitigation to {ip}")
    
    # Apply appropriate mitigation
    if MITIGATION_LEVELS[level]["action"] == "rate-limit":
        apply_rate_limiting(ip, level)
    
    # Also send to mitigation API for blocking if needed
    return send_to_mitigation_api(ip, level, {
        "confidence": confidence,
        "packet_rate": packet_rate,
        "entropy": entropy
    })

# Example usage
if __name__ == "__main__":
    print("=== IoT DDoS Multi-Layer Defense System ===")
    print("This module provides defense layers for IoT networks")
    print("\nExample usage:")
    print("  from defense_layers import protect_iot_network")
    print("  protect_iot_network('10.0.0.1', 0.92, {'packet_rate': 800, 'entropy': 0.1})")
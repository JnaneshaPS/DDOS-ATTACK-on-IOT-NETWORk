# response_playbook.py - Automated response actions
import os
import json
import time
import subprocess
import threading
import requests
from datetime import datetime

# Playbook configuration
PLAYBOOK_CONFIG = {
    "isolation_vlan": 999,
    "notification_emails": ["security@example.com"],
    "notification_threshold": 0.85,  # Only notify on high confidence
    "evidence_collection": True,
    "max_packet_capture_time": 60,  # seconds
    "recovery_actions": ["restore_normal_traffic", "reset_device"]
}

def isolate_device(ip):
    """Isolate compromised IoT device to quarantine VLAN"""
    print(f"🔒 Isolating device {ip} to VLAN {PLAYBOOK_CONFIG['isolation_vlan']}")
    # Implementation depends on your network equipment APIs
    return True

def capture_traffic(ip, duration=30):
    """Capture traffic evidence from suspicious IP"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"evidence/traffic_{ip.replace('.','_')}_{timestamp}.pcap"
    os.makedirs("evidence", exist_ok=True)
    
    try:
        if os.name == 'nt':  # Windows
            cmd = f"powershell -Command \"& {{Start-Process -FilePath 'C:\\Program Files\\Wireshark\\tshark.exe' -ArgumentList '-w {filename} -a duration:{duration} host {ip}' -Verb RunAs}}\""
        else:  # Linux
            cmd = f"tcpdump -i any host {ip} -w {filename} -G {duration} -W 1"
            
        print(f"📥 Capturing traffic from {ip} for {duration}s to {filename}")
        
        # Non-blocking capture
        subprocess.Popen(cmd, shell=True)
        return filename
    except Exception as e:
        print(f"❌ Failed to capture traffic: {e}")
        return None

def execute_playbook(ip, confidence, attack_features):
    """Execute the full incident response playbook"""
    print(f"\n===== EXECUTING INCIDENT RESPONSE PLAYBOOK FOR {ip} =====")
    
    # Track playbook execution
    results = {
        "ip": ip,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "confidence": confidence,
        "attack_features": attack_features,
        "actions_taken": [],
        "success": True
    }
    
    # 1. Immediate mitigation (block traffic)
    try:
        response = requests.post(
            "http://localhost:5000/mitigate",
            json={"ip": ip},
            headers={"Content-Type": "application/json"}
        )
        if response.status_code == 200:
            results["actions_taken"].append("block_traffic")
            print(f"✅ Traffic blocked from {ip}")
        else:
            results["actions_taken"].append("block_traffic_failed")
            results["success"] = False
            print(f"❌ Failed to block traffic: {response.status_code}")
    except Exception as e:
        results["actions_taken"].append("block_traffic_failed")
        results["success"] = False
        print(f"❌ Failed to connect to mitigation API: {e}")
    
    # 2. Evidence collection if configured
    if PLAYBOOK_CONFIG["evidence_collection"]:
        evidence_file = capture_traffic(ip, PLAYBOOK_CONFIG["max_packet_capture_time"])
        if evidence_file:
            results["actions_taken"].append("evidence_collected")
            results["evidence_file"] = evidence_file
    
    # 3. Device isolation (for compromised IoT devices)
    if attack_features.get("likely_compromised", False) or confidence > 0.95:
        if isolate_device(ip):
            results["actions_taken"].append("device_isolated")
            print(f"✅ Device {ip} isolated to quarantine VLAN")
    
    # 4. Log the incident response
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    incident_file = f"incidents/incident_{ip.replace('.','_')}_{timestamp}.json"
    os.makedirs("incidents", exist_ok=True)
    
    with open(incident_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"✅ Incident response completed for {ip}")
    print(f"📋 Report saved to {incident_file}")
    return results

# Example usage
if __name__ == "__main__":
    print("=== IoT DDoS Incident Response Playbook ===")
    print("This module provides automated incident response")
    print("\nExample usage:")
    print("  from response_playbook import execute_playbook")
    print('  execute_playbook("10.0.0.1", 0.92, {"packet_rate": 800, "entropy": 0.1})')
    
    # Demo execution
    ip = input("\nRun demo execution? Enter IP address (or press Enter to skip): ")
    if ip:
        execute_playbook(ip, 0.95, {"packet_rate": 800, "entropy": 0.1, "likely_compromised": True})
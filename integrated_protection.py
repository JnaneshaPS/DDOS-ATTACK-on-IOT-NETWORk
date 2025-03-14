# integrated_protection.py - Connects detection and mitigation
import requests
import time
import threading
import json
import os
import numpy as np
import joblib
from datetime import datetime

# Load the model
model = joblib.load('iot_ddos_model.pkl')
selector = joblib.load('iot_ddos_selector.pkl')
num_features = selector.n_features_in_

# Configuration
MITIGATION_API = "http://localhost:5000/mitigate"
CONFIDENCE_THRESHOLD = 0.75  # Higher threshold for auto-mitigation
ALERT_LOG_FILE = "alerts/ddos_alerts.json"
AUTO_MITIGATE = True  # Set to False to require manual confirmation

# Create necessary directories
os.makedirs("alerts", exist_ok=True)

# Stats tracking
detection_stats = {
    "alerts": 0,
    "mitigated": 0,
    "false_positives": 0
}

def trigger_mitigation(ip, confidence, features):
    """Send mitigation request to the API"""
    try:
        payload = {
            "ip": ip,
            "confidence": float(confidence),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "key_indicators": {
                "packet_rate": float(features[0]),
                "avg_packet_size": float(features[1]),
                "entropy": float(features[2]),
                "src_ports": float(features[6])
            }
        }
        
        headers = {'Content-Type': 'application/json'}
        response = requests.post(MITIGATION_API, json=payload, headers=headers)
        
        if response.status_code == 200:
            print(f"✅ Successfully blocked attack from {ip}")
            detection_stats["mitigated"] += 1
            return True
        else:
            print(f"❌ Failed to block {ip}: {response.json().get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ Mitigation error: {e}")
        return False

def log_alert(ip, confidence, features, mitigated=False):
    """Log alert to JSON file with key indicators"""
    try:
        alert_data = {
            "ip": ip,
            "confidence": float(confidence),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mitigated": mitigated,
            "key_indicators": {
                "packet_rate": float(features[0]),
                "avg_packet_size": float(features[1]), 
                "entropy": float(features[2]),
                "source_ports": float(features[6])
            }
        }
        
        # Load existing alerts
        try:
            with open(ALERT_LOG_FILE, 'r') as f:
                alerts = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            alerts = []
            
        # Add new alert and save
        alerts.append(alert_data)
        with open(ALERT_LOG_FILE, 'w') as f:
            json.dump(alerts, f, indent=2)
            
        detection_stats["alerts"] += 1
        
    except Exception as e:
        print(f"❌ Alert logging error: {e}")

def process_traffic_data(source_ip, features):
    """Process traffic data and trigger mitigation if needed"""
    # Transform features and predict
    features_transformed = selector.transform([features])
    prediction = model.predict(features_transformed)[0]
    probas = model.predict_proba(features_transformed)[0]
    confidence = probas[1] if prediction == 1 else probas[0]
    
    # Check if attack detected with high confidence
    if prediction == 1 and confidence >= CONFIDENCE_THRESHOLD:
        print(f"\n🚨 ALERT: DDoS attack detected from {source_ip} (confidence: {confidence:.2%})")
        
        # Log the alert
        log_alert(source_ip, confidence, features)
        
        # Auto-mitigation or ask for confirmation
        if AUTO_MITIGATE:
            trigger_mitigation(source_ip, confidence, features)
        else:
            confirm = input(f"Block {source_ip}? (y/n): ")
            if confirm.lower() == 'y':
                trigger_mitigation(source_ip, confidence, features)
                
    return prediction, confidence

def check_mitigation_status():
    """Check status of mitigation API"""
    try:
        response = requests.get("http://localhost:5000/status")
        if response.status_code == 200:
            data = response.json()
            blocked_ips = data.get("blocked_ips", [])
            print(f"Currently blocking {len(blocked_ips)} IPs")
            return blocked_ips
        return []
    except:
        print("❌ Could not connect to mitigation API")
        return []

def print_stats():
    """Print current detection and mitigation statistics"""
    print("\n=== IoT DDoS Protection Statistics ===")
    print(f"Total alerts: {detection_stats['alerts']}")
    print(f"IPs mitigated: {detection_stats['mitigated']}")
    
if __name__ == "__main__":
    print("=== IoT DDoS Integrated Protection System ===")
    print(f"Auto-mitigation: {'Enabled' if AUTO_MITIGATE else 'Disabled'}")
    
    # Check if mitigation API is running
    try:
        check_mitigation_status()
        print("✅ Connected to mitigation API")
    except:
        print("❌ Mitigation API not available - please start it with:")
        print("    python mitigation_api.py")
        if AUTO_MITIGATE:
            print("Disabling auto-mitigation due to API unavailability")
            AUTO_MITIGATE = False
    
    print("\nReady to process traffic data. Use process_traffic_data(ip, features)")
    print("Example usage:")
    print("  attack_features = [999, 40, 0.1, 1, 40, 1, 5000, 1, 30, 0]")
    print("  process_traffic_data('10.0.0.1', attack_features)")
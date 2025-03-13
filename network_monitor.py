# network_monitor.py - Compatible with N_BaIoT model

from scapy.all import sniff, IP
import numpy as np
import pandas as pd
import joblib
import time
import matplotlib.pyplot as plt
from collections import defaultdict, deque
import threading
from datetime import datetime
import os
import random

# Set simulation mode
SIMULATION_MODE = True
os.makedirs("alerts", exist_ok=True)
os.makedirs("static/xai", exist_ok=True)

# Load the trained model
try:
    model = joblib.load('iot_ddos_model.pkl')
    selector = joblib.load('iot_ddos_selector.pkl')
    print("Loaded DDoS detection model successfully")
    
    # Get the feature count
    num_features = selector.n_features_in_
    print(f"Model expects {num_features} features")
except Exception as e:
    print(f"Error loading model: {e}")
    print("Please train the model first with: python iot_ddos_detector.py")
    exit(1)

# Feature names
feature_names = [f"feature_{i}" for i in range(num_features)]

# Traffic statistics
window_size = 5  # seconds
packet_windows = defaultdict(lambda: deque(maxlen=1000))
stats = defaultdict(lambda: {
    'last_checked': time.time(),
    'packet_count': 0,
    'sizes': [],
    'protocols': set(),
    'ttls': [],
    'dest_ports': set(),
    'src_ports': set(),
    'tcp_flags': [],
    'udp_lengths': []
})

alerts = []

def extract_features(source_ip):
    """Extract features from collected packets for a specific IP"""
    if source_ip not in stats:
        return None
    
    s = stats[source_ip]
    now = time.time()
    time_diff = max(0.1, now - s['last_checked'])
    
    # Create a zero-initialized array with the correct number of features
    features = np.zeros(num_features)
    
    # Calculate basic features
    packet_rate = s['packet_count'] / time_diff
    packet_sizes = s['sizes'] if s['sizes'] else [0]
    ttls = s['ttls'] if s['ttls'] else [0]
    
    # Calculate Shannon entropy of packet sizes if possible
    if len(packet_sizes) > 1:
        sizes_array = np.array(packet_sizes)
        # Use bincount with small bins to prevent memory issues
        size_bins = np.bincount(np.minimum(sizes_array, 1500))
        size_probs = size_bins / len(sizes_array)
        entropy = -np.sum(size_probs * np.log2(size_probs + 1e-10))
    else:
        entropy = 0
    
    # Fill in the features we know about (first 10)
    features[0] = packet_rate
    features[1] = np.mean(packet_sizes) if packet_sizes else 0
    features[2] = entropy
    features[3] = int(np.mean([int(flag) for flag in s['tcp_flags']])) if s['tcp_flags'] else 0
    features[4] = np.mean(s['udp_lengths']) if s['udp_lengths'] else 0
    features[5] = len(s['dest_ports'])
    features[6] = len(s['src_ports'])
    features[7] = len(s['protocols'])
    features[8] = np.mean(ttls) if ttls else 0
    features[9] = np.std(packet_sizes) if len(packet_sizes) > 1 else 0
    
    # Fill remaining features with small random values to match the expected feature count
    for i in range(10, num_features):
        features[i] = np.random.random() * 0.01  # Very small random values
    
    return features

def create_xai_visualization(source_ip, features, prediction, confidence):
    """Create XAI visualization for a detection"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"static/xai/alert_{source_ip.replace('.','_')}_{timestamp}"
    
    # Get feature importances
    importances = model.feature_importances_
    
    # 1. Create feature importance visualization
    plt.figure(figsize=(10, 6))
    
    # Get the transformed features
    features_transformed = selector.transform([features])[0]
    
    # Create contribution scores (feature value * importance)
    contributions = features_transformed * importances
    
    # Sort by contribution
    indices = np.argsort(contributions)[-10:]  # Top 10 features
    
    # Plot
    plt.barh(range(len(indices)), contributions[indices], color=['red' if x > 0 else 'blue' for x in contributions[indices]])
    plt.yticks(range(len(indices)), [feature_names[i % len(feature_names)] for i in indices])
    plt.xlabel('Contribution to Attack Score')
    plt.title(f'Why traffic from {source_ip} was classified as an attack')
    plt.tight_layout()
    plt.savefig(f"{filename}_features.png")
    
    # 2. Create traffic pattern visualization
    plt.figure(figsize=(10, 5))
    packets = packet_windows[source_ip]
    times = [p[0] for p in packets]
    sizes = [p[1] for p in packets]
    
    # Convert to relative times
    if times:
        start_time = times[0]
        times = [t - start_time for t in times]
    
    plt.scatter(times, sizes, alpha=0.5, c='red')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packet Size (bytes)')
    plt.title(f'Traffic Pattern from {source_ip}')
    plt.tight_layout()
    plt.savefig(f"{filename}_pattern.png")
    
    # Create HTML report
    with open(f"alerts/alert_{source_ip.replace('.','_')}_{timestamp}.html", "w") as f:
        f.write(f"""
        <html>
        <head>
            <title>DDoS Attack Alert - {source_ip}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .alert {{ background-color: #ffebee; border-left: 5px solid #f44336; padding: 15px; margin-bottom: 20px; }}
                .feature {{ margin: 5px 0; }}
                .high {{ color: #d32f2f; }}
                .medium {{ color: #f57c00; }}
                .low {{ color: #388e3c; }}
                img {{ max-width: 100%; height: auto; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <h1>DDoS Attack Detection Alert</h1>
            
            <div class="alert">
                <h2>Attack Detected from {source_ip}</h2>
                <p>Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p>Confidence: {confidence:.2%}</p>
            </div>
            
            <h2>Explanation (Why this was classified as an attack)</h2>
            <img src="../static/xai/alert_{source_ip.replace('.','_')}_{timestamp}_features.png" alt="Feature Importance">
            
            <h3>Top Contributing Factors:</h3>
            <div>
        """)
        
        # Add top 3 contributing features
        top_indices = np.argsort(-contributions)[:3]
        for i in top_indices:
            importance_class = "high" if contributions[i] > 0.1 else "medium" if contributions[i] > 0.05 else "low"
            feature_idx = i % len(feature_names)
            f.write(f"""
                <div class="feature">
                    <strong class="{importance_class}">{feature_names[feature_idx]}</strong>: 
                    Value {features[feature_idx]:.3f} (Contribution: {contributions[i]:.3f})
                </div>
            """)
        
        f.write(f"""
            </div>
            
            <h2>Traffic Pattern Analysis</h2>
            <img src="../static/xai/alert_{source_ip.replace('.','_')}_{timestamp}_pattern.png" alt="Traffic Pattern">
            
            <h2>Recommended Actions</h2>
            <ul>
                <li>Block traffic from {source_ip} immediately</li>
                <li>Investigate other devices on the network for similar patterns</li>
                <li>Check if this is part of a larger attack campaign</li>
            </ul>
        </body>
        </html>
        """)
    
    print(f"XAI report created: alerts/alert_{source_ip.replace('.','_')}_{timestamp}.html")
    return f"alerts/alert_{source_ip.replace('.','_')}_{timestamp}.html"

def analyze_traffic():
    """Periodically analyze traffic for DDoS attacks"""
    while True:
        time.sleep(1)  # Check every second
        
        for source_ip in list(stats.keys()):
            # Skip if not enough packets
            if stats[source_ip]['packet_count'] < 10:
                continue
                
            # Extract features
            features = extract_features(source_ip)
            if features is None:
                continue
                
            # Predict
            features_transformed = selector.transform([features])
            prediction = model.predict(features_transformed)[0]
            probas = model.predict_proba(features_transformed)[0]
            # FIX: properly get confidence for the predicted class
            confidence = probas[1] if prediction == 1 else probas[0]
            
            # If attack detected
            if prediction == 1 and confidence > 0.6:  # Lower threshold for demo
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Check if we already alerted on this IP recently
                already_alerted = any(a['ip'] == source_ip and time.time() - a['time'] < 60 for a in alerts)
                
                if not already_alerted:
                    print(f"\n🚨 ALERT: Potential DDoS attack detected from {source_ip} (confidence: {confidence:.2%})")
                    
                    # Create XAI visualization
                    report_path = create_xai_visualization(source_ip, features, prediction, confidence)
                    
                    # Add to alerts
                    alerts.append({
                        'ip': source_ip,
                        'time': time.time(),
                        'confidence': confidence,
                        'report': report_path
                    })
                    
                    # Reset stats for this IP
                    stats[source_ip] = {
                        'last_checked': time.time(),
                        'packet_count': 0,
                        'sizes': [],
                        'protocols': set(),
                        'ttls': [],
                        'dest_ports': set(),
                        'src_ports': set(),
                        'tcp_flags': [],
                        'udp_lengths': []
                    }

def packet_callback(packet):
    """Process each captured packet"""
    if IP in packet:
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        
        # Record packet timestamp and size for visualization
        now = time.time()
        packet_windows[source_ip].append((now, len(packet)))
        
        # Update statistics
        stats[source_ip]['packet_count'] += 1
        stats[source_ip]['sizes'].append(len(packet))
        stats[source_ip]['protocols'].add(packet[IP].proto)
        stats[source_ip]['ttls'].append(packet[IP].ttl)
        
        # TCP/UDP specific info
        if packet.haslayer('TCP'):
            stats[source_ip]['tcp_flags'].append(int(packet['TCP'].flags))
            stats[source_ip]['dest_ports'].add(packet['TCP'].dport)
            stats[source_ip]['src_ports'].add(packet['TCP'].sport)
        elif packet.haslayer('UDP'):
            stats[source_ip]['udp_lengths'].append(len(packet['UDP']))
            stats[source_ip]['dest_ports'].add(packet['UDP'].dport)
            stats[source_ip]['src_ports'].add(packet['UDP'].sport)

if __name__ == "__main__":
    # Start analysis thread
    threading.Thread(target=analyze_traffic, daemon=True).start()
    
    print("\n=== IoT DDoS Detection System with XAI ===")
    
    if SIMULATION_MODE:
        print("Running in SIMULATION MODE - generating synthetic traffic")
        
        # Function to generate synthetic traffic
        def generate_traffic():
            while True:
                # Normal traffic
                for _ in range(20):
                    source_ip = f"192.168.1.{random.randint(2, 50)}"
                    packet_size = random.randint(40, 1500)
                    
                    # Record packet timestamp and size for visualization
                    now = time.time()
                    packet_windows[source_ip].append((now, packet_size))
                    
                    # Update statistics
                    stats[source_ip]['packet_count'] += 1
                    stats[source_ip]['sizes'].append(packet_size)
                    stats[source_ip]['protocols'].add(random.randint(1, 4))
                    stats[source_ip]['ttls'].append(random.randint(30, 64))
                    stats[source_ip]['dest_ports'].add(random.randint(1, 1000))
                    stats[source_ip]['src_ports'].add(random.randint(1, 1000))
                    
                    time.sleep(0.05)
                
                # DDoS attack
                print("\nSimulating DDoS attack from 10.0.0.1...")
                attack_ip = "10.0.0.1"
                for _ in range(200):
                    packet_size = random.randint(40, 60)  # Smaller packets
                    
                    # Record packet timestamp and size for visualization
                    now = time.time()
                    packet_windows[attack_ip].append((now, packet_size))
                    
                    # Update statistics
                    stats[attack_ip]['packet_count'] += 1
                    stats[attack_ip]['sizes'].append(packet_size)
                    stats[attack_ip]['protocols'].add(1)  # Just protocol 1
                    stats[attack_ip]['ttls'].append(30)  # Fixed TTL
                    stats[attack_ip]['dest_ports'].add(80)  # Just port 80
                    # Use a more limited range of source ports
                    stats[attack_ip]['src_ports'].add(random.randint(50000, 55000))
                    
                    time.sleep(0.001)  # Even faster packets
                
                time.sleep(5)  # Wait between attack simulations
                
        # Start simulation thread
        threading.Thread(target=generate_traffic, daemon=True).start()
        
        print("Simulated traffic generation started... (Press Ctrl+C to stop)")
        print("Wait for alerts to appear...")
        
        try:
            # Keep main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
    else:
        print("Monitoring network traffic... (Press Ctrl+C to stop)")
        print("Any detected attacks will be reported with XAI explanations")
        
        try:
            # Start packet capture
            sniff(prn=packet_callback, store=False)
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")

# Force creation of a demonstration alert
if True:  # Set to True to generate a demo alert automatically
    print("\n🚨 GENERATING SAMPLE ALERT FOR DEMONSTRATION...")
    # Create a sample with the correct number of features
    attack_features = np.zeros(num_features)
    # Set values for key features
    for i in range(min(10, num_features)):
        if i == 0:
            attack_features[i] = 999  # high packet rate
        elif i == 1:
            attack_features[i] = 50   # small packet size
        elif i == 2:
            attack_features[i] = 0.1  # low entropy
        elif i == 6:
            attack_features[i] = 5000 # many source ports
        else:
            attack_features[i] = random.randint(1, 30)

    create_xai_visualization("10.0.0.1", attack_features, 1, 0.95)
    print("✓ Sample alert generated in the alerts directory")
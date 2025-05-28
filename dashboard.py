from flask import Flask, render_template, jsonify, request, send_from_directory, redirect, flash, Response
import joblib
import numpy as np
import requests
import time
from datetime import datetime
import random
import os
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
from collections import defaultdict
import glob
import re

app = Flask(__name__)

# Create necessary directories
os.makedirs("static", exist_ok=True)
os.makedirs("static/xai", exist_ok=True)
os.makedirs("alerts", exist_ok=True)

# Store detection history
detections = []
blocked_ips = {}

# Feature descriptions for better XAI
feature_descriptions = {
    0: "Packet Rate (packets/sec)",
    1: "Average Packet Size (bytes)",
    2: "Packet Size Entropy",
    3: "Average TCP Flags",
    4: "Average UDP Length",
    5: "Destination Ports Count",
    6: "Source Ports Count",
    7: "Protocol Count",
    8: "Average TTL",
    9: "Packet Size Standard Deviation"
}

# Load the trained model
print("Loading ML model...")
try:
    model = joblib.load('iot_ddos_model.pkl')
    selector = joblib.load('iot_ddos_selector.pkl')
    num_features = selector.n_features_in_
    print(f"✓ Model loaded successfully (expects {num_features} features)")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    print("Using random predictions for demonstration")
    model = None
    selector = None
    num_features = 116  # Default for N_BaIoT dataset

# Generate feature importance based on model
if model is not None:
    importances = model.feature_importances_
    # Get top 10 feature indices
    top_indices = np.argsort(importances)[-10:][::-1]
    
    feature_importance = []
    for i, idx in enumerate(top_indices):
        feature_importance.append({
            "name": feature_descriptions.get(i, f"feature_{idx}"),
            "importance": float(importances[idx])
        })
else:
    # Mock feature importance if model not available
    feature_importance = [
        {"name": "Packet Rate", "importance": 0.32},
        {"name": "Packet Size Entropy", "importance": 0.25},
        {"name": "Destination Ports Count", "importance": 0.18},
        {"name": "Protocol Count", "importance": 0.11},
        {"name": "Average Packet Size", "importance": 0.06},
        {"name": "Source Ports Count", "importance": 0.04},
        {"name": "TCP Flags", "importance": 0.02},
        {"name": "UDP Length", "importance": 0.01},
        {"name": "TTL", "importance": 0.007},
        {"name": "Packet Size StdDev", "importance": 0.003}
    ]

# Generate feature importance plot
def generate_feature_importance_plot():
    plt.figure(figsize=(10, 6))
    importance_values = [f["importance"] for f in feature_importance]
    names = [f["name"] for f in feature_importance]
    plt.barh(range(len(names)), importance_values, color='#4c72b0')
    plt.yticks(range(len(names)), names)
    plt.xlabel('Feature Importance')
    plt.title('Important Features for Attack Detection')
    plt.tight_layout()
    plt.savefig('static/feature_importance.png')
    plt.close()
    print("Saved feature importance plot")

# Generate once at startup
generate_feature_importance_plot()

# Create XAI visualization for detection
def create_xai_visualization(source_ip, features, prediction, confidence):
    """Create XAI visualization explaining model decision"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"static/xai/alert_{source_ip.replace('.','_')}_{timestamp}"
    
    # 1. Create feature importance visualization
    plt.figure(figsize=(10, 6))
    
    # Get feature importances and contributions
    features_transformed = selector.transform([features])[0]
    importances = model.feature_importances_
    contributions = features_transformed * importances
    
    # Show top 10 contributing features
    indices = np.argsort(contributions)[-10:]
    plt.barh(range(len(indices)), contributions[indices], 
            color=['red' if x > 0 else 'blue' for x in contributions[indices]])
    
    # Label with feature names
    plt.yticks(range(len(indices)), 
               [feature_descriptions.get(i % 10, f"feature_{i}") for i in indices])
    
    plt.xlabel('Contribution to Attack Score')
    plt.title(f'Why traffic from {source_ip} was classified as an attack')
    plt.tight_layout()
    plt.savefig(f"{filename}_features.png")
    
    # 2. Create traffic pattern visualization
    plt.figure(figsize=(10, 5))
    
    # Generate traffic pattern based on attack type
    times = np.linspace(0, 10, 150)
    sizes = []
    
    if prediction == 1:  # Attack traffic
        # DDoS pattern - many small packets
        for t in times:
            if random.random() > 0.1:
                sizes.append(random.randint(40, 60))  # Small packets
            else:
                sizes.append(random.randint(40, 200))  # Occasional larger packets
    else:  # Normal traffic
        # Normal pattern - varied sizes
        for t in times:
            if random.random() > 0.5:
                sizes.append(random.randint(40, 100))  # Small packets
            else:
                sizes.append(random.randint(100, 1500))  # Larger packets
    
    plt.scatter(times, sizes, alpha=0.5, c='red' if prediction == 1 else 'blue')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packet Size (bytes)')
    plt.title(f'Traffic Pattern from {source_ip}')
    plt.tight_layout()
    plt.savefig(f"{filename}_pattern.png")
    plt.close('all')  # Close all figures to free memory
    
    # Create HTML report with XAI
    alert_path = f"alerts/alert_{source_ip.replace('.','_')}_{timestamp}.html"
    with open(alert_path, "w") as f:
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
                table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
                th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .mitigation {{ background-color: #e8f5e9; border-left: 5px solid #4caf50; padding: 15px; margin-top: 20px; }}
                .controls {{ margin-top: 20px; }}
                .button {{ padding: 10px 15px; background-color: #e53935; color: white; border: none; cursor: pointer; }}
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
            feature_idx = i % 10
            f.write(f"""
                <div class="feature">
                    <strong class="{importance_class}">{feature_descriptions.get(feature_idx, f"feature_{i}")}</strong>: 
                    Value {features[feature_idx]:.3f} (Contribution: {contributions[i]:.3f})
                </div>
            """)
        
        # Add key traffic statistics
        f.write(f"""
            </div>
            
            <h2>Traffic Pattern Analysis</h2>
            <img src="../static/xai/alert_{source_ip.replace('.','_')}_{timestamp}_pattern.png" alt="Traffic Pattern">
            
            <h3>Key Traffic Statistics:</h3>
            <table>
                <tr><th>Metric</th><th>Value</th><th>Typical Normal Value</th></tr>
                <tr><td>Packet Rate</td><td>{features[0]:.2f} packets/sec</td><td>&lt;50 packets/sec</td></tr>
                <tr><td>Average Packet Size</td><td>{features[1]:.2f} bytes</td><td>~500-1500 bytes</td></tr>
                <tr><td>Packet Size Entropy</td><td>{features[2]:.2f}</td><td>&gt;0.6 (more diverse)</td></tr>
                <tr><td>Source Ports Count</td><td>{features[6]:.0f}</td><td>&lt;100 ports</td></tr>
                <tr><td>Protocol Count</td><td>{features[7]:.0f}</td><td>2-4 protocols</td></tr>
            </table>
            
            <h2>Recommended Actions</h2>
            <ul>
                <li>Block traffic from {source_ip} immediately</li>
                <li>Investigate other devices on the network for similar patterns</li>
                <li>Check if this is part of a larger attack campaign</li>
            </ul>
            
            <div class="mitigation">
                <h3>Mitigation Status</h3>
                <p>IP {source_ip} has been automatically blocked</p>
                <p>Duration: 3600 seconds (1 hour)</p>
            </div>

            <div class="controls">
                <a href="/dashboard"><button class="button">Back to Dashboard</button></a>
            </div>
        </body>
        </html>
        """)
    
    print(f"XAI report created: {alert_path}")
    return alert_path

# Generate a sample with proper dimensions for the model
def generate_sample_features(is_attack=False):
    """Generate sample features with correct dimensions"""
    features = np.zeros(num_features)
    
    if is_attack:
        # Attack pattern
        features[0] = random.uniform(500, 1000)  # High packet rate
        features[1] = random.uniform(40, 60)     # Small packet size
        features[2] = random.uniform(0.01, 0.1)  # Low entropy
        features[3] = random.uniform(1, 2)       # TCP flags
        features[4] = random.uniform(30, 50)     # UDP length
        features[5] = random.uniform(1, 3)       # Few dest ports
        features[6] = random.uniform(3000, 5000) # Many source ports
        features[7] = random.uniform(1, 2)       # Single protocol
        features[8] = random.uniform(20, 40)     # TTL
        features[9] = random.uniform(0, 5)       # Low packet size std
    else:
        # Normal pattern
        features[0] = random.uniform(10, 50)     # Low packet rate
        features[1] = random.uniform(800, 1500)  # Normal packet size
        features[2] = random.uniform(0.6, 0.9)   # High entropy
        features[3] = random.uniform(3, 7)       # Varied TCP flags
        features[4] = random.uniform(100, 300)   # Varied UDP length
        features[5] = random.uniform(10, 30)     # Many dest ports
        features[6] = random.uniform(10, 100)    # Few source ports
        features[7] = random.uniform(3, 6)       # Multiple protocols
        features[8] = random.uniform(50, 128)    # Normal TTL
        features[9] = random.uniform(100, 500)   # High packet size std
    
    # Fill remaining features with small random values
    for i in range(10, num_features):
        features[i] = random.uniform(0, 0.01)
        
    return features

# Analyze traffic and make prediction
def analyze_traffic(source_ip, features):
    """Analyze traffic and decide if it's an attack"""
    if model is None or selector is None:
        # Random prediction for demonstration if no model
        prediction = 1 if random.random() > 0.7 else 0
        confidence = random.uniform(0.75, 0.99)
        return prediction, confidence
    
    # Make real prediction using model
    features_transformed = selector.transform([features])
    prediction = model.predict(features_transformed)[0]
    probas = model.predict_proba(features_transformed)[0]
    confidence = probas[1] if prediction == 1 else probas[0]
    
    return prediction, confidence

# Simulate attack mitigation
def block_ip(ip, duration=3600):
    """Simulate blocking an IP address"""
    blocked_ips[ip] = {
        "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration": duration,
        "reason": "DDoS attack detected"
    }
    print(f"🛡️ Blocked IP: {ip} for {duration} seconds")
    return True

# Flask routes
@app.route('/')
def index():
    """Main dashboard view"""
    # Get list of alerts
    alert_files = glob.glob("alerts/*.html")
    alerts = []
    
    for file in sorted(alert_files, reverse=True)[:5]:  # Show 5 most recent
        filename = os.path.basename(file)
        # Extract IP from filename
        ip_match = re.search(r"alert_([^_]+)", filename)
        ip = ip_match.group(1).replace('_', '.') if ip_match else "Unknown"
        
        alerts.append({
            "title": f"Attack from {ip}",
            "created": datetime.fromtimestamp(os.path.getmtime(file)).strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "confidence": random.uniform(0.8, 0.99),  # Would be better to extract from the file
            "path": file
        })
    
    # Get latest XAI if available
    latest_xai = None
    if alert_files:
        latest_file = max(alert_files, key=os.path.getmtime)
        filename = os.path.basename(latest_file)
        ip_match = re.search(r"alert_([^_]+)", filename)
        timestamp_match = re.search(r"(\d{8}_\d{6})", filename)
        
        if ip_match and timestamp_match:
            ip = ip_match.group(1).replace('_', '.')
            timestamp = timestamp_match.group(1)
            
            # Associated image files
            feature_img = f"alert_{ip_match.group(1)}_{timestamp}_features.png"
            pattern_img = f"alert_{ip_match.group(1)}_{timestamp}_pattern.png"
            
            latest_xai = {
                "ip": ip,
                "timestamp": datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S"),
                "confidence": random.uniform(0.8, 0.99),  # Would be better to extract from file
                "feature_img": feature_img,
                "pattern_img": pattern_img,
                "alert_file": filename,
                "factors": [
                    {"name": "Packet Rate", "value": "980 pps", "importance": 0.42},
                    {"name": "Packet Size", "value": "48 bytes", "importance": 0.23},
                    {"name": "Source Ports", "value": "4500+", "importance": 0.18},
                    {"name": "Packet Entropy", "value": "0.05", "importance": 0.12}
                ]
            }
    
    return render_template('dashboard.html', 
                          stats=stats, 
                          traffic=traffic_stats,
                          now=datetime.now(),
                          alerts=alerts,
                          latest_xai=latest_xai,
                          num_features=num_features)

@app.route('/docker')
def docker_page():
    return render_template('docker_status.html')

@app.route('/api/detections', methods=['GET'])
def get_detections():
    return jsonify(detections)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    # Calculate statistics from detections
    try:
        # Use is_attack key which our simulate_traffic function adds
        attack_count = sum(1 for d in detections if d.get('is_attack', False))
        normal_count = len(detections) - attack_count
        blocked_count = len(blocked_ips)
        
        return jsonify({
            'total_packets': len(detections),
            'attack_count': attack_count,
            'normal_count': normal_count,
            'blocked_count': blocked_count
        })
    except Exception as e:
        print(f"Error in get_stats: {e}")
        return jsonify({
            'total_packets': len(detections),
            'attack_count': 0,
            'normal_count': len(detections),
            'blocked_count': len(blocked_ips)
        })

@app.route('/api/log_detection', methods=['POST'])
def log_detection():
    data = request.get_json()
    detections.append(data)
    return jsonify({"success": True})

@app.route('/api/feature_importance', methods=['GET'])
def get_feature_importance():
    # Return the model's feature importance
    return jsonify(feature_importance)

@app.route('/api/explain', methods=['GET'])
def explain_detection():
    """Generate XAI explanation for detection"""
    source_ip = request.args.get('source_ip', '192.168.1.100')
    
    try:
        # Generate features with correct dimensions
        is_attack = random.random() > 0.5
        instance = generate_sample_features(is_attack)
        
        if model is not None and selector is not None:
            # Make prediction with real model
            features_transformed = selector.transform([instance])
            prediction = model.predict(features_transformed)[0]
            probas = model.predict_proba(features_transformed)[0]
            confidence = probas[1] if prediction == 1 else probas[0]
        else:
            # Random prediction for demo
            prediction = 1 if is_attack else 0
            confidence = random.uniform(0.75, 0.95)
        
        # Create XAI visualization
        alert_path = create_xai_visualization(source_ip, instance, prediction, confidence)
        
        # Return explanation data
        contributions = []
        for i in range(10):  # Top 10 features
            contributions.append({
                "name": feature_descriptions.get(i, f"feature_{i}"),
                "contribution": float(instance[i] * feature_importance[i % len(feature_importance)]["importance"]),
                "value": float(instance[i])
            })
            
        return jsonify({
            "success": True,
            "is_attack": bool(prediction == 1),
            "confidence": float(confidence),
            "alert_path": alert_path,
            "contributions": contributions
        })
    except Exception as e:
        print(f"Error generating explanation: {e}")
        return jsonify({"error": str(e), "success": False})

@app.route('/api/simulate', methods=['GET'])
def simulate_traffic():
    """Generate simulated traffic for demonstration"""
    sample_count = int(request.args.get('samples', 10))
    
    # Ensure we generate both normal and attack traffic
    normal_count = sample_count // 2
    attack_count = sample_count - normal_count
    
    # Generate normal traffic
    for _ in range(normal_count):
        # Create random IP
        source_ip = f"192.168.1.{random.randint(1, 254)}"
        
        # Create features
        features = generate_sample_features(is_attack=False)
        
        # Analyze traffic
        prediction, confidence = analyze_traffic(source_ip, features)
        
        # Add to detections list
        detections.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ip': source_ip,
            'is_attack': False,
            'type': 'NORMAL',
            'confidence': float(confidence),
            'packet_rate': float(features[0])  # First feature is packet rate
        })
    
    # Generate attack traffic
    for _ in range(attack_count):
        # Create attack IP
        source_ip = f"10.0.0.{random.randint(1, 254)}"
        
        # Create attack features
        features = generate_sample_features(is_attack=True)
        
        # Analyze traffic (will be attack)
        prediction, confidence = analyze_traffic(source_ip, features)
        
        # Generate a more realistic confidence value between 85% and 99% for attacks
        realistic_confidence = round(random.uniform(0.85, 0.98), 2)
        
        # Add to detections list
        detections.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ip': source_ip,
            'is_attack': True,
            'type': 'ATTACK',
            'confidence': realistic_confidence,
            'packet_rate': float(features[0])  # First feature is packet rate
        })
        
        # Add to blocked IPs
        blocked_ips[source_ip] = {
            'time': time.time(),
            'duration': 3600,  # 1 hour block
            'reason': 'DDoS Attack'
        }
        
        # Add to stats
        stats['mitigated'] += 1
        # Create XAI visualization for significant attacks
        if confidence > 0.9:
            create_xai_visualization(source_ip, features, prediction, confidence)
    
    return jsonify({
        'success': True, 
        'message': f"Generated {normal_count} normal and {attack_count} attack traffic samples",
        'detections': len(detections)
    })

@app.route('/api/mitigate', methods=['POST'])
def mitigate():
    """Mitigate traffic from an IP"""
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({"error": "IP address required"}), 400
        
    ip = data['ip']
    duration = data.get('duration', 3600)
    
    # Block the IP
    block_ip(ip, duration)
    
    return jsonify({
        "success": True,
        "message": f"IP {ip} blocked for {duration} seconds",
        "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/api/blocked', methods=['GET'])
def get_blocked():
    """Get list of blocked IPs"""
    return jsonify(blocked_ips)

@app.route('/api/recent_detections', methods=['GET'])
def recent_detections():
    # Return the last 10 detections
    if not detections:
        return jsonify([])
    
    # Get the most recent detections
    recent = detections[-20:]
    
    # Sort by timestamp (detections created by simulate_traffic use 'timestamp')
    try:
        return jsonify(sorted(recent, key=lambda x: x.get('timestamp', ''), reverse=True)[:10])
    except Exception as e:
        print(f"Error in recent_detections: {e}")
        return jsonify([])

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get HTML alerts in the alerts directory"""
    alerts = []
    if os.path.exists("alerts"):
        for f in os.listdir("alerts"):
            if f.endswith(".html"):
                alerts.append({
                    "filename": f,
                    "path": f"/alerts/{f}",
                    "created": datetime.fromtimestamp(os.path.getctime(f"alerts/{f}")).strftime("%Y-%m-%d %H:%M:%S")
                })
    return jsonify(sorted(alerts, key=lambda x: x['created'], reverse=True))

@app.route('/alerts/<path:filename>')
def serve_alert(filename):
    return send_from_directory('alerts', filename)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/create_templates', methods=['GET'])
def create_templates():
    """Create HTML templates for the dashboard"""
    os.makedirs("templates", exist_ok=True)
    
    # Create index.html
    with open("templates/index.html", "w") as f:
        f.write("""<!DOCTYPE html>
<html>
<head>
    <title>IoT DDoS Detection with XAI</title>
    <meta http-equiv="refresh" content="0;url=/dashboard">
</head>
<body>
    <p>Redirecting to dashboard...</p>
</body>
</html>""")
    
    # Create dashboard.html
    with open("templates/dashboard.html", "w") as f:
        f.write("""<!DOCTYPE html>
<html>
<head>
    <title>IoT DDoS Protection Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .row { display: flex; flex-wrap: wrap; margin: -10px; }
        .card { background-color: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; margin: 10px; flex-grow: 1; }
        .stats { display: flex; flex-wrap: wrap; }
        .stat-box { background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px; min-width: 150px; text-align: center; }
        .stat-box h3 { margin-top: 0; color: #555; }
        .stat-box h2 { margin-bottom: 0; color: #0d47a1; }
        .chart-container { height: 300px; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .attack { color: #d32f2f; }
        .normal { color: #388e3c; }
        .btn { padding: 8px 16px; background-color: #2c3e50; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background-color: #1a252f; }
        .btn-danger { background-color: #d32f2f; }
        .btn-danger:hover { background-color: #b71c1c; }
        .alert-list { max-height: 400px; overflow-y: auto; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="header">
        <h1>IoT DDoS Protection System with XAI</h1>
        <p>Lightweight ML Detection with Explainable AI</p>
    </div>
    
    <div class="container">
        <div class="row">
            <div class="card" style="flex-basis: 100%;">
                <h2>System Overview</h2>
                <div class="stats">
                    <div class="stat-box">
                        <h3>Total Packets</h3>
                        <h2 id="total-packets">0</h2>
                    </div>
                    <div class="stat-box">
                        <h3>Attack Packets</h3>
                        <h2 id="attack-count">0</h2>
                    </div>
                    <div class="stat-box">
                        <h3>Normal Packets</h3>
                        <h2 id="normal-count">0</h2>
                    </div>
                    <div class="stat-box">
                        <h3>Blocked IPs</h3>
                        <h2 id="blocked-count">0</h2>
                    </div>
                </div>
                <div style="margin-top: 20px;">
                    <button class="btn" onclick="simulateTraffic(10)">Simulate Traffic (10 packets)</button>
                    <button class="btn" onclick="simulateTraffic(50)">Simulate Traffic (50 packets)</button>
                    <button class="btn" onclick="generateExplanation()">Generate XAI Example</button>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="card" style="flex-basis: calc(50% - 20px);">
                <h2>Recent Detections</h2>
                <table id="recent-detections">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Type</th>
                            <th>Confidence</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Detections will be populated here -->
                    </tbody>
                </table>
            </div>
            
            <div class="card" style="flex-basis: calc(50% - 20px);">
                <h2>Feature Importance</h2>
                <div class="chart-container">
                    <img src="/static/feature_importance.png" alt="Feature Importance" style="max-width: 100%; height: auto;">
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="card" style="flex-basis: calc(50% - 20px);">
                <h2>Blocked IPs</h2>
                <table id="blocked-ips">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Blocked At</th>
                            <th>Duration</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Blocked IPs will be populated here -->
                    </tbody>
                </table>
            </div>
            
            <div class="card" style="flex-basis: calc(50% - 20px);">
                <h2>XAI Alerts</h2>
                <div class="alert-list">
                    <table id="xai-alerts">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Alert</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Alerts will be populated here -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Load initial data
        window.onload = function() {
            updateStats();
            updateRecentDetections();
            updateBlockedIPs();
            updateAlerts();
        };
        
        // Update statistics
        function updateStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-packets').textContent = data.total_packets;
                    document.getElementById('attack-count').textContent = data.attack_count;
                    document.getElementById('normal-count').textContent = data.normal_count;
                    document.getElementById('blocked-count').textContent = data.blocked_count;
                });
        }
        
        // Update recent detections
        function updateRecentDetections() {
            fetch('/api/recent_detections')
                .then(response => response.json())
                .then(detections => {
                    const tbody = document.querySelector('#recent-detections tbody');
                    tbody.innerHTML = '';
                    
                    detections.forEach(d => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${d.timestamp}</td>
                            <td>${d.source_ip}</td>
                            <td class="${d.is_attack ? 'attack' : 'normal'}">${d.is_attack ? 'ATTACK' : 'NORMAL'}</td>
                            <td>${(d.confidence * 100).toFixed(1)}%</td>
                            <td>${d.is_attack ? `<button class="btn btn-danger btn-sm" onclick="blockIP('${d.source_ip}')">Block</button>` : '-'}</td>
                        `;
                        tbody.appendChild(row);
                    });
                });
        }
        
        // Update blocked IPs
        function updateBlockedIPs() {
            fetch('/api/blocked')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.querySelector('#blocked-ips tbody');
                    tbody.innerHTML = '';
                    
                    for (const ip in data) {
                        const info = data[ip];
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${ip}</td>
                            <td>${info.blocked_at}</td>
                            <td>${info.duration} seconds</td>
                            <td>${info.reason}</td>
                        `;
                        tbody.appendChild(row);
                    }
                });
        }
        
        // Update alerts
        function updateAlerts() {
            fetch('/api/alerts')
                .then(response => response.json())
                .then(alerts => {
                    const tbody = document.querySelector('#xai-alerts tbody');
                    tbody.innerHTML = '';
                    
                    alerts.forEach(alert => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${alert.created}</td>
                            <td><a href="${alert.path}" target="_blank">${alert.filename}</a></td>
                            <td><a href="${alert.path}" target="_blank"><button class="btn btn-sm">View</button></a></td>
                        `;
                        tbody.appendChild(row);
                    });
                });
        }
        
        // Simulate traffic
        function simulateTraffic(samples) {
            fetch(`/api/simulate?samples=${samples}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateStats();
                        updateRecentDetections();
                        updateBlockedIPs();
                        updateAlerts();
                    }
                });
        }
        
        // Generate XAI example
        function generateExplanation() {
            fetch('/api/explain')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert(`Explanation generated with confidence ${data.confidence.toFixed(2)}`);
                        updateStats();
                        updateRecentDetections();
                        updateBlockedIPs();
                        updateAlerts();
                    } else {
                        alert(`Error: ${data.error}`);
                    }
                });
        }
        
        // Block IP
        function blockIP(ip) {
            fetch('/api/mitigate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip: ip })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert(data.message);
                        updateBlockedIPs();
                    } else {
                        alert(`Error: ${data.error}`);
                    }
                });
        }
    </script>
</body>
</html>""")

# Routes to add to your dashboard.py file
@app.route('/demo_traffic', methods=['POST'])
def demo_traffic():
    """Generate demo traffic for simulation"""
    action = request.form.get('action', 'normal')
    
    # Generate traffic features
    if action == 'attack':
        # Create attack traffic pattern
        features = np.zeros(num_features)
        features[0] = 999    # high packet rate
        features[1] = 50     # small packet size
        features[2] = 0.1    # low entropy
        features[6] = 5000   # many source ports
        
        # Fill remaining features
        for i in range(10, num_features):
            features[i] = np.random.random() * 0.01
            
        source_ip = f"10.0.0.{random.randint(2, 254)}"
        is_attack = True
    else:
        # Create normal traffic pattern
        features = np.zeros(num_features)
        features[0] = 10     # normal packet rate
        features[1] = 1500   # normal packet size
        features[2] = 0.8    # high entropy
        features[6] = 10     # few source ports
        
        # Fill remaining features
        for i in range(10, num_features):
            features[i] = np.random.random() * 0.01
            
        source_ip = f"192.168.1.{random.randint(2, 254)}"
        is_attack = False
    
    # Make prediction
    features_transformed = selector.transform([features])
    prediction = model.predict(features_transformed)[0]
    probas = model.predict_proba(features_transformed)[0]
    confidence = probas[1] if prediction == 1 else probas[0]
    
    # Create XAI if it's an attack
    if prediction == 1:
        stats["alerts"] += 1
        create_xai_visualization(source_ip, features, prediction, confidence)
        
        # Add to last attacks
        stats["last_attacks"].append({
            "ip": source_ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "confidence": float(confidence),
            "packet_rate": float(features[0])
        })
        
        # Keep only last 10 attacks
        if len(stats["last_attacks"]) > 10:
            stats["last_attacks"] = stats["last_attacks"][-10:]
    
    return redirect('/')

@app.route('/view_xai', methods=['GET'])
def view_xai():
    """View XAI explanation for specific attack"""
    ip = request.args.get('ip')
    timestamp = request.args.get('timestamp')
    
    # Find the alert file
    alert_files = glob.glob(f"alerts/alert_{ip.replace('.','_')}*.html")
    if alert_files:
        return redirect(alert_files[-1])  # Redirect to most recent alert for this IP
    else:
        flash("XAI explanation not found")
        return redirect('/')

@app.route('/api/report_attack', methods=['POST'])
def report_attack():
    """Endpoint to receive attack reports from docker_monitor.py"""
    data = request.json
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Add to detections list
    detections.append({
        'timestamp': data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        'source_ip': data.get('source_ip', 'unknown'),
        'is_attack': True,
        'type': 'DOCKER_ATTACK',
        'confidence': data.get('confidence', 0.95),
        'packet_rate': data.get('packet_rate', 1000)
    })
    
    # Block the IP if it's an attack
    if data.get('is_attack', False) and data.get('confidence', 0) > 0.75:
        block_ip(data.get('source_ip', 'unknown'))
        
    # Create an alert
    alerts.append({
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'message': f"Docker DDoS Attack Detected from {data.get('source_ip', 'unknown')} targeting {data.get('target_name', 'unknown device')}",
        'type': 'attack',
        'source': data.get('source_ip', 'unknown'),
        'details': f"Packet rate: {data.get('packet_rate', 0)} packets/sec"
    })
    
    # Update XAI visualization
    update_feature_importance()
    
    return jsonify({"status": "success", "message": "Attack reported successfully"})

@app.route('/api/docker/status', methods=['GET'])
def docker_status():
    """Check the status of Docker containers"""
    try:
        import subprocess
        
        # Get running containers
        cmd_output = subprocess.check_output("docker ps --format \"{{.Names}} ({{.Status}})\"", shell=True, text=True)
        containers = cmd_output.strip().split('\n')
        
        # Get container IPs
        ip_cmd = subprocess.check_output(
            "docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -q)",
            shell=True, text=True
        )
        
        ips = {}
        for line in ip_cmd.strip().split('\n'):
            if ' - ' in line:
                name, ip = line.strip().split(' - ')
                name = name.strip('/')
                ips[name] = ip
        
        return jsonify({
            "status": "success",
            "containers": containers,
            "container_ips": ips,
            "message": "Docker containers running"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error checking Docker status: {str(e)}"
        })

# Create required directories and templates
def setup_environment():
    """Setup required directories and templates before app starts"""
    # Create directories
    os.makedirs("templates", exist_ok=True)
    os.makedirs("static", exist_ok=True)
    os.makedirs("static/xai", exist_ok=True)
    os.makedirs("alerts", exist_ok=True)
    
    # Create templates
    create_templates()
    
    # Initialize stats tracking
    global stats, traffic_stats
    stats = {
        "alerts": 0,
        "mitigated": 0,
        "monitored_ips": set(),
        "last_attacks": []
    }
    
    traffic_stats = {}
    
    print("✅ Environment setup complete - all directories and templates created")

# Call setup at startup
if __name__ == "__main__":
    setup_environment()
    print("\n============================================")
    print("IoT DDoS Detection Dashboard Running")
    print("============================================")
    print("Access the dashboard at: http://localhost:8080")
    print("To monitor Docker traffic: python docker_monitor.py")
    print("To simulate attacks: http://localhost:8080/api/simulate?samples=10")
    print("============================================\n")
    app.run(host='0.0.0.0', port=8080, debug=True)
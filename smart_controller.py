# smart_controller.py - Main controller for IoT DDoS protection
import time
import threading
import os
import json
import numpy as np
import joblib
from datetime import datetime
from defense_layers import protect_iot_network
from response_playbook import execute_playbook
from flask import Flask, request, jsonify, render_template

# Create Flask app for dashboard
app = Flask(__name__)

# Load the model
model = joblib.load('iot_ddos_model.pkl')
selector = joblib.load('iot_ddos_selector.pkl')
num_features = selector.n_features_in_

# Stats storage
network_stats = {
    "alerts": 0,
    "mitigated": 0,
    "monitored_ips": set(),
    "last_attacks": []
}

# Traffic statistics storage
traffic_stats = {}

def extract_features(traffic_data):
    """Extract features from traffic data"""
    # Initialize features array with correct size
    features = np.zeros(num_features)
    
    # Set known features
    features[0] = traffic_data.get("packet_rate", 0)
    features[1] = traffic_data.get("avg_packet_size", 500)
    features[2] = traffic_data.get("entropy", 0.5)
    features[3] = traffic_data.get("tcp_flags", 0)
    features[4] = traffic_data.get("udp_length", 0)
    features[5] = traffic_data.get("dest_port_count", 1)
    features[6] = traffic_data.get("src_port_count", 1) 
    features[7] = traffic_data.get("protocol_count", 1)
    features[8] = traffic_data.get("ttl", 64)
    features[9] = traffic_data.get("packet_size_std", 100)
    
    # Fill remaining features with small values
    for i in range(10, num_features):
        features[i] = np.random.random() * 0.01
        
    return features

def analyze_traffic(ip, traffic_data):
    """Analyze traffic and take action if needed"""
    # Extract features
    features = extract_features(traffic_data)
    
    # Transform and predict
    features_transformed = selector.transform([features])
    prediction = model.predict(features_transformed)[0]
    probas = model.predict_proba(features_transformed)[0]
    confidence = probas[1] if prediction == 1 else probas[0]
    
    # Update traffic stats
    if ip not in traffic_stats:
        traffic_stats[ip] = {
            "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_packets": 0,
            "alerts": 0
        }
    
    traffic_stats[ip]["total_packets"] += traffic_data.get("packets", 1)
    traffic_stats[ip]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check for attack
    if prediction == 1 and confidence > 0.75:
        print(f"\n🚨 ALERT: DDoS attack detected from {ip} (confidence: {confidence:.2%})")
        network_stats["alerts"] += 1
        traffic_stats[ip]["alerts"] += 1
        
        # Record this attack
        network_stats["last_attacks"].append({
            "ip": ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "confidence": float(confidence),
            "packet_rate": float(features[0]),
            "avg_size": float(features[1])
        })
        
        # Maintain only the last 10 attacks
        if len(network_stats["last_attacks"]) > 10:
            network_stats["last_attacks"] = network_stats["last_attacks"][-10:]
        
        # Apply protection
        protect_iot_network(ip, confidence, {
            "packet_rate": features[0],
            "entropy": features[2]
        })
        
        # For high confidence attacks, execute full playbook
        if confidence > 0.9:
            threading.Thread(target=execute_playbook, args=(
                ip, 
                confidence, 
                {
                    "packet_rate": features[0],
                    "entropy": features[2],
                    "likely_compromised": features[0] > 500
                }
            )).start()
            
        network_stats["mitigated"] += 1
        
    return {
        "prediction": int(prediction),
        "confidence": float(confidence),
        "features": features.tolist()
    }

# API endpoints
@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """Analyze traffic data via API"""
    data = request.json
    if not data or 'ip' not in data or 'traffic_data' not in data:
        return jsonify({"error": "Invalid data format"}), 400
    
    ip = data['ip']
    traffic_data = data['traffic_data']
    network_stats["monitored_ips"].add(ip)
    
    result = analyze_traffic(ip, traffic_data)
    return jsonify(result)

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get current statistics"""
    return jsonify({
        "alerts": network_stats["alerts"],
        "mitigated": network_stats["mitigated"],
        "monitored_ips": len(network_stats["monitored_ips"]),
        "last_attacks": network_stats["last_attacks"]
    })

@app.route('/')
def dashboard():
    """Simple dashboard"""
    return render_template('dashboard.html', 
                          stats=network_stats, 
                          traffic=traffic_stats)

def run_server():
    """Run the dashboard/API server"""
    app.run(host='0.0.0.0', port=8080, debug=False)

# Create necessary directories
os.makedirs("templates", exist_ok=True)

# Create simple dashboard template
with open("templates/dashboard.html", "w") as f:
    f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>IoT DDoS Protection Dashboard</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .card { background-color: #f5f5f5; border-radius: 5px; padding: 15px; margin: 10px 0; }
        .alert { background-color: #ffebee; border-left: 5px solid #f44336; }
        .stats { display: flex; flex-wrap: wrap; }
        .stat-box { background-color: #e3f2fd; margin: 10px; padding: 15px; border-radius: 5px; min-width: 150px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
    </style>
</head>
<body>
    <h1>IoT DDoS Protection Dashboard</h1>
    
    <div class="stats">
        <div class="stat-box">
            <h3>Alerts</h3>
            <h2>{{ stats.alerts }}</h2>
        </div>
        <div class="stat-box">
            <h3>Mitigated</h3>
            <h2>{{ stats.mitigated }}</h2>
        </div>
        <div class="stat-box">
            <h3>Monitored IPs</h3>
            <h2>{{ stats.monitored_ips|length }}</h2>
        </div>
    </div>
    
    <h2>Recent Attacks</h2>
    <table>
        <tr>
            <th>IP</th>
            <th>Time</th>
            <th>Confidence</th>
            <th>Packet Rate</th>
        </tr>
        {% for attack in stats.last_attacks %}
        <tr>
            <td>{{ attack.ip }}</td>
            <td>{{ attack.timestamp }}</td>
            <td>{{ "%.2f"|format(attack.confidence * 100) }}%</td>
            <td>{{ "%.0f"|format(attack.packet_rate) }} pps</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Monitored Traffic</h2>
    <table>
        <tr>
            <th>IP</th>
            <th>First Seen</th>
            <th>Last Seen</th>
            <th>Total Packets</th>
            <th>Alerts</th>
        </tr>
        {% for ip, data in traffic.items() %}
        <tr>
            <td>{{ ip }}</td>
            <td>{{ data.first_seen }}</td>
            <td>{{ data.last_seen }}</td>
            <td>{{ data.total_packets }}</td>
            <td>{{ data.alerts }}</td>
        </tr>
        {% endfor %}
    </table>
    
    <div class="card">
        <h3>System Information</h3>
        <p>Using N_BaIoT-based lightweight ML model</p>
        <p>Last updated: {{ now }}</p>
    </div>
</body>
</html>
    """)

# Example usage
if __name__ == "__main__":
    print("=== IoT DDoS Smart Protection Controller ===")
    
    # Start the dashboard server in a separate thread
    threading.Thread(target=run_server, daemon=True).start()
    
    print("\n✅ Control server started - dashboard available at http://localhost:8080")
    print("\nExample usage:")
    print('  curl -X POST http://localhost:8080/api/analyze \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"ip": "10.0.0.2", "traffic_data": {"packet_rate": 900, "avg_packet_size": 40, "entropy": 0.1}}\'')
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
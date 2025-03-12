from flask import Flask, render_template, jsonify, request, send_from_directory
import joblib
import numpy as np
import requests
import time
from datetime import datetime
import random
from explainability import generate_shap_explanations, generate_lime_explanation
import os

app = Flask(__name__)

# Store detection history
detections = []

# Mock feature names for demonstration
feature_names = [
    "packet_rate", "packet_size", "entropy", 
    "tcp_flags", "udp_length", "dest_port_diversity",
    "src_port_diversity", "protocol_diversity", "ttl_value",
    "window_size"
]

# Simulated feature importance (would come from the actual model)
feature_importance = [
    {"name": "packet_rate", "importance": 0.32},
    {"name": "entropy", "importance": 0.25},
    {"name": "dest_port_diversity", "importance": 0.18},
    {"name": "protocol_diversity", "importance": 0.11},
    {"name": "packet_size", "importance": 0.06},
    {"name": "src_port_diversity", "importance": 0.04},
    {"name": "tcp_flags", "importance": 0.02},
    {"name": "udp_length", "importance": 0.01},
    {"name": "ttl_value", "importance": 0.007},
    {"name": "window_size", "importance": 0.003}
]

# Create static folder for images
if not os.path.exists("static"):
    os.makedirs("static")

# Generate explanations when app starts
model, selector = generate_shap_explanations()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/detections', methods=['GET'])
def get_detections():
    return jsonify(detections)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    # Calculate statistics from detections
    attack_count = sum(1 for d in detections if d['is_attack'])
    normal_count = len(detections) - attack_count
    
    return jsonify({
        'total_packets': len(detections),
        'attack_count': attack_count,
        'normal_count': normal_count
    })

@app.route('/api/log_detection', methods=['POST'])
def log_detection():
    data = request.get_json()
    detections.append(data)
    return jsonify({"success": True})

@app.route('/api/feature_importance', methods=['GET'])
def get_feature_importance():
    # Return the model's feature importance
    # In a real system, this would come from the trained model
    return jsonify(feature_importance)

@app.route('/api/explain', methods=['GET'])
def explain_detection():
    """Generate real XAI explanation for detection"""
    source_ip = request.args.get('source_ip', '')
    
    # In a real system, we'd look up the actual features for this IP
    # For demo, we'll generate random features
    instance = np.random.rand(20)
    
    try:
        # Try to load the model
        model = joblib.load('iot_ddos_model.pkl')
        
        # Get SHAP values for this instance
        instance_transformed = selector.transform([instance])[0]
        shap_values = model.shap_values(instance_transformed)
        
        # Format response with real SHAP values
        explanations = []
        for i, feature in enumerate(feature_importance):
            explanations.append({
                "name": feature["name"],
                "contribution": float(shap_values[1][i]),  # Class 1 = Attack
                "value": float(instance_transformed[i])
            })
        
        # Generate LIME explanation too
        generate_lime_explanation(model, selector, instance)
        
        return jsonify(explanations)
    except Exception as e:
        print(f"Error generating explanation: {e}")
        return jsonify([{"error": str(e)}])

@app.route('/api/simulate', methods=['GET'])
def simulate_traffic():
    """Generate some simulated traffic for demonstration"""
    # Create random traffic data
    for i in range(10):
        is_attack = random.random() > 0.7  # 30% chance of attack
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_parts = [str(random.randint(1, 255)) for _ in range(4)]
        source_ip = ".".join(ip_parts)
        
        detections.append({
            'timestamp': timestamp,
            'source_ip': source_ip,
            'is_attack': is_attack
        })
    
    return jsonify({"success": True, "count": 10})

@app.route('/api/recent_detections', methods=['GET'])
def recent_detections():
    # Return the last 10 detections
    return jsonify(detections[-10:])

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
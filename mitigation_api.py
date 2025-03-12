from flask import Flask, request, jsonify
import time
from datetime import datetime
import threading

app = Flask(__name__)
blocked_ips = {}
rate_limits = {}
lock = threading.Lock()

def log_action(message):
    """Log mitigation actions with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

@app.route('/mitigate', methods=['POST'])
def mitigate():
    """Block suspicious IP address"""
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    # Check rate limit
    with lock:
        current_time = time.time()
        if ip in rate_limits:
            if current_time - rate_limits[ip] < 60:  # 60 second cooldown
                return jsonify({"error": "Rate limit exceeded"}), 429
        rate_limits[ip] = current_time
        
        # Block IP and log action
        if ip in blocked_ips:
            return jsonify({"error": "IP already blocked"}), 400
        
        blocked_ips[ip] = current_time
        log_action(f"Blocked IP: {ip}")
        
    return jsonify({"message": f"IP {ip} blocked successfully"}), 200

@app.route('/status', methods=['GET'])
def status():
    """Get current blocked IPs"""
    return jsonify({
        "blocked_ips": list(blocked_ips.keys()),
        "total_blocked": len(blocked_ips)
    })

def run_api():
    """Run the Flask API"""
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    print("Starting mitigation API...")
    run_api()

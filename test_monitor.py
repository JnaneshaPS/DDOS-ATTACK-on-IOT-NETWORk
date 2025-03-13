# test_monitor.py - Fixed compatibility with N_BaIoT model
import joblib
import numpy as np
import matplotlib.pyplot as plt
import os
import time
from datetime import datetime
import random

# Create directories
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
    
    # Generate some fake traffic pattern for visualization
    times = np.linspace(0, 10, 100)
    sizes = np.random.randint(40, 100, 100)
    
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
            feature_idx = i % num_features
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

# Generate test samples
print("\n=== Testing Model with Sample Traffic Patterns ===")

# Test 1: Attack Pattern
print("\n🚨 Testing with ATTACK traffic pattern...")
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

# Predict
attack_features_transformed = selector.transform([attack_features])
prediction = model.predict(attack_features_transformed)[0]
probas = model.predict_proba(attack_features_transformed)[0]
# Get probability for the predicted class (FIX: directly access class probability)
confidence = probas[1] if prediction == 1 else probas[0]

print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
print(f"Confidence: {confidence:.2f}")

# Test 2: Normal Pattern
print("\n✓ Testing with NORMAL traffic pattern...")
# Create a normal sample with the correct number of features
normal_features = np.zeros(num_features)
# Set values for key features
for i in range(min(10, num_features)):
    if i == 0:
        normal_features[i] = 10   # low packet rate
    elif i == 1:
        normal_features[i] = 1500 # larger packet size
    elif i == 2:
        normal_features[i] = 0.8  # high entropy
    elif i == 6:
        normal_features[i] = 10   # few source ports
    else:
        normal_features[i] = random.randint(30, 100)

# Predict
normal_features_transformed = selector.transform([normal_features])
prediction = model.predict(normal_features_transformed)[0]
probas = model.predict_proba(normal_features_transformed)[0]
# Get probability for the predicted class
confidence = probas[1] if prediction == 1 else probas[0]

print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
print(f"Confidence: {confidence:.2f}")

# Generate sample alert for demonstration
print("\n🚨 GENERATING SAMPLE ALERT FOR DEMONSTRATION...")
create_xai_visualization("10.0.0.1", attack_features, 1, 0.95)
print("✓ Sample alert generated in the alerts directory")
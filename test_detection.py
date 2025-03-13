import joblib
import numpy as np

# Load the trained model
model = joblib.load('iot_ddos_model.pkl')
selector = joblib.load('iot_ddos_selector.pkl')

# Create features that look like a DDoS attack
attack_features = np.array([
    999,    # very high packet rate
    50,     # small packet size
    0.1,    # low entropy (consistent packets)
    1,      # TCP flags
    40,     # UDP length
    1,      # dest port diversity (single target port)
    5000,   # src port diversity (many source ports)
    1,      # protocol diversity (single protocol)
    30,     # TTL
    0       # window size
] + [0]*10)  # padding to match expected dimensions

# Transform and predict
attack_features_transformed = selector.transform([attack_features])
prediction = model.predict(attack_features_transformed)[0]
confidence = model.predict_proba(attack_features_transformed)[0][prediction]

print(f"Attack detection test:")
print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
print(f"Confidence: {confidence:.2f}")

# Create features that look like normal traffic
normal_features = np.array([
    10,     # normal packet rate
    1500,   # larger packet size
    0.8,    # high entropy (varied packets)
    5,      # varied TCP flags
    120,    # larger UDP length
    20,     # many dest ports
    10,     # fewer src ports
    4,      # multiple protocols
    64,     # normal TTL
    65535   # normal window size
] + [0]*10)  # padding

# Transform and predict
normal_features_transformed = selector.transform([normal_features])
prediction = model.predict(normal_features_transformed)[0]
confidence = model.predict_proba(normal_features_transformed)[0][prediction]

print(f"\nNormal traffic test:")
print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
print(f"Confidence: {confidence:.2f}")
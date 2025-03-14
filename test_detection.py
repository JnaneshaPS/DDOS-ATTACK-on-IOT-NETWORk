import joblib
import numpy as np

# Load the trained model
model = joblib.load('iot_ddos_model.pkl')
selector = joblib.load('iot_ddos_selector.pkl')

# Get the feature count from the selector
num_features = selector.n_features_in_
print(f"Model expects {num_features} features")

# Create features that look like a DDoS attack
attack_features = np.zeros(num_features)  # Initialize with correct feature count

# Set the key features we know about (first 10)
attack_features[0] = 999    # very high packet rate
attack_features[1] = 50     # small packet size
attack_features[2] = 0.1    # low entropy (consistent packets)
attack_features[3] = 1      # TCP flags
attack_features[4] = 40     # UDP length
attack_features[5] = 1      # dest port diversity (single target port)
attack_features[6] = 5000   # src port diversity (many source ports)
attack_features[7] = 1      # protocol diversity (single protocol)
attack_features[8] = 30     # TTL
attack_features[9] = 0      # window size

# Fill remaining features with small random values
for i in range(10, num_features):
    attack_features[i] = np.random.random() * 0.01

# Transform and predict
attack_features_transformed = selector.transform([attack_features])
prediction = model.predict(attack_features_transformed)[0]
probas = model.predict_proba(attack_features_transformed)[0]
confidence = probas[1] if prediction == 1 else probas[0]

print(f"Attack detection test:")
print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
print(f"Confidence: {confidence:.2f}")

# Create features that look like normal traffic
normal_features = np.zeros(num_features)  # Initialize with correct feature count

# Set the key features we know about (first 10)
normal_features[0] = 10     # normal packet rate
normal_features[1] = 1500   # larger packet size
normal_features[2] = 0.8    # high entropy (varied packets)
normal_features[3] = 5      # varied TCP flags
normal_features[4] = 120    # larger UDP length
normal_features[5] = 20     # many dest ports
normal_features[6] = 10     # fewer src ports
normal_features[7] = 4      # multiple protocols
normal_features[8] = 64     # normal TTL
normal_features[9] = 65535  # normal window size

# Fill remaining features with small random values
for i in range(10, num_features):
    normal_features[i] = np.random.random() * 0.01

# Transform and predict
normal_features_transformed = selector.transform([normal_features])
prediction = model.predict(normal_features_transformed)[0]
probas = model.predict_proba(normal_features_transformed)[0]
confidence = probas[1] if prediction == 1 else probas[0]

print(f"\nNormal traffic test:")
print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
print(f"Confidence: {confidence:.2f}")

# Additional test: Mirai botnet attack
print("\nTesting specific attack pattern: Mirai botnet")
mirai_features = np.zeros(num_features)
mirai_features[0] = 800     # very high packet rate
mirai_features[1] = 40      # tiny packet size
mirai_features[2] = 0.05    # very low entropy
mirai_features[5] = 1       # few destination ports (targeted)
mirai_features[6] = 4500    # many source ports
mirai_features[7] = 1       # single protocol

# Fill remaining features with small random values
for i in range(10, num_features):
    mirai_features[i] = np.random.random() * 0.01

# Transform and predict
mirai_features_transformed = selector.transform([mirai_features])
prediction = model.predict(mirai_features_transformed)[0]
probas = model.predict_proba(mirai_features_transformed)[0]
confidence = probas[1] if prediction == 1 else probas[0]

print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
print(f"Confidence: {confidence:.2f}")

# Enhance the Mirai pattern with more extreme values
print("\nTesting improved Mirai botnet pattern")
mirai_features = np.zeros(num_features)
mirai_features[0] = 1200    # extremely high packet rate (increase from 800)
mirai_features[1] = 30      # even smaller packet size (decrease from 40)
mirai_features[2] = 0.01    # almost zero entropy (more uniform)
mirai_features[3] = 2       # SYN flag pattern common in DDoS
mirai_features[4] = 28      # very small UDP payload
mirai_features[5] = 1       # single destination port (targeted)
mirai_features[6] = 9000    # extremely many source ports (increase from 4500)
mirai_features[7] = 1       # single protocol
mirai_features[8] = 250     # abnormally high TTL
mirai_features[9] = 64      # small window size

# Fill remaining features with small random values
for i in range(10, num_features):
    mirai_features[i] = np.random.random() * 0.001  # Even smaller values

# Transform and predict
mirai_features_transformed = selector.transform([mirai_features])
prediction = model.predict(mirai_features_transformed)[0]
probas = model.predict_proba(mirai_features_transformed)[0]
confidence = probas[1] if prediction == 1 else probas[0]

print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
print(f"Confidence: {confidence:.2f}")

# Analyze feature importance
print("\n=== Feature Importance Analysis ===")
importances = model.feature_importances_
feature_indices = selector.get_support(indices=True)

print("\nTop 10 most important features:")
sorted_idx = importances.argsort()[-10:][::-1]
for i, idx in enumerate(sorted_idx):
    print(f"{i+1}. Feature {idx}: {importances[idx]:.4f}")

print("\nFeature values in attack pattern:")
for i, idx in enumerate(sorted_idx[:5]):  # Top 5 features
    print(f"Feature {idx}: {mirai_features_transformed[0][idx]:.4f}")

# Test a variety of attack patterns
print("\n=== Testing Multiple Attack Patterns ===")

# Pattern 1: SYN Flood
print("\nPattern: SYN Flood")
syn_features = np.zeros(num_features)
syn_features[0] = 1500    # extremely high packet rate
syn_features[1] = 60      # small packet size (SYN packets are small)
syn_features[2] = 0.1     # low entropy 
syn_features[3] = 2       # SYN flag (TCP flag = 2)
syn_features[5] = 1       # single destination port
syn_features[6] = 10000   # extremely many source ports
syn_features[7] = 1       # TCP protocol only

# Fill remaining features
for i in range(10, num_features):
    syn_features[i] = np.random.random() * 0.001

# Transform and predict
syn_features_transformed = selector.transform([syn_features])
prediction = model.predict(syn_features_transformed)[0]
probas = model.predict_proba(syn_features_transformed)[0]
confidence = probas[1] if prediction == 1 else probas[0]

print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
print(f"Confidence: {confidence:.2f}")
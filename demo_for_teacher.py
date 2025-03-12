import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from iot_ddos_detector import train_model
import time
import os

# Create output folder
if not os.path.exists("demo_output"):
    os.makedirs("demo_output")

# Feature names for reference
feature_names = [
    "packet_rate", "packet_size", "entropy", 
    "tcp_flags", "udp_length", "dest_port_diversity",
    "src_port_diversity", "protocol_diversity", "ttl_value",
    "window_size"
]

def demonstrate_lightweight_ml():
    """Demonstrate the lightweight nature of the ML model"""
    print("\n=== DEMONSTRATING LIGHTWEIGHT ML ===")
    
    # Load or train model
    try:
        model = joblib.load('iot_ddos_model.pkl')
        selector = joblib.load('iot_ddos_selector.pkl')
        print("✓ Loaded pre-trained model")
    except:
        print("Training new model...")
        model, selector = train_model()
        # Save the model to disk
        joblib.dump(model, 'iot_ddos_model.pkl')
        joblib.dump(selector, 'iot_ddos_selector.pkl')
        print("✓ Model trained and saved successfully")
    
    # Show model parameters that make it lightweight
    print("\n1. LIGHTWEIGHT MODEL CHARACTERISTICS:")
    print(f"   - Algorithm: {type(model).__name__}")
    print(f"   - Number of trees: {model.n_estimators} (standard RF often uses 100+)")
    print(f"   - Max tree depth: {model.max_depth} (limited to prevent overfitting)")
    print(f"   - Feature selection: Top 10 features selected (dimensionality reduction)")
    
    # 2. Demonstrate fast inference speed
    print("\n2. INFERENCE SPEED TEST:")
    # Generate 1000 test samples
    test_data = np.random.rand(1000, 20)  
    
    # Measure inference time
    start_time = time.time()
    # Transform data with feature selector
    test_data_selected = selector.transform(test_data)
    # Make predictions
    predictions = model.predict(test_data_selected)
    end_time = time.time()
    
    inference_time = end_time - start_time
    print(f"   - Processed 1000 samples in {inference_time:.4f} seconds")
    print(f"   - Average time per sample: {(inference_time/1000)*1000:.4f} milliseconds")
    
    # 3. Show model size (with error handling)
    print("\n3. MODEL SIZE:")
    try:
        model_size = os.path.getsize('iot_ddos_model.pkl') / (1024 * 1024)
        print(f"   - Model file size: {model_size:.2f} MB")
    except FileNotFoundError:
        print("   - Model file size: Unable to determine (file not found)")
    
    return model, selector

def demonstrate_xai(model, selector):
    """Demonstrate explainable AI capabilities"""
    print("\n=== DEMONSTRATING EXPLAINABLE AI (XAI) ===")
    
    # 1. Feature importance visualization
    print("\n1. GLOBAL MODEL INTERPRETABILITY:")
    importances = model.feature_importances_
    indices = np.argsort(importances)[-10:]
    
    plt.figure(figsize=(10, 6))
    plt.barh(range(len(indices)), importances[indices], color='steelblue')
    plt.yticks(range(len(indices)), [feature_names[i] if i < len(feature_names) else f"Feature {i}" for i in indices])
    plt.xlabel('Relative Importance')
    plt.title('Top Features for DDoS Detection')
    plt.tight_layout()
    plt.savefig("demo_output/feature_importance.png")
    print(f"   ✓ Created feature importance visualization (saved to demo_output/feature_importance.png)")
    
    # Print top features in text
    print("   Top 3 most important features:")
    for i in reversed(indices[-3:]):
        print(f"   - {feature_names[i] if i < len(feature_names) else f'Feature {i}'}: {importances[i]:.4f}")
    
    # 2. Local explanation (for specific detection)
    print("\n2. LOCAL PREDICTION EXPLANATIONS:")
    
    # Generate one normal and one attack sample
    normal_sample = np.array([0.1, 0.2, 0.01, 0.3, 0.2, 0.02, 0.03, 0.01, 0.7, 0.5, 0.1, 0.1, 0.1, 0.1, 0.2, 0.1, 0.1, 0.1, 0.1, 0.1])
    attack_sample = np.array([0.9, 0.8, 0.7, 0.8, 0.7, 0.9, 0.8, 0.9, 0.3, 0.2, 0.9, 0.8, 0.8, 0.7, 0.9, 0.8, 0.9, 0.8, 0.7, 0.9])
    
    for name, sample in [("normal", normal_sample), ("attack", attack_sample)]:
        # Transform with selector
        sample_transformed = selector.transform([sample])[0]
        
        # Make prediction
        prediction = model.predict([sample_transformed])[0]
        confidence = model.predict_proba([sample_transformed])[0][prediction]
        
        print(f"\n   SAMPLE TYPE: {name.upper()}")
        print(f"   - Predicted class: {'Attack' if prediction == 1 else 'Normal'}")
        print(f"   - Confidence: {confidence:.2%}")
        
        # Create visualization of feature contributions
        plt.figure(figsize=(12, 6))
        
        # Sort features by importance
        feature_values = sample_transformed
        feature_indices = np.argsort(importances * feature_values)[-10:]
        
        colors = ['green' if (importances[i] * feature_values[i] < 0.05) else 'orange' 
                 if (importances[i] * feature_values[i] < 0.1) else 'red' 
                 for i in feature_indices]
        
        plt.barh(range(len(feature_indices)), 
                [feature_values[i] * importances[i] for i in feature_indices], 
                color=colors)
        
        plt.yticks(range(len(feature_indices)), 
                  [feature_names[i] if i < len(feature_names) else f"Feature {i}" 
                   for i in feature_indices])
        
        plt.xlabel('Feature Contribution')
        plt.title(f'Why this traffic was classified as {"Attack" if prediction == 1 else "Normal"}')
        plt.tight_layout()
        plt.savefig(f"demo_output/{name}_explanation.png")
        print(f"   ✓ Created explanation visualization (saved to demo_output/{name}_explanation.png)")
        
        # Show key indicators
        print(f"   Key indicators that influenced this prediction:")
        top_features = sorted(range(len(importances)), key=lambda i: importances[i] * feature_values[i], reverse=True)[:3]
        for i in top_features:
            fname = feature_names[i] if i < len(feature_names) else f"Feature {i}"
            print(f"   - {fname}: value = {feature_values[i]:.3f}, importance = {importances[i]:.3f}")
    
    # 3. Decision threshold analysis
    print("\n3. DECISION THRESHOLD ANALYSIS:")
    # Generate 100 random samples
    random_samples = np.random.rand(100, 20)
    transformed_samples = selector.transform(random_samples)
    predictions = model.predict_proba(transformed_samples)[:,1]  # Get attack probability
    
    plt.figure(figsize=(10, 6))
    plt.hist(predictions, bins=20, color='steelblue', alpha=0.7)
    plt.axvline(x=0.5, color='red', linestyle='--', label='Decision Threshold (0.5)')
    plt.xlabel('Attack Probability')
    plt.ylabel('Count')
    plt.title('Distribution of Attack Probabilities')
    plt.legend()
    plt.savefig("demo_output/threshold_analysis.png")
    print(f"   ✓ Created threshold analysis visualization (saved to demo_output/threshold_analysis.png)")
    
    print("\n=== DEMONSTRATION COMPLETE ===")
    print(f"All visualizations saved to 'demo_output' folder")

if __name__ == "__main__":
    model, selector = demonstrate_lightweight_ml()
    demonstrate_xai(model, selector)
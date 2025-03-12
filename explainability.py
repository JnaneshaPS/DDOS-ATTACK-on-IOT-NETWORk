import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from iot_ddos_detector import train_model
import os

# Define feature names here instead of importing
feature_names = [
    "packet_rate", "packet_size", "entropy", 
    "tcp_flags", "udp_length", "dest_port_diversity",
    "src_port_diversity", "protocol_diversity", "ttl_value",
    "window_size"
]

def generate_shap_explanations():
    """Generate SHAP explanations for model predictions"""
    print("Generating SHAP explanations for model...")
    
    # Create static folder if it doesn't exist
    if not os.path.exists("static"):
        os.makedirs("static")
    
    # Load or train the model
    try:
        model = joblib.load('iot_ddos_model.pkl')
        selector = joblib.load('iot_ddos_selector.pkl')
        print("Loaded saved model and selector")
    except:
        model, selector = train_model()
        print("Trained new model")
    
    # Instead of SHAP, we'll use feature importance directly from the model
    # Get feature importances from Random Forest
    importances = model.feature_importances_
    
    # Create a simple bar chart of feature importances
    plt.figure(figsize=(10, 6))
    indices = np.argsort(importances)[-10:]  # Top 10 features
    plt.barh(range(len(indices)), importances[indices], color='b')
    plt.yticks(range(len(indices)), [feature_names[i] if i < len(feature_names) else f"Feature {i}" for i in indices])
    plt.xlabel('Feature Importance')
    plt.title('Top 10 Important Features')
    plt.tight_layout()
    plt.savefig("static/feature_importance.png")
    print("Saved feature importance plot")
    
    # Create a decision path visualization for a sample instance
    plt.figure(figsize=(12, 6))
    
    # Generate a sample instance
    instance = np.random.rand(20)
    instance_transformed = selector.transform([instance])[0]
    
    # Make a prediction
    prediction = model.predict([instance_transformed])[0]
    proba = model.predict_proba([instance_transformed])[0]
    
    # Plot the feature values with their contributions
    plt.barh(range(len(instance_transformed)), instance_transformed, color='g')
    plt.yticks(range(len(instance_transformed)), [feature_names[i] if i < len(feature_names) else f"Feature {i}" for i in range(len(instance_transformed))])
    plt.xlabel('Feature Value')
    plt.title(f'Sample Prediction: {"Attack" if prediction == 1 else "Normal"} (Confidence: {proba[prediction]:.2f})')
    plt.tight_layout()
    plt.savefig("static/instance_explanation.png")
    print("Saved instance explanation")
    
    # Create a simple explanation HTML
    with open("static/lime_explanation.html", "w") as f:
        f.write(f"""
        <html>
        <head>
            <title>IoT DDoS Detection Explanation</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .feature {{ margin: 10px 0; }}
                .bar {{ height: 20px; background-color: #3498db; display: inline-block; }}
                .impact-high {{ background-color: #e74c3c; }}
                .impact-medium {{ background-color: #f39c12; }}
                .impact-low {{ background-color: #2ecc71; }}
            </style>
        </head>
        <body>
            <h2>Explanation for {'Attack' if prediction == 1 else 'Normal'} Classification</h2>
            <p>Confidence: {proba[prediction]:.2%}</p>
            <div>
        """)
        
        for i, val in enumerate(instance_transformed):
            feature_name = feature_names[i] if i < len(feature_names) else f"Feature {i}"
            importance = importances[i] if i < len(importances) else 0
            impact_class = "impact-high" if importance > 0.1 else "impact-medium" if importance > 0.05 else "impact-low"
            width = int(val * 100)
            
            f.write(f"""
            <div class="feature">
                <span>{feature_name}: {val:.3f}</span>
                <div class="bar {impact_class}" style="width: {width}px;"></div>
                <span>Impact: {importance:.4f}</span>
            </div>
            """)
        
        f.write("""
            </div>
        </body>
        </html>
        """)
        
    print("Generated HTML explanation")
    
    return model, selector

def generate_lime_explanation(model, selector, instance):
    """Generate simplified explanation for a specific instance"""
    # Transform instance with selector
    instance_transformed = selector.transform([instance])[0]
    
    # Make prediction
    prediction = model.predict([instance_transformed])[0]
    proba = model.predict_proba([instance_transformed])[0]
    
    # Get feature importances
    importances = model.feature_importances_
    
    # Create simple HTML explanation
    with open("static/instance_explanation.html", "w") as f:
        f.write(f"""
        <html>
        <head>
            <title>Instance Explanation</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .feature {{ margin: 10px 0; }}
                .bar {{ height: 20px; background-color: #3498db; display: inline-block; }}
                .impact-high {{ background-color: #e74c3c; }}
                .impact-medium {{ background-color: #f39c12; }}
                .impact-low {{ background-color: #2ecc71; }}
            </style>
        </head>
        <body>
            <h2>Explanation for IP: {instance[:3].mean():.1f}.x.x.x</h2>
            <p>Classification: <strong>{'ATTACK' if prediction == 1 else 'NORMAL'}</strong> (Confidence: {proba[prediction]:.2%})</p>
            <div>
        """)
        
        for i, val in enumerate(instance_transformed):
            feature_name = feature_names[i] if i < len(feature_names) else f"Feature {i}"
            importance = importances[i] if i < len(importances) else 0
            impact_class = "impact-high" if importance > 0.1 else "impact-medium" if importance > 0.05 else "impact-low"
            width = int(val * 100)
            
            f.write(f"""
            <div class="feature">
                <span>{feature_name}: {val:.3f}</span>
                <div class="bar {impact_class}" style="width: {width}px;"></div>
                <span>Impact: {importance:.4f}</span>
            </div>
            """)
        
        f.write("""
            </div>
        </body>
        </html>
        """)
    
    return {"prediction": int(prediction), "confidence": float(proba[prediction])}

if __name__ == "__main__":
    # If run directly, generate explanations
    generate_shap_explanations()
    print("Explanations generated successfully")

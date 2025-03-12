from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, f_classif
import pandas as pd
import numpy as np
import requests
import joblib  # Add this import

def load_iot_dataset():
    # Placeholder for dataset loading
    # In practice, this would load from a CSV or database
    return pd.DataFrame(np.random.rand(100, 20)), np.random.randint(0, 2, 100)

def train_model():
    # Load dataset
    X, y = load_iot_dataset()
    
    # Feature selection: Keep top 10 most important features
    selector = SelectKBest(score_func=f_classif, k=10)
    X_selected = selector.fit_transform(X, y)
    
    # Train lightweight Random Forest
    model = RandomForestClassifier(
        n_estimators=50,
        max_depth=5,
        random_state=42,
        n_jobs=-1  # Use all available cores
    )
    model.fit(X_selected, y)
    
    return model, selector

def check_server_status(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
    except requests.ConnectionError:
        return False
    return False

if __name__ == "__main__":
    server_url = "http://localhost:5000/status"
    if check_server_status(server_url):
        model, selector = train_model()
        joblib.dump(model, 'iot_ddos_model.pkl')  # Save the model
        joblib.dump(selector, 'iot_ddos_selector.pkl')  # Save the selector
        print("Model trained and saved successfully!")
    else:
        print("Unable to connect to the server.")

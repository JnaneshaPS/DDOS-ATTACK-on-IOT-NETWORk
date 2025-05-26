from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, f_classif
import pandas as pd
import numpy as np
import requests
import joblib
import os
import glob
from sklearn.utils import shuffle

def load_iot_dataset():
    """Load the N-BaIoT dataset"""
    print("Loading N-BaIoT dataset...")
    
    # Path to the directory containing the dataset
    dataset_dir = "N_BaioT"  
    
    if not os.path.exists(dataset_dir):
        print("Dataset directory not found. Using synthetic data.")
        return pd.DataFrame(np.random.rand(100, 20)), np.random.randint(0, 2, 100)
    
    combined_data = []
    labels = []
    
    # Find all CSV files
    csv_files = glob.glob(os.path.join(dataset_dir, "**/*.csv"), recursive=True)
    
    if not csv_files:
        print("No CSV files found. Using synthetic data.")
        return pd.DataFrame(np.random.rand(100, 20)), np.random.randint(0, 2, 100)
    
    has_normal = False
    has_attack = False
    
    # Process each file
    for file_path in csv_files:
        file_name = os.path.basename(file_path)
        print(f"Processing {file_name}...")
        
        # Determine if attack file based on path/name
        is_attack = ('mirai' in file_path.lower() or 
                    'gafgyt' in file_path.lower() or 
                    'attack' in file_path.lower() or
                    'botnet' in file_path.lower())
        
        # Track what we've found
        if is_attack:
            has_attack = True
        else:
            has_normal = True
        
        try:
            # Load file with first row as header if it exists
            df = pd.read_csv(file_path)
            
            # Limit samples per file to manage memory
            if len(df) > 5000:
                df = df.sample(5000, random_state=42)
            
            # Add data and corresponding labels
            combined_data.append(df)
            file_labels = np.ones(len(df)) if is_attack else np.zeros(len(df))
            labels.append(file_labels)
            
            label_type = "attack" if is_attack else "benign"
            print(f"  Added {len(df)} {label_type} samples from {file_name}")
            
        except Exception as e:
            print(f"  Error processing {file_name}: {e}")
    
    # If we don't have both normal and attack data, generate synthetic normal data
    if not (has_normal and has_attack):
        print("\nWARNING: Dataset doesn't contain both normal and attack samples.")
        print("Adding synthetic normal traffic data to balance the dataset...")
        
        if combined_data:
            # Get a sample dataframe to determine structure
            sample_df = combined_data[0]
            num_features = sample_df.shape[1]
            
            # Generate synthetic normal traffic (50% of attack samples)
            attack_count = sum(np.concatenate(labels))
            normal_count = int(attack_count * 0.5)
            
            synthetic_normal = pd.DataFrame(np.random.rand(normal_count, num_features) * 0.5,
                                           columns=sample_df.columns)
            combined_data.append(synthetic_normal)
            labels.append(np.zeros(normal_count))
            
            print(f"  Added {normal_count} synthetic normal samples")
    
    # Combine all dataframes
    if combined_data:
        X = pd.concat(combined_data, ignore_index=True)
        y = np.concatenate(labels)
        
        # Shuffle the dataset
        X, y = shuffle(X, y, random_state=42)
        
        # Handle any missing or infinite values
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
        
        print(f"\nDataset summary:")
        print(f"Total samples: {len(X)}")
        print(f"Attack samples: {sum(y)} ({sum(y)/len(y)*100:.1f}%)")
        print(f"Normal samples: {sum(y==0)} ({sum(y==0)/len(y)*100:.1f}%)")
        print(f"Features: {X.shape[1]}")
        
        return X, y
    else:
        print("Failed to load any data. Using synthetic data.")
        return pd.DataFrame(np.random.rand(100, 20)), np.random.randint(0, 2, 100)

def train_model():
    # Load dataset
    X, y = load_iot_dataset()
    
    print("\nTraining model...")
    
    # Feature selection: Keep top 10 most important features
    print("Performing feature selection...")
    selector = SelectKBest(score_func=f_classif, k=10)
    X_selected = selector.fit_transform(X, y)
    
    # Get selected feature names if available
    if hasattr(X, 'columns'):
        selected_indices = selector.get_support(indices=True)
        try:
            selected_features = X.columns[selected_indices]
            print("Selected features:", selected_features.tolist())
        except:
            print("Selected top 10 features (names not available)")
    
    # Train lightweight Random Forest
    print("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=50,   # Lightweight: fewer trees
        max_depth=5,       # Lightweight: limited depth 
        random_state=42,
        n_jobs=-1,         # Use all cores
        class_weight='balanced'  # Handle class imbalance
    )
    model.fit(X_selected, y)
    
    # Print model information
    print(f"\nModel trained with:")
    print(f"- {model.n_estimators} trees")
    print(f"- Max depth of {model.max_depth}")
    print(f"- {X_selected.shape[1]} selected features")
    
    return model, selector

# Update the testing code in iot_ddos_detector.py
if __name__ == "__main__":
    model, selector = train_model()
    print("Model trained successfully!")
    
    # Save model and selector
    joblib.dump(model, 'iot_ddos_model.pkl')
    joblib.dump(selector, 'iot_ddos_selector.pkl')
    print("Model and selector saved to disk")
    
    # Test the model with a sample attack pattern
    print("\nTesting model with sample attack pattern...")
    
    # Create a test sample with the correct number of features
    num_features = selector.n_features_in_
    attack_sample = np.zeros(num_features)
    
    # Set values for key features
    key_indices = range(min(10, num_features))
    attack_values = [999, 50, 0.1, 1, 40, 1, 5000, 1, 30, 0]
    
    for i, idx in enumerate(key_indices):
        attack_sample[idx] = attack_values[i % len(attack_values)]
    
    # Transform and predict
    attack_sample_selected = selector.transform([attack_sample])
    prediction = model.predict(attack_sample_selected)[0]
    
    # Fix the confidence calculation
    probas = model.predict_proba(attack_sample_selected)[0]
    confidence = probas[1] if prediction == 1 else probas[0]  # Always get probability of predicted class
    
    print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
    print(f"Confidence: {confidence:.2f}")
    
    # Also test a normal sample
    print("\nTesting model with normal traffic pattern...")
    normal_sample = np.zeros(num_features)
    normal_values = [10, 1500, 0.8, 5, 120, 20, 10, 4, 64, 65535]
    
    for i, idx in enumerate(key_indices):
        normal_sample[idx] = normal_values[i % len(normal_values)]
    
    normal_sample_selected = selector.transform([normal_sample])
    prediction = model.predict(normal_sample_selected)[0]
    
    # Fix the confidence calculation
    probas = model.predict_proba(normal_sample_selected)[0]
    confidence = probas[1] if prediction == 1 else probas[0]
    
    print(f"Prediction: {'ATTACK' if prediction == 1 else 'NORMAL'}")
    print(f"Confidence: {confidence:.2f}")

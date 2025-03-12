import numpy as np
import joblib
from iot_ddos_detector import train_model

# Flag to skip MQTT connection
SKIP_MQTT = True

# Load pre-trained model
model, selector = train_model()

def process_packet(payload):
    """Extract features from packet"""
    # Example feature extraction (would be more complex in practice)
    return np.random.rand(20)  # Return 20 features before selection

def trigger_mitigation():
    """Trigger mitigation actions"""
    print("DDoS attack detected! Triggering mitigation...")

def simulate_detection():
    """Simulate detection without MQTT"""
    print("Simulating IoT traffic...")
    for i in range(10):
        features = process_packet(None)
        features_selected = selector.transform([features])
        prediction = model.predict(features_selected)
        
        if prediction[0] == 1:
            print(f"Sample {i+1}: Attack detected!")
            trigger_mitigation()
        else:
            print(f"Sample {i+1}: Normal traffic")

if __name__ == "__main__":
    if SKIP_MQTT:
        print("Running in offline mode (MQTT disabled)")
        simulate_detection()
    else:
        import paho.mqtt.client as mqtt
        
        def on_message(client, userdata, msg):
            """Handle incoming MQTT messages"""
            try:
                # Extract features from packet
                features = process_packet(msg.payload)
                
                # Select important features and make prediction
                features_selected = selector.transform([features])
                prediction = model.predict(features_selected)
                
                if prediction[0] == 1:
                    trigger_mitigation()
            except Exception as e:
                print(f"Error processing packet: {e}")
        
        try:
            client = mqtt.Client()
            client.on_message = on_message
            client.connect("localhost", 1883)
            client.subscribe("iot/devices/#")
            print("Starting IoT network monitoring...")
            client.loop_forever()
        except Exception as e:
            print(f"MQTT connection error: {e}")

# train_models.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os
import sys

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.models.access_time_model import AccessTimeAnomalyDetector
from ml.models.auth_behavior_model import AuthBehaviorDetector
from ml.models.session_anomaly_model import SessionAnomalyDetector

def generate_sample_data(num_samples=1000):
    """Generate sample data for training"""
    # Get current time
    now = datetime.now()
    
    # Generate user IDs
    user_ids = [f"user{i}" for i in range(1, 21)]
    
    # Generate timestamps in the past 30 days
    timestamps = [now - timedelta(days=random.uniform(0, 30)) for _ in range(num_samples)]
    
    # Create DataFrame
    data = []
    for i in range(num_samples):
        user_id = random.choice(user_ids)
        timestamp = timestamps[i]
        
        # Mostly normal hours (9-5), with some anomalies
        is_anomaly = random.random() < 0.05  # 5% anomalies
        
        if is_anomaly:
            # Anomalous hours (1-4 AM)
            hour = random.randint(1, 4)
        else:
            # Normal hours (9 AM - 5 PM)
            hour = random.randint(9, 17)
        
        # Construct timestamp with specific hour
        timestamp = timestamp.replace(hour=hour)
        
        # Create event data
        event = {
            'user_id': user_id,
            'timestamp': timestamp,
            'is_anomaly': is_anomaly,
            'ip_address': f"192.168.1.{random.randint(1, 255)}",
            'context': {
                'device_id': f"device-{random.randint(1, 5)}",
                'session_id': f"session-{random.randint(1, 100)}",
                'geo_location': {
                    'country': 'US',
                    'city': 'New York',
                    'latitude': 40.7128,
                    'longitude': -74.0060
                }
            }
        }
        
        data.append(event)
    
    return pd.DataFrame(data)

def train_models():
    """Train all ML models"""
    print("Generating sample training data...")
    training_data = generate_sample_data(1000)
    
    print("Training AccessTimeAnomalyDetector...")
    access_time_model = AccessTimeAnomalyDetector()
    access_time_model.train(training_data)
    access_time_model.save_model()
    print("AccessTimeAnomalyDetector trained and saved.")
    
    print("Training AuthBehaviorDetector...")
    auth_behavior_model = AuthBehaviorDetector()
    auth_behavior_model.train(training_data)
    auth_behavior_model.save_model()
    print("AuthBehaviorDetector trained and saved.")
    
    print("Training SessionAnomalyDetector...")
    session_anomaly_model = SessionAnomalyDetector()
    session_anomaly_model.train(training_data)
    session_anomaly_model.save_model()
    print("SessionAnomalyDetector trained and saved.")
    
    print("All models trained and saved successfully!")

if __name__ == "__main__":
    # Create models directory if it doesn't exist
    os.makedirs("models", exist_ok=True)
    
    train_models()
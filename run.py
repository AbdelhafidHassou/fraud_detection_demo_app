# run.py
from app import create_app
import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import logging
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_models_exist():
    """Check if trained models exist"""
    model_files = [
        "models/access_time_model.joblib",
        "models/auth_behavior_model.joblib", 
        "models/session_anomaly_model.joblib"
    ]
    
    return all(os.path.exists(f) for f in model_files)

def generate_sample_data(num_samples=1000):
    """Generate sample data for training"""
    logger.info(f"Generating {num_samples} samples of training data...")
    
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
            # Keep as datetime object instead of converting to int
            'timestamp': timestamp,  # Changed from int(timestamp.timestamp())
            'is_anomaly': is_anomaly,
            'ip_address': f"192.168.1.{random.randint(1, 255)}",
            'context': {
                'device_id': f"device-{random.randint(1, 5)}",
                'session_id': f"session-{random.randint(1, 100)}",
                'endpoint': random.choice(['login', 'dashboard', 'profile', 'settings']),
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
    """Train all ML models with sample data"""
    logger.info("First run detected - training models with sample data...")
    
    # Import models here to avoid circular imports
    try:
        from ml.models.access_time_model import AccessTimeAnomalyDetector
        from ml.models.auth_behavior_model import AuthBehaviorDetector
        from ml.models.session_anomaly_model import SessionAnomalyDetector
    except ImportError as e:
        logger.error(f"Failed to import ML models: {str(e)}")
        logger.error("Aborting model training. Please ensure all dependencies are installed.")
        return False
    
    # Create models directory if it doesn't exist
    os.makedirs("models", exist_ok=True)
    
    try:
        # Generate sample data
        training_data = generate_sample_data(1000)
        
        # Train access time model
        logger.info("Training AccessTimeAnomalyDetector...")
        access_time_model = AccessTimeAnomalyDetector()
        access_time_model.train(training_data)
        access_time_model.save_model()
        
        # Train auth behavior model
        logger.info("Training AuthBehaviorDetector...")
        auth_behavior_model = AuthBehaviorDetector()
        auth_behavior_model.train(training_data)
        auth_behavior_model.save_model()
        
        # Train session anomaly model
        logger.info("Training SessionAnomalyDetector...")
        session_anomaly_model = SessionAnomalyDetector()
        session_anomaly_model.train(training_data)
        session_anomaly_model.save_model()
        
        logger.info("All models trained and saved successfully!")
        return True
    except Exception as e:
        logger.error(f"Error during model training: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False

# Main application
if __name__ == '__main__':
    # Check if models exist, train if not
    if not check_models_exist():
        train_models()
        # Small delay to ensure files are completely written
        time.sleep(1)
    else:
        logger.info("Trained models found - skipping training step")
    
    # Create and run app
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
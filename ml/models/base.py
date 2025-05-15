# ml/models/base.py
from abc import ABC, abstractmethod
import numpy as np
import pandas as pd
from typing import Dict, Any, List
import joblib
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class BaseAnomalyDetector(ABC):
    """Base class for all anomaly detection models"""
    
    def __init__(self, model_name: str, model_path: str = "models"):
        self.model_name = model_name
        self.model_path = model_path
        self.model = None
        self.feature_names: List[str] = []
        self.is_trained = False
        
    @abstractmethod
    def extract_features(self, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]] = None) -> np.ndarray:
        """Extract features from event data"""
        pass
    
    @abstractmethod
    def train(self, training_data: pd.DataFrame):
        """Train the model on historical data"""
        pass
    
    def predict(self, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]] = None) -> float:
        """Predict anomaly score for an event"""
        if not self.is_trained:
            raise ValueError(f"Model {self.model_name} is not trained")
        
        features = self.extract_features(event_data, historical_data)
        
        # Ensure features is 2D array
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Get anomaly score
        if hasattr(self.model, 'decision_function'):
            # For models like Isolation Forest, One-Class SVM
            anomaly_score = self.model.decision_function(features)[0]
            # Convert to probability-like score (0-1)
            score = 1 / (1 + np.exp(-anomaly_score))
        else:
            # For models like Random Forest
            score = self.model.predict_proba(features)[0][1]
        
        # Ensure score is between 0 and 1
        return np.clip(score, 0, 1)
    
    def save_model(self):
        """Save trained model to disk"""
        if not self.is_trained:
            raise ValueError(f"Cannot save untrained model {self.model_name}")
        
        model_file = os.path.join(self.model_path, f"{self.model_name}.joblib")
        os.makedirs(self.model_path, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        joblib.dump(model_data, model_file)
        logger.info(f"Model {self.model_name} saved to {model_file}")
    
    def load_model(self):
        """Load trained model from disk"""
        model_file = os.path.join(self.model_path, f"{self.model_name}.joblib")
        
        if not os.path.exists(model_file):
            raise FileNotFoundError(f"Model file {model_file} not found")
        
        model_data = joblib.load(model_file)
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']
        
        logger.info(f"Model {self.model_name} loaded from {model_file}")
        
# Add this to ml/models/base.py
def convert_to_datetime(timestamp):
    """Convert various timestamp formats to datetime object"""
    if isinstance(timestamp, datetime):
        return timestamp
    elif isinstance(timestamp, int) or isinstance(timestamp, float):
        return datetime.fromtimestamp(timestamp)
    elif isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp)
        except ValueError:
            try:
                return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                # Try other common formats
                for fmt in ["%Y-%m-%d", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y"]:
                    try:
                        return datetime.strptime(timestamp, fmt)
                    except ValueError:
                        continue
    
    # Default to current time if all parsing fails
    logger.warning(f"Could not parse timestamp: {timestamp}, using current time")
    return datetime.now()

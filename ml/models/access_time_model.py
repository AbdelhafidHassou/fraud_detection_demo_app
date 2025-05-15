# ml/models/access_time_model.py
from sklearn.ensemble import IsolationForest
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging

from ml.models.base import BaseAnomalyDetector
from core.config import settings
from .base import BaseAnomalyDetector, convert_to_datetime

logger = logging.getLogger(__name__)


class AccessTimeAnomalyDetector(BaseAnomalyDetector):
    """Detects anomalies in access patterns based on time of day and day of week"""
    
    def __init__(self, model_path: str = "models"):
        super().__init__("access_time_model", model_path)
        self.model = IsolationForest(
            contamination=0.05,  # Expected proportion of outliers
            random_state=42,
            n_estimators=100
        )
        self.feature_names = [
            'hour', 'day_of_week', 'minute', 'is_weekend',
            'hour_sin', 'hour_cos', 'day_sin', 'day_cos',
            'time_since_last_access', 'access_frequency_last_hour',
            'access_frequency_last_day', 'avg_access_hour',
            'std_access_hour', 'usual_access_window'
        ]
    
    def extract_features(self, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]] = None) -> np.ndarray:
        """Extract time-based features from event data"""
        # Then in your extract_features methods:
        timestamp = convert_to_datetime(event_data.get('timestamp'))
        
        timestamp = event_data.get('timestamp')
        if isinstance(timestamp, int):
            # Unix timestamp (seconds since epoch)
            timestamp = datetime.fromtimestamp(timestamp)
        elif isinstance(timestamp, str):
            try:
                # ISO format string
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                # Try parsing as regular date string
                timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        elif not isinstance(timestamp, datetime):
            # Default to current time if invalid format
            logger.warning(f"Invalid timestamp format: {timestamp}, using current time")
            timestamp = datetime.now()
        
        features = {}
        
        # Basic time features
        features['hour'] = timestamp.hour
        features['day_of_week'] = timestamp.weekday()
        features['minute'] = timestamp.minute
        features['is_weekend'] = 1 if timestamp.weekday() >= 5 else 0
        
        # Cyclical encoding for hour and day
        features['hour_sin'] = np.sin(2 * np.pi * timestamp.hour / 24)
        features['hour_cos'] = np.cos(2 * np.pi * timestamp.hour / 24)
        features['day_sin'] = np.sin(2 * np.pi * timestamp.weekday() / 7)
        features['day_cos'] = np.cos(2 * np.pi * timestamp.weekday() / 7)
        
        # Historical pattern features
        if historical_data:
            self._extract_historical_features(features, timestamp, historical_data)
        else:
            # Default values when no historical data
            features['time_since_last_access'] = 0
            features['access_frequency_last_hour'] = 0
            features['access_frequency_last_day'] = 0
            features['avg_access_hour'] = 12  # Noon as default
            features['std_access_hour'] = 6   # 6 hours standard deviation
            features['usual_access_window'] = 0
        
        # Convert to numpy array in the correct order
        return np.array([features[name] for name in self.feature_names])
    
    def _extract_historical_features(self, features: Dict, current_time: datetime, historical_data: List[Dict[str, Any]]):
        """Extract features based on historical access patterns"""
        # Convert historical data to timestamps
        historical_times = []
        for event in historical_data:
            ts = event.get('timestamp')
            ts_datetime = convert_to_datetime(ts)
            historical_times.append(ts_datetime)
        
        if not historical_times:
            features.update({
                'time_since_last_access': 24,  # Default to 24 hours
                'access_frequency_last_hour': 0,
                'access_frequency_last_day': 0,
                'avg_access_hour': 12,
                'std_access_hour': 6,
                'usual_access_window': 0
            })
            return
        
        # Sort historical times
        historical_times.sort()
        
        # Time since last access (in hours)
        last_access = historical_times[-1] if historical_times else current_time
        features['time_since_last_access'] = (current_time - last_access).total_seconds() / 3600
        
        # Access frequency in last hour
        one_hour_ago = current_time - timedelta(hours=1)
        features['access_frequency_last_hour'] = sum(1 for t in historical_times if t >= one_hour_ago)
        
        # Access frequency in last day
        one_day_ago = current_time - timedelta(days=1)
        features['access_frequency_last_day'] = sum(1 for t in historical_times if t >= one_day_ago)
        
        # Average and standard deviation of access hours
        access_hours = [t.hour for t in historical_times]
        features['avg_access_hour'] = np.mean(access_hours) if access_hours else 12
        features['std_access_hour'] = np.std(access_hours) if len(access_hours) > 1 else 6
        
        # Check if current access is within usual time window
        if access_hours:
            min_hour = min(access_hours)
            max_hour = max(access_hours)
            features['usual_access_window'] = 1 if min_hour <= current_time.hour <= max_hour else 0
        else:
            features['usual_access_window'] = 1
            
        # Ensure all datetime comparisons use datetime objects
        if historical_times:
            time_diff = (current_time - historical_times[-1]).total_seconds() / 3600
            features['time_since_last_access'] = time_diff
        else:
            features['time_since_last_access'] = 24  # Default value
    
    def train(self, training_data: pd.DataFrame):
        """Train the Isolation Forest model"""
        logger.info(f"Training {self.model_name} with {len(training_data)} samples")
        
        # Extract features for all training data
        features_list = []
        
        for idx, row in training_data.iterrows():
            # Get historical data for this user
            user_history = training_data[
                (training_data['user_id'] == row['user_id']) & 
                (training_data['timestamp'] < row['timestamp'])
            ].to_dict('records')
            
            features = self.extract_features(row.to_dict(), user_history)
            features_list.append(features)
        
        X = np.array(features_list)
        
        # Train the model
        self.model.fit(X)
        self.is_trained = True
        
        logger.info(f"Training completed for {self.model_name}")

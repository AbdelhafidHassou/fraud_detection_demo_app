import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import logging
from datetime import datetime, timedelta
import time
from app.database import Database

logger = logging.getLogger(__name__)

class MLAccessTimeAnalyzer:
    """
    Machine Learning model for detecting anomalies in user access times.
    Uses Isolation Forest algorithm to identify unusual login patterns.
    """
    
    def __init__(self, model_path=None):
        """
        Initialize the Access Time Analyzer with an existing model or create a new one.
        
        Args:
            model_path (str): Path to saved model file (optional)
        """
        self.model = None
        self.scaler = StandardScaler()
        self.contamination = 0.05  # Expected proportion of anomalies
        self.min_samples = 10      # Minimum number of samples needed to train
        self.db = Database()
        
        if model_path and os.path.exists(model_path):
            self._load_model(model_path)
            logger.info(f"Loaded Access Time model from {model_path}")
        else:
            logger.info("No existing Access Time model found, will train new model when data available")
    
    def _extract_features(self, timestamp):
        """
        Extract time-based features from timestamp
        
        Args:
            timestamp (int or datetime): Login timestamp
            
        Returns:
            dict: Dictionary of features
        """
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(timestamp)
        else:
            dt = timestamp
            
        # Basic time features
        features = {
            'hour': dt.hour,
            'minute': dt.minute,
            'day_of_week': dt.weekday(),
            'month': dt.month,
            'day_of_month': dt.day,
            'is_weekend': 1 if dt.weekday() >= 5 else 0,
            'is_business_hours': 1 if 9 <= dt.hour < 17 else 0,
            'is_evening': 1 if 17 <= dt.hour < 22 else 0,
            'is_night': 1 if (dt.hour >= 22 or dt.hour < 6) else 0,
            'quarter_of_day': dt.hour // 6  # 0-3: night, morning, afternoon, evening
        }
        
        # Cyclic encoding for hour and day of week to capture periodicity
        features['hour_sin'] = np.sin(2 * np.pi * dt.hour / 24)
        features['hour_cos'] = np.cos(2 * np.pi * dt.hour / 24)
        features['day_of_week_sin'] = np.sin(2 * np.pi * dt.weekday() / 7)
        features['day_of_week_cos'] = np.cos(2 * np.pi * dt.weekday() / 7)
        
        return features
    
    def train(self, login_data, save_path=None):
        """
        Train the model using historical login data
        
        Args:
            login_data (list): List of login timestamps
            save_path (str): Path to save the trained model (optional)
            
        Returns:
            bool: True if training was successful
        """
        if len(login_data) < self.min_samples:
            logger.warning(f"Not enough data to train model. Need at least {self.min_samples} samples.")
            return False
        
        # Extract features for each login timestamp
        features_list = []
        for timestamp in login_data:
            features = self._extract_features(timestamp)
            features_list.append(list(features.values()))
        
        # Convert to numpy array
        X = np.array(features_list)
        
        # Scale the features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest model
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto'
        )
        self.model.fit(X_scaled)
        
        # Save the model if path is provided
        if save_path:
            self._save_model(save_path)
            
        logger.info(f"Successfully trained access time model with {len(login_data)} samples")
        return True
    
    def predict(self, timestamp):
        """
        Predict anomaly score for a login timestamp
        
        Args:
            timestamp (int or datetime): Login timestamp
            
        Returns:
            float: Anomaly score (0-1, higher means more anomalous)
            
        Note: Returns 0.5 (medium risk) if model is not trained
        """
        if self.model is None:
            logger.warning("Model not trained, returning default score")
            return 0.5
        
        # Extract features
        features = self._extract_features(timestamp)
        X = np.array(list(features.values())).reshape(1, -1)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score
        raw_score = -self.model.score_samples(X_scaled)[0]
        
        # Normalize score to 0-1 range
        normalized_score = min(max(raw_score / 0.5, 0), 1)
        
        return normalized_score
    
    def analyze(self, user_id, timestamp=None, user_history=None):
        """
        Analyze a login timestamp for anomalies
        
        Args:
            user_id (str): User identifier
            timestamp (int): Login timestamp (defaults to current time)
            user_history (list): Optional list of previous login timestamps
            
        Returns:
            dict: Analysis results including risk score
        """
        try:
            # Default to current time if not provided
            if timestamp is None:
                timestamp = int(time.time())
            
            # If user history is not provided, get it from the database
            if user_history is None:
                login_records = self.db.get_login_history(user_id)
                user_history = [record['timestamp'] for record in login_records]
            
            # If user history is provided and model not trained yet, train it
            if user_history and len(user_history) >= self.min_samples and self.model is None:
                # Create models directory if it doesn't exist
                model_dir = os.path.join('data', 'models')
                os.makedirs(model_dir, exist_ok=True)
                
                # Train the model
                model_path = os.path.join(model_dir, f"access_time_{user_id}.joblib")
                self.train(user_history, save_path=model_path)
            
            # Get anomaly score
            anomaly_score = self.predict(timestamp)
            
            # Convert to risk score (0-100)
            risk_score = self._calculate_risk_score(anomaly_score)
            
            # Get feature importance
            feature_importance = self._get_feature_importance(timestamp) if self.model else None
            
            # Determine status
            if risk_score > 80:
                status = 'high_anomaly'
                message = 'Login time highly unusual for this user'
            elif risk_score > 50:
                status = 'medium_anomaly'
                message = 'Login time somewhat unusual for this user'
            else:
                status = 'normal'
                message = 'Login time consistent with historical patterns'
            
            # Return results
            result = {
                'risk_score': risk_score,
                'status': status,
                'message': message,
                'anomaly_score': round(anomaly_score, 4),
                'feature_importance': feature_importance,
                'current_time': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Store current login for future analysis
            self._store_login(user_id, timestamp)
            
            return result
        
        except Exception as e:
            logger.error(f"Error in ML access time analysis: {str(e)}")
            return {
                'risk_score': 50,
                'status': 'error',
                'message': f"Error in access time analysis: {str(e)}"
            }
    
    def _calculate_risk_score(self, anomaly_score):
        """Calculate risk score based on anomaly score"""
        # Threshold-based conversion to risk score
        if anomaly_score < 0.3:
            return 0
        elif anomaly_score < 0.5:
            return int((anomaly_score - 0.3) / 0.2 * 50)
        else:
            return int(50 + (anomaly_score - 0.5) / 0.5 * 50)
    
    def _get_feature_importance(self, timestamp):
        """
        Calculate feature importance to explain the prediction
        This is a simplified version that identifies the most anomalous features
        
        Args:
            timestamp (int): Login timestamp
            
        Returns:
            dict: Feature importance scores
        """
        features = self._extract_features(timestamp)
        feature_names = list(features.keys())
        X = np.array(list(features.values())).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        # For each feature, calculate how much it contributes to the anomaly
        importance = {}
        for i, feature_name in enumerate(feature_names):
            # Create a modified version with this feature set to median
            X_modified = X_scaled.copy()
            X_modified[0, i] = 0  # Assuming scaled data has 0 mean
            
            # Calculate how much the score changes when this feature is "normalized"
            original_score = -self.model.score_samples(X_scaled)[0]
            modified_score = -self.model.score_samples(X_modified)[0]
            
            # The importance is how much the anomaly score decreases when feature is normalized
            importance[feature_name] = original_score - modified_score
        
        # Sort by absolute importance and take top 3
        sorted_importance = sorted(importance.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
        return {k: round(v, 4) for k, v in sorted_importance}
    
    def _save_model(self, path):
        """Save the model to disk"""
        if self.model is None:
            logger.warning("No model to save")
            return
        
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'metadata': {
                    'timestamp': time.time(),
                    'contamination': self.contamination
                }
            }
            joblib.dump(model_data, path)
            logger.info(f"Saved model to {path}")
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
    
    def _load_model(self, path):
        """Load the model from disk"""
        try:
            model_data = joblib.load(path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.contamination = model_data['metadata']['contamination']
            logger.info(f"Loaded model from {path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False
            
    def _store_login(self, user_id, timestamp):
        """
        Store login information for future training
        Note: In this implementation, we rely on Database.store_login which 
        is already called elsewhere in the system.
        """
        pass

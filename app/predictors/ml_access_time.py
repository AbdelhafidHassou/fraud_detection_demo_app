# app/predictors/ml_access_time.py
import logging
import time
from datetime import datetime
from ml.models.access_time_model import AccessTimeAnomalyDetector
from app.database import Database
from ml.models.base import convert_to_datetime

logger = logging.getLogger(__name__)

class MLAccessTimeAnalyzer:
    """
    Wrapper for AccessTimeAnomalyDetector ML model.
    Analyzes access times to detect anomalies.
    """
    
    def __init__(self):
        self.db = Database()
        self.model = AccessTimeAnomalyDetector()
        
        # Try to load trained model, otherwise use untrained model
        try:
            self.model.load_model()
            logger.info("Loaded trained AccessTimeAnomalyDetector model")
        except FileNotFoundError:
            logger.warning("No trained model found for AccessTimeAnomalyDetector")
        
        logger.info("MLAccessTimeAnalyzer initialized")
    
    def analyze(self, user_id, timestamp=None):
        """
        Analyze a login timestamp for time-based anomalies
        
        Args:
            user_id (str): User identifier
            timestamp (int): Login timestamp (defaults to current time)
            
        Returns:
            dict: Analysis results including anomaly score and time features
        """
        try:
            # Default to current time if not provided
            if timestamp is None:
                timestamp = int(time.time())
            
            # Convert timestamp to datetime using utility function
            login_time = convert_to_datetime(timestamp)
            
            # Get user's login history
            login_history = self.db.get_login_history(user_id)
            
            # Prepare event data and historical data for the model
            event_data = {
                'user_id': user_id,
                'timestamp': timestamp
            }
            
            # Format historical data for the model
            historical_data = [
                {'user_id': user_id, 'timestamp': record['timestamp']} 
                for record in login_history
            ]
            
            # If model is trained, predict anomaly score
            if self.model.is_trained:
                anomaly_score = self.model.predict(event_data, historical_data)
                
                # Anomaly scores are typically between 0-1 where higher values indicate anomalies
                # Scale to 0-100 risk score with proper thresholding
                if anomaly_score < 0.3:  # Low anomaly
                    risk_score = int(anomaly_score * 100 / 3)  # 0-33
                elif anomaly_score < 0.7:  # Medium anomaly
                    risk_score = int(33 + (anomaly_score - 0.3) * 100 / 0.4)  # 33-66
                else:  # High anomaly
                    risk_score = int(66 + (anomaly_score - 0.7) * 100 / 0.3)  # 66-100
                
                # Determine status based on risk score
                if risk_score > 75:
                    status = 'high_anomaly'
                    message = 'Login time highly unusual for this user'
                elif risk_score > 40:
                    status = 'medium_anomaly'
                    message = 'Login time somewhat unusual for this user'
                else:
                    status = 'normal'
                    message = 'Login time consistent with historical patterns'
            
            # Store current login for future analysis
            self.db.store_login({
                'user_id': user_id,
                'timestamp': timestamp
            })
            
            # Prepare result
            result = {
                'risk_score': risk_score,
                'status': status,
                'message': message
            }
            
            # Log high-risk time anomalies
            if risk_score > 70:
                logger.warning(f"High-risk time anomaly detected for user {user_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in access time analysis: {str(e)}")
            return {
                'risk_score': 50,  # Medium risk due to error
                'status': 'error',
                'message': f"Error in access time analysis: {str(e)}"
            }
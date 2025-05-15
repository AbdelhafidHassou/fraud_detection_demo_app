import logging
import time
from ml.models.auth_behavior_model import AuthBehaviorDetector
from app.database import Database

logger = logging.getLogger(__name__)

class MLAuthBehaviorAnalyzer:
    """
    Wrapper for AuthBehaviorDetector ML model.
    Detects anomalies in authentication behavior patterns.
    """
    
    def __init__(self):
        self.db = Database()
        self.model = AuthBehaviorDetector()
        
        # Try to load trained model, otherwise use untrained model
        try:
            self.model.load_model()
            logger.info("Loaded trained AuthBehaviorDetector model")
        except FileNotFoundError:
            logger.warning("No trained model found for AuthBehaviorDetector")
        
        logger.info("MLAuthBehaviorAnalyzer initialized")
    
    def analyze(self, user_id, ip_address, timestamp=None):
        """
        Analyze authentication behavior for anomalies
        
        Args:
            user_id (str): User identifier
            ip_address (str): IP address
            timestamp (int): Event timestamp (defaults to current time)
            
        Returns:
            dict: Analysis results including risk score and flags
        """
        try:
            # Default to current time if not provided
            if timestamp is None:
                timestamp = int(time.time())
            
            # Get user's authentication history
            auth_history = self.db.get_auth_history(user_id)
            
            # Get relevant context data
            geo_location = self.db.get_ip_location(ip_address)
            device_data = self.db.get_recent_device_data(user_id)
            
            # Prepare event data
            event_data = {
                'user_id': user_id,
                'timestamp': timestamp,
                'context': {
                    'ip_address': ip_address,
                    'geo_location': geo_location,
                    'device_id': device_data.get('device_id') if device_data else None
                }
            }
            
            # If model is trained, predict anomaly score
            if self.model.is_trained and len(auth_history) > 0:
                anomaly_score = self.model.predict(event_data, auth_history)
                
                # Calculate risk score (0-100)
                risk_score = int(anomaly_score * 100)
                
                # Determine status based on risk score
                if risk_score > 80:
                    status = 'high_risk_behavior'
                    message = 'Authentication exhibits highly suspicious behavior'
                elif risk_score > 50:
                    status = 'suspicious_behavior'
                    message = 'Authentication exhibits potentially suspicious behavior'
                else:
                    status = 'normal_behavior'
                    message = 'Authentication behavior appears normal'
            else:
                # Not enough data for prediction
                risk_score = 0
                status = 'insufficient_data'
                message = 'Not enough data for auth behavior analysis'
            
            # Store event for future analysis
            self.db.store_auth_event(event_data)
            
            # Prepare result
            result = {
                'risk_score': risk_score,
                'status': status,
                'message': message
            }
            
            # Log high-risk behavior
            if risk_score > 70:
                logger.warning(f"High-risk auth behavior detected for user {user_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in auth behavior analysis: {str(e)}")
            return {
                'risk_score': 50,  # Medium risk due to error
                'status': 'error',
                'message': f"Error in auth behavior analysis: {str(e)}"
            }
import logging
import time
from ml.models.session_anomaly_model import SessionAnomalyDetector
from app.database import Database

logger = logging.getLogger(__name__)

class MLSessionAnomalyDetector:
    """
    Wrapper for SessionAnomalyDetector ML model.
    Detects anomalies in user session behavior.
    """
    
    def __init__(self):
        self.db = Database()
        self.model = SessionAnomalyDetector()
        
        # Try to load trained model, otherwise use untrained model
        try:
            self.model.load_model()
            logger.info("Loaded trained SessionAnomalyDetector model")
        except FileNotFoundError:
            logger.warning("No trained model found for SessionAnomalyDetector")
        
        logger.info("MLSessionAnomalyDetector initialized")
    
    def detect(self, user_id, session_events):
        """
        Detect anomalies in session behavior
        
        Args:
            user_id (str): User identifier
            session_events (list): List of session events
                Each event should have 'type', 'timestamp', and optional 'metadata'
            
        Returns:
            dict: Detection results including anomaly score and flags
        """
        try:
            # Validate input
            if not session_events or len(session_events) < 2:
                return {
                    'risk_score': 0,
                    'status': 'insufficient_data',
                    'message': 'Need at least 2 events for session analysis',
                    'anomaly_score': 0
                }
            
            # Sort events by timestamp if not already sorted
            sorted_events = sorted(session_events, key=lambda x: x.get('timestamp', 0))
            
            # Get historical session data
            historical_sessions = self.db.get_historical_sessions(user_id)
            
            # Create current session data
            current_session = {
                'user_id': user_id,
                'session_id': sorted_events[0].get('session_id', str(time.time())),
                'timestamp': sorted_events[-1].get('timestamp', int(time.time())),
                'context': {
                    'session_id': sorted_events[0].get('session_id', str(time.time())),
                }
            }
            
            # If model is trained, predict anomaly score
            if self.model.is_trained and len(historical_sessions) > 0:
                anomaly_score = self.model.predict(current_session, historical_sessions)
                
                # Calculate risk score (0-100)
                risk_score = int(anomaly_score * 100)
                
                # Determine status based on risk score
                if risk_score > 80:
                    status = 'high_risk_behavior'
                    message = 'Session exhibits highly suspicious behavior'
                elif risk_score > 50:
                    status = 'suspicious_behavior'
                    message = 'Session contains potentially suspicious behavior'
                else:
                    status = 'normal_behavior'
                    message = 'Session behavior appears normal'
            else:
                # Not enough data for prediction
                risk_score = 0
                status = 'insufficient_data'
                message = 'Not enough data for session analysis'
            
            # Store session for future analysis
            self.db.store_session(user_id, sorted_events)
            
            # Prepare result
            result = {
                'risk_score': risk_score,
                'status': status,
                'message': message,
                'anomaly_score': anomaly_score if 'anomaly_score' in locals() else 0,
                'events_analyzed': len(sorted_events)
            }
            
            # Log high-risk sessions
            if risk_score > 70:
                logger.warning(f"High-risk session behavior detected for user {user_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in session anomaly detection: {str(e)}")
            return {
                'risk_score': 50,  # Medium risk due to error
                'status': 'error',
                'message': f"Error in session anomaly detection: {str(e)}"
            }
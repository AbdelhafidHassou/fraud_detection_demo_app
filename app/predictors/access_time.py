import logging
import time
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
from app.database import Database

logger = logging.getLogger(__name__)

class AccessTimeAnalyzer:
    """
    Analyzes user access time patterns to detect anomalies.
    Uses Isolation Forest algorithm for anomaly detection.
    """
    
    def __init__(self):
        self.db = Database()
        
        # Configuration
        self.min_history_points = 5  # Minimum number of logins needed for reliable analysis
        self.contamination = 0.1     # Expected proportion of anomalies
        
        logger.info("AccessTimeAnalyzer initialized")
    
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
            
            # Convert timestamp to datetime for easier feature extraction
            login_time = datetime.fromtimestamp(timestamp)
            
            # Extract time features for current login
            current_features = self._extract_time_features(login_time)
            
            # Get user's login history
            login_history = self._get_login_history(user_id)
            
            # If not enough history, can't perform anomaly detection
            if len(login_history) < self.min_history_points:
                logger.info(f"Not enough login history for user {user_id} ({len(login_history)} points)")
                
                # Store current login for future analysis
                self._store_time_data(user_id, timestamp)
                
                return {
                    'risk_score': 0,
                    'status': 'insufficient_history',
                    'anomaly_score': 0,
                    'message': f"Need at least {self.min_history_points} logins for pattern analysis",
                    'time_features': current_features
                }
            
            # Extract features from historical logins
            historical_features = []
            for login in login_history:
                login_dt = datetime.fromtimestamp(login)
                features = self._extract_time_features(login_dt)
                historical_features.append(list(features.values()))
            
            # Convert to numpy array
            X = np.array(historical_features)
            
            # Train isolation forest model
            model = IsolationForest(contamination=self.contamination, random_state=42)
            model.fit(X)
            
            # Predict anomaly for current login
            current_features_array = np.array([list(current_features.values())])
            anomaly_score = -model.score_samples(current_features_array)[0]  # Negated to make higher = more anomalous
            
            # Normalize score to 0-1 range
            normalized_score = min(max(anomaly_score / 0.5, 0), 1)
            
            # Calculate risk score based on anomaly score
            risk_score = self._calculate_risk_score(normalized_score)
            
            # Determine anomaly status
            if risk_score > 70:
                status = 'high_anomaly'
                message = 'Login time highly unusual for this user'
            elif risk_score > 40:
                status = 'medium_anomaly'
                message = 'Login time somewhat unusual for this user'
            else:
                status = 'normal'
                message = 'Login time consistent with historical patterns'
            
            # Store current login for future analysis
            self._store_time_data(user_id, timestamp)
            
            # Check against specific suspicious patterns
            specific_patterns = self._check_specific_patterns(current_features, login_history)
            
            # If specific patterns found, they override the anomaly detection
            if specific_patterns:
                status = specific_patterns['status']
                message = specific_patterns['message']
                risk_score = specific_patterns['risk_score']
            
            # Prepare result
            result = {
                'risk_score': risk_score,
                'status': status,
                'message': message,
                'anomaly_score': round(normalized_score, 4),
                'time_features': current_features
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
    
    def _extract_time_features(self, dt):
        """
        Extract time-based features from a datetime
        
        Args:
            dt (datetime): Datetime object
            
        Returns:
            dict: Time features
        """
        return {
            'hour': dt.hour,
            'minute': dt.minute / 60.0,  # Normalize to 0-1
            'day_of_week': dt.weekday(),
            'is_weekend': 1 if dt.weekday() >= 5 else 0,
            'is_business_hours': 1 if 9 <= dt.hour < 17 else 0,
            'day_of_month': dt.day / 31.0,  # Normalize to 0-1
            'month': dt.month / 12.0,  # Normalize to 0-1
            'quarter_of_day': dt.hour // 6  # 0-3: night, morning, afternoon, evening
        }
    
    def _get_login_history(self, user_id):
        """
        Get login timestamp history for a user
        
        Args:
            user_id (str): User identifier
            
        Returns:
            list: List of login timestamps
        """
        # In a real implementation, this would fetch from your database
        login_records = self.db.get_login_history(user_id)
        
        # Extract timestamps
        return [record['timestamp'] for record in login_records]
    
    def _store_time_data(self, user_id, timestamp):
        """
        Store time data for future analysis.
        This is done in the database.py module when storing logins.
        """
        # No need to do anything here as the login is already stored
        pass
    
    def _calculate_risk_score(self, anomaly_score):
        """
        Calculate risk score based on anomaly score
        
        Args:
            anomaly_score (float): Normalized anomaly score (0-1)
            
        Returns:
            int: Risk score (0-100)
        """
        # Simple linear scaling with threshold
        if anomaly_score < 0.3:
            # Low anomaly scores are considered normal
            return 0
        
        # Scale from 0.3-1.0 to 0-100
        scaled_score = (anomaly_score - 0.3) / 0.7 * 100
        return min(100, max(0, int(scaled_score)))
    
    def _check_specific_patterns(self, current_features, login_history):
        """
        Check for specific suspicious patterns
        
        Args:
            current_features (dict): Time features of current login
            login_history (list): Historical login timestamps
            
        Returns:
            dict: Pattern details if found, None otherwise
        """
        # Convert login history to datetime objects
        history_dts = [datetime.fromtimestamp(ts) for ts in login_history]
        
        # Check for odd hours (2-5 AM local time) if this is not normal for the user
        odd_hours_count = sum(1 for dt in history_dts if 2 <= dt.hour < 5)
        odd_hours_ratio = odd_hours_count / len(history_dts)
        
        if 2 <= current_features['hour'] < 5 and odd_hours_ratio < 0.1:
            return {
                'status': 'odd_hours',
                'message': 'Login outside of user\'s normal hours (late night)',
                'risk_score': 60
            }
        
        # Check for weekend login if user never logs in on weekends
        weekend_count = sum(1 for dt in history_dts if dt.weekday() >= 5)
        weekend_ratio = weekend_count / len(history_dts)
        
        if current_features['is_weekend'] == 1 and weekend_ratio < 0.05:
            return {
                'status': 'unusual_day',
                'message': 'Login on weekend when user typically doesn\'t access',
                'risk_score': 70
            }
        
        # Check for first login in a long time
        if login_history:
            latest_history_ts = max(login_history)
            current_ts = time.mktime(datetime.now().timetuple())
            days_since_last_login = (current_ts - latest_history_ts) / (60 * 60 * 24)
            
            if days_since_last_login > 60:  # More than 60 days
                return {
                    'status': 'dormant_account',
                    'message': f'First login after {int(days_since_last_login)} days of inactivity',
                    'risk_score': 75
                }
        
        return None
# ml/models/auth_behavior_model.py
import time
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging
from collections import Counter

from ml.models.base import BaseAnomalyDetector
from core.config import settings

from .base import BaseAnomalyDetector, convert_to_datetime


logger = logging.getLogger(__name__)


class AuthBehaviorDetector(BaseAnomalyDetector):
    """Detects anomalies in authentication behavior patterns using Random Forest"""
    
    def __init__(self, model_path: str = "models"):
        super().__init__("auth_behavior_model", model_path)
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.feature_names = [
            'login_frequency_hour', 'login_frequency_day', 'login_frequency_week',
            'failed_attempts_ratio', 'success_rate_recent',
            'device_count', 'new_device_flag', 'device_switch_frequency',
            'location_count', 'new_location_flag', 'location_switch_frequency',
            'avg_time_between_logins', 'std_time_between_logins',
            'event_type_diversity', 'most_common_event_ratio',
            'is_typical_hour', 'is_typical_day',
            'unusual_pattern_score', 'velocity_score'
        ]
        
        # Statistical rules thresholds
        self.rules = {
            'max_failed_attempts': 5,
            'min_success_rate': 0.7,
            'max_new_locations_per_day': 3,
            'max_velocity_km_per_hour': 1000,
            'suspicious_countries': ['XX', 'YY'],  # Example suspicious countries
        }
    
    def extract_features(self, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]] = None) -> np.ndarray:
        """Extract authentication behavior features"""
        # Then in your extract_features methods:
        current_time = convert_to_datetime(event_data.get('timestamp'))
        
        features = {}
        current_time = event_data.get('timestamp')
        if isinstance(current_time, int):
            current_time = datetime.fromtimestamp(current_time)
        elif isinstance(current_time, str):
            current_time = datetime.fromisoformat(current_time)
        
        if not historical_data:
            # Default values when no historical data
            features.update({
                'login_frequency_hour': 0,
                'login_frequency_day': 0,
                'login_frequency_week': 0,
                'failed_attempts_ratio': 0,
                'success_rate_recent': 1.0,
                'device_count': 1,
                'new_device_flag': 1,
                'device_switch_frequency': 0,
                'location_count': 1,
                'new_location_flag': 1,
                'location_switch_frequency': 0,
                'avg_time_between_logins': 24,
                'std_time_between_logins': 12,
                'event_type_diversity': 1,
                'most_common_event_ratio': 1.0,
                'is_typical_hour': 1,
                'is_typical_day': 1,
                'unusual_pattern_score': 0,
                'velocity_score': 0
            })
        else:
            self._extract_frequency_features(features, current_time, historical_data)
            self._extract_device_features(features, event_data, historical_data)
            self._extract_location_features(features, event_data, historical_data)
            self._extract_temporal_features(features, current_time, historical_data)
            self._extract_behavior_patterns(features, event_data, historical_data)
            self._calculate_risk_scores(features, event_data, historical_data)
        
        return np.array([features[name] for name in self.feature_names])
    
    def _extract_frequency_features(self, features: Dict, current_time: datetime, historical_data: List[Dict[str, Any]]):
        """Extract login frequency features"""
        if isinstance(current_time, int):
            current_time = datetime.fromtimestamp(current_time)
        elif isinstance(current_time, str):
            try:
                current_time = datetime.fromisoformat(current_time)
            except ValueError:
                current_time = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
                
        # Define time windows
        one_hour_ago = current_time - timedelta(hours=1)
        one_day_ago = current_time - timedelta(days=1)
        one_week_ago = current_time - timedelta(weeks=1)
        
        # Initialize counters
        hour_count = 0
        day_count = 0
        week_count = 0
        failed_count = 0
        success_count = 0
        
        hour_count = day_count = week_count = 0
        failed_count = success_count = 0
        
        for event in historical_data:
            event_time = convert_to_datetime(event.get('timestamp'))
            
            # Count events in different time windows
            if event_time >= one_hour_ago:
                hour_count += 1
            
            if event_time >= one_day_ago:
                day_count += 1
                
            if event_time >= one_week_ago:
                week_count += 1
            
            # Count success/failure events if status is available
            status = event.get('status')
            if status == 'success':
                success_count += 1
            elif status == 'failure':
                failed_count += 1
        
        features['login_frequency_hour'] = hour_count
        features['login_frequency_day'] = day_count
        features['login_frequency_week'] = week_count
        
        total_recent = success_count + failed_count
        features['failed_attempts_ratio'] = failed_count / total_recent if total_recent > 0 else 0
        features['success_rate_recent'] = success_count / total_recent if total_recent > 0 else 1
    
    def _extract_device_features(self, features: Dict, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]]):
        """Extract device-related features"""
        current_device = event_data.get('context', {}).get('device_id')
        
        # Get all historical devices
        historical_devices = []
        device_switches = 0
        last_device = None
        
        for event in sorted(historical_data, key=lambda x: x.get('timestamp')):
            device = event.get('context', {}).get('device_id')
            if device:
                historical_devices.append(device)
                if last_device and device != last_device:
                    device_switches += 1
                last_device = device
        
        unique_devices = set(historical_devices)
        features['device_count'] = len(unique_devices)
        features['new_device_flag'] = 1 if current_device not in unique_devices else 0
        features['device_switch_frequency'] = device_switches / len(historical_data) if historical_data else 0
    
    def _extract_location_features(self, features: Dict, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]]):
        """Extract location-related features"""
        current_location = event_data.get('context', {}).get('geo_location', {})
        current_country = current_location.get('country')
        current_city = current_location.get('city')
        
        # Get all historical locations
        historical_locations = []
        location_switches = 0
        last_location = None
        
        for event in sorted(historical_data, key=lambda x: x.get('timestamp')):
            location = event.get('context', {}).get('geo_location', {})
            if location:
                loc_key = f"{location.get('country')}_{location.get('city')}"
                historical_locations.append(loc_key)
                if last_location and loc_key != last_location:
                    location_switches += 1
                last_location = loc_key
        
        unique_locations = set(historical_locations)
        current_loc_key = f"{current_country}_{current_city}"
        
        features['location_count'] = len(unique_locations)
        features['new_location_flag'] = 1 if current_loc_key not in unique_locations else 0
        features['location_switch_frequency'] = location_switches / len(historical_data) if historical_data else 0
    
    def _extract_temporal_features(self, features: Dict, current_time: datetime, historical_data: List[Dict[str, Any]]):
        """Extract time-based patterns"""
        # Calculate time between logins
        login_times = []
        for event in historical_data:
            if event.get('event_type') == 'login':
                event_time = event.get('timestamp')
                if isinstance(event_time, str):
                    event_time = datetime.fromisoformat(event_time)
                login_times.append(event_time)
        
        login_times.sort()
        time_diffs = []
        
        for i in range(1, len(login_times)):
            diff = (login_times[i] - login_times[i-1]).total_seconds() / 3600  # hours
            time_diffs.append(diff)
        
        if time_diffs:
            features['avg_time_between_logins'] = np.mean(time_diffs)
            features['std_time_between_logins'] = np.std(time_diffs)
        else:
            features['avg_time_between_logins'] = 24
            features['std_time_between_logins'] = 12
    
    def _extract_behavior_patterns(self, features: Dict, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]]):
        """Extract behavioral patterns"""
        # Event type diversity
        event_types = [event.get('event_type') for event in historical_data]
        event_counter = Counter(event_types)
        
        features['event_type_diversity'] = len(event_counter)
        
        if event_types:
            most_common_count = event_counter.most_common(1)[0][1]
            features['most_common_event_ratio'] = most_common_count / len(event_types)
        else:
            features['most_common_event_ratio'] = 1.0
        
        # Get current time from event_data
        current_time = convert_to_datetime(event_data.get('timestamp'))
        
        # Typical access patterns
        access_hours = []
        access_days = []
        
        for event in historical_data:
            event_time = convert_to_datetime(event.get('timestamp'))
            access_hours.append(event_time.hour)
            access_days.append(event_time.weekday())
        
        if access_hours:
            typical_hours = set(h for h, count in Counter(access_hours).items() if count > len(access_hours) * 0.1)
            features['is_typical_hour'] = 1 if current_time.hour in typical_hours else 0
        else:
            features['is_typical_hour'] = 1
        
        if access_days:
            typical_days = set(d for d, count in Counter(access_days).items() if count > len(access_days) * 0.1)
            features['is_typical_day'] = 1 if current_time.weekday() in typical_days else 0
        else:
            features['is_typical_day'] = 1
    
    def _calculate_risk_scores(self, features: Dict, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]]):
        """Calculate specialized risk scores"""
        # Unusual pattern score
        unusual_score = 0
        
        # Check for rule violations
        if features['failed_attempts_ratio'] > 0.5:
            unusual_score += 0.3
        
        if features['new_device_flag'] and features['new_location_flag']:
            unusual_score += 0.4
        
        if not features['is_typical_hour'] or not features['is_typical_day']:
            unusual_score += 0.3
        
        features['unusual_pattern_score'] = min(unusual_score, 1.0)
        
        # Velocity score (impossible travel)
        features['velocity_score'] = self._calculate_velocity_score(event_data, historical_data)
    
    def _calculate_velocity_score(self, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]]) -> float:
        """Calculate velocity score based on travel speed between locations"""
        current_location = event_data.get('context', {}).get('geo_location', {})
        current_time = event_data.get('timestamp')
        
        if isinstance(current_time, str):
            current_time = datetime.fromisoformat(current_time)
        
        if not current_location or not historical_data:
            return 0.0
        
        # Find the most recent event with a different location
        for event in sorted(historical_data, key=lambda x: x.get('timestamp'), reverse=True):
            event_location = event.get('context', {}).get('geo_location', {})
            event_time = event.get('timestamp')
            
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time)
            
            if event_location and event_location != current_location:
                # Calculate time difference in hours
                time_diff = (current_time - event_time).total_seconds() / 3600
                
                if time_diff > 0:
                    # Simplified distance calculation (would use proper geo distance in production)
                    # Assuming 1000 km between different countries, 100 km between cities
                    if event_location.get('country') != current_location.get('country'):
                        distance = 1000
                    elif event_location.get('city') != current_location.get('city'):
                        distance = 100
                    else:
                        distance = 0
                    
                    velocity = distance / time_diff if time_diff > 0 else 0
                    
                    # Score based on velocity (impossible travel)
                    if velocity > self.rules['max_velocity_km_per_hour']:
                        return 1.0
                    else:
                        return velocity / self.rules['max_velocity_km_per_hour']
        
        return 0.0
    
    def predict(self, event_data, historical_data=None):
        if not self.is_trained or not historical_data:
            return 0.0  # Default score when not enough data
        
        # Normalize historical data timestamps
        normalized_history = []
        for item in historical_data:
            item_copy = item.copy()
            if 'timestamp' in item_copy:
                # Ensure timestamp is datetime
                item_copy['timestamp'] = convert_to_datetime(item_copy['timestamp'])
            normalized_history.append(item_copy)
    
    def train(self, training_data: pd.DataFrame):
        """Train the Random Forest model"""
        logger.info(f"Training {self.model_name} with {len(training_data)} samples")
        
        # Prepare training data
        X = []
        y = []
        
        # Group by user to create user sessions
        for user_id, user_data in training_data.groupby('user_id'):
            user_events = user_data.sort_values('timestamp').to_dict('records')
            
            for i, event in enumerate(user_events):
                # Use previous events as historical data
                historical = user_events[:i] if i > 0 else []
                
                features = self.extract_features(event, historical)
                X.append(features)
                y.append(1 if event.get('is_anomaly', False) else 0)
        
        X = np.array(X)
        y = np.array(y)
        
        # Train the model
        self.model.fit(X, y)
        self.is_trained = True
        
        logger.info(f"Training completed for {self.model_name}")
        logger.info(f"Feature importances: {dict(zip(self.feature_names, self.model.feature_importances_))}")
# ml/models/session_anomaly_model.py
import os
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging
import json

from ml.models.base import BaseAnomalyDetector
from core.config import settings
from .base import BaseAnomalyDetector, convert_to_datetime

logger = logging.getLogger(__name__)


class SessionAnomalyDetector(BaseAnomalyDetector):
    """Detects anomalies in session behavior using One-Class SVM"""
    
    def __init__(self, model_path: str = "models"):
        super().__init__("session_anomaly_model", model_path)
        self.model = OneClassSVM(
            kernel='rbf',
            nu=0.05,  # Expected proportion of outliers
            gamma='scale'
        )
        self.scaler = StandardScaler()
        self.feature_names = [
            'session_duration', 'request_count', 'unique_endpoints',
            'data_volume', 'error_rate', 'avg_response_time',
            'endpoint_diversity', 'request_velocity',
            'unusual_endpoint_access', 'time_between_requests_avg',
            'time_between_requests_std', 'session_start_hour',
            'concurrent_sessions', 'ip_changes',
            'user_agent_changes', 'privilege_escalation_attempts',
            'sensitive_data_access', 'bulk_data_requests',
            'api_version_switches', 'unusual_http_methods'
        ]
    
    def extract_features(self, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]] = None) -> np.ndarray:
        """Extract session behavior features"""
        current_time = convert_to_datetime(event_data.get('timestamp'))
        features = {}
        
        # Get session context
        session_id = event_data.get('context', {}).get('session_id')
        
        # Initialize features with defaults (directly using feature_names)
        features = {
            'session_duration': 0,
            'request_count': 1,
            'unique_endpoints': 1,
            'data_volume': 0,
            'error_rate': 0,
            'avg_response_time': 100,
            'endpoint_diversity': 1.0,
            'request_velocity': 0,
            'unusual_endpoint_access': 0,
            'time_between_requests_avg': 0,
            'time_between_requests_std': 0,
            'session_start_hour': current_time.hour,
            'concurrent_sessions': 1,
            'ip_changes': 0,
            'user_agent_changes': 0,
            'privilege_escalation_attempts': 0,
            'sensitive_data_access': 0,
            'bulk_data_requests': 0,
            'api_version_switches': 0,
            'unusual_http_methods': 0
        }
        
        if historical_data and session_id:
            # Extract features from session history
            session_events = [e for e in historical_data 
                            if e.get('context', {}).get('session_id') == session_id]
            
            # Extract features from data
            self._extract_session_metrics(features, current_time, session_events)
            self._extract_request_patterns(features, event_data, session_events)
            self._extract_security_features(features, event_data, session_events)
            self._extract_behavioral_anomalies(features, event_data, session_events, historical_data)
        
        return np.array([features[name] for name in self.feature_names])
    
    def _extract_session_metrics(self, features: Dict, current_time: datetime, session_events: List[Dict[str, Any]]):
        """Extract basic session metrics"""
        if not session_events:
            features.update({
                'session_duration': 0,
                'request_count': 1,
                'unique_endpoints': 1,
                'session_start_hour': current_time.hour
            })
            return
        
        # Session duration
        session_times = []
        for event in session_events:
            event_time = event.get('timestamp')
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time)
            session_times.append(event_time)
        
        session_start = min(session_times)
        session_duration = (current_time - session_start).total_seconds() / 60  # minutes
        
        features['session_duration'] = session_duration
        features['request_count'] = len(session_events) + 1  # +1 for current event
        features['session_start_hour'] = session_start.hour
        
        # Unique endpoints accessed
        endpoints = set()
        for event in session_events:
            endpoint = event.get('context', {}).get('endpoint', event.get('event_type', ''))
            endpoints.add(endpoint)
        
        features['unique_endpoints'] = len(endpoints)
        features['endpoint_diversity'] = len(endpoints) / (len(session_events) + 1) if session_events else 1
    
    def _extract_request_patterns(self, features: Dict, event_data: Dict[str, Any], session_events: List[Dict[str, Any]]):
        """Extract request pattern features"""
        # Time between requests
        request_times = []
        for event in session_events:
            event_time = convert_to_datetime(event.get('timestamp'))
            request_times.append(event_time)
        
        if len(request_times) > 1:
            request_times.sort()
            time_diffs = []
            for i in range(1, len(request_times)):
                diff = (request_times[i] - request_times[i-1]).total_seconds()
                time_diffs.append(diff)
            
            features['time_between_requests_avg'] = np.mean(time_diffs)
            features['time_between_requests_std'] = np.std(time_diffs)
            
            # Request velocity (requests per minute)
            total_time = (request_times[-1] - request_times[0]).total_seconds() / 60
            features['request_velocity'] = len(request_times) / total_time if total_time > 0 else 0
        else:
            features['time_between_requests_avg'] = 0
            features['time_between_requests_std'] = 0
            features['request_velocity'] = 0
        
        # Data volume and response times
        data_volumes = []
        response_times = []
        error_count = 0
        
        for event in session_events:
            # Simulated metrics (in real implementation, these would come from actual data)
            data_volume = event.get('context', {}).get('response_size', 1000)
            response_time = event.get('context', {}).get('response_time', 100)
            status_code = event.get('context', {}).get('status_code', 200)
            
            data_volumes.append(data_volume)
            response_times.append(response_time)
            
            if status_code >= 400:
                error_count += 1
        
        features['data_volume'] = sum(data_volumes)
        features['avg_response_time'] = np.mean(response_times) if response_times else 100
        features['error_rate'] = error_count / (len(session_events) + 1) if session_events else 0
    
    def _extract_security_features(self, features: Dict, event_data: Dict[str, Any], session_events: List[Dict[str, Any]]):
        """Extract security-related features"""
        # IP and User-Agent changes
        ips = set()
        user_agents = set()
        
        current_ip = event_data.get('context', {}).get('ip_address')
        current_ua = event_data.get('context', {}).get('user_agent')
        
        for event in session_events:
            ip = event.get('context', {}).get('ip_address')
            ua = event.get('context', {}).get('user_agent')
            if ip:
                ips.add(ip)
            if ua:
                user_agents.add(ua)
        
        features['ip_changes'] = len(ips) - 1 if current_ip in ips else len(ips)
        features['user_agent_changes'] = len(user_agents) - 1 if current_ua in user_agents else len(user_agents)
        
        # Security-sensitive actions
        privilege_escalations = 0
        sensitive_access = 0
        bulk_requests = 0
        
        sensitive_endpoints = ['/admin', '/users', '/config', '/export', '/download']
        bulk_endpoints = ['/bulk', '/export', '/report', '/download']
        
        for event in session_events:
            endpoint = event.get('context', {}).get('endpoint', '')
            event_type = event.get('event_type', '')
            
            if any(sensitive in endpoint for sensitive in sensitive_endpoints):
                sensitive_access += 1
            
            if any(bulk in endpoint for bulk in bulk_endpoints):
                bulk_requests += 1
            
            if event_type in ['role_change', 'permission_change', 'admin_access']:
                privilege_escalations += 1
        
        features['privilege_escalation_attempts'] = privilege_escalations
        features['sensitive_data_access'] = sensitive_access
        features['bulk_data_requests'] = bulk_requests
    
    def _extract_behavioral_anomalies(self, features: Dict, event_data: Dict[str, Any], 
                                    session_events: List[Dict[str, Any]], all_historical_data: List[Dict[str, Any]]):
        """Extract behavioral anomaly indicators"""
        # Unusual endpoint access (accessing rarely used endpoints)
        all_endpoints = []
        for event in all_historical_data:
            endpoint = event.get('context', {}).get('endpoint', event.get('event_type', ''))
            all_endpoints.append(endpoint)
        
        from collections import Counter
        endpoint_counts = Counter(all_endpoints)
        total_accesses = len(all_endpoints)
        
        current_endpoint = event_data.get('context', {}).get('endpoint', event_data.get('event_type', ''))
        if total_accesses > 0:
            endpoint_frequency = endpoint_counts[current_endpoint] / total_accesses
            features['unusual_endpoint_access'] = 1 if endpoint_frequency < 0.01 else 0
        else:
            features['unusual_endpoint_access'] = 0
        
        # API version switches
        api_versions = set()
        for event in session_events:
            api_version = event.get('context', {}).get('api_version', 'v1')
            api_versions.add(api_version)
        
        features['api_version_switches'] = len(api_versions) - 1 if api_versions else 0
        
        # Unusual HTTP methods
        unusual_methods = 0
        common_methods = ['GET', 'POST', 'PUT', 'DELETE']
        
        for event in session_events:
            method = event.get('context', {}).get('http_method', 'GET')
            if method not in common_methods:
                unusual_methods += 1
        
        features['unusual_http_methods'] = unusual_methods
        
        # Concurrent sessions (simplified)
        user_id = event_data.get('user_id')
        concurrent = 0
        
        for event in all_historical_data[-100:]:  # Check last 100 events
            if (event.get('user_id') == user_id and 
                event.get('context', {}).get('session_id') != event_data.get('context', {}).get('session_id')):
                event_time = event.get('timestamp')
                if isinstance(event_time, str):
                    event_time = datetime.fromisoformat(event_time)
                
                # Consider concurrent if within last hour
                if (datetime.utcnow() - event_time).total_seconds() < 3600:
                    concurrent += 1
        
        features['concurrent_sessions'] = concurrent
    
    def train(self, training_data: pd.DataFrame):
        """Train the One-Class SVM model"""
        logger.info(f"Training {self.model_name} with {len(training_data)} samples")
        
        # Prepare training data - use only normal sessions for One-Class SVM
        X_normal = []
        
        # Group by session to create session features
        # First, let's extract session_id properly
        def get_session_id(row):
            if isinstance(row.get('context'), dict):
                return row['context'].get('session_id')
            # Fallback to direct session_id column if exists
            return row.get('session_id')
        
        training_data['extracted_session_id'] = training_data.apply(get_session_id, axis=1)
        
        # Filter out anomalies and missing session IDs
        normal_data = training_data[
            (training_data['is_anomaly'] == False) & 
            (training_data['extracted_session_id'].notna())
        ]
        
        for session_id, session_data in normal_data.groupby('extracted_session_id'):
            session_events = session_data.sort_values('timestamp').to_dict('records')
            
            # Extract features for the last event in the session
            if session_events:
                last_event = session_events[-1]
                historical = session_events[:-1]
                
                # Make sure we have the current event in the right format
                if 'context' not in last_event and 'session_id' in last_event:
                    # Add session_id to context if it's missing
                    if isinstance(last_event.get('context'), dict):
                        last_event['context']['session_id'] = last_event['session_id']
                    else:
                        last_event['context'] = {'session_id': last_event['session_id']}
                
                features = self.extract_features(last_event, historical)
                X_normal.append(features)
        
        if not X_normal:
            logger.warning("No normal session data found for training")
            # Create dummy data to prevent errors
            dummy_features = np.zeros((10, len(self.feature_names)))
            X_normal = dummy_features
        
        X_normal = np.array(X_normal)
        
        # Fit the scaler and transform data
        X_scaled = self.scaler.fit_transform(X_normal)
        
        # Train the model on normal data only
        self.model.fit(X_scaled)
        self.is_trained = True
        
        logger.info(f"Training completed for {self.model_name}")
    
    def predict(self, event_data: Dict[str, Any], historical_data: List[Dict[str, Any]] = None) -> float:
        """Override predict to handle scaling"""
        if not self.is_trained:
            raise ValueError(f"Model {self.model_name} is not trained")
        
        features = self.extract_features(event_data, historical_data)
        
        # Ensure features is 2D array
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Get anomaly score
        anomaly_score = self.model.decision_function(features_scaled)[0]
        
        # Convert to probability-like score (0-1)
        # For One-Class SVM, negative scores indicate anomalies
        score = 1 / (1 + np.exp(anomaly_score))  # Inverted because negative = anomaly
        
        return np.clip(score, 0, 1)
    
    def save_model(self):
        """Override to save scaler as well"""
        if not self.is_trained:
            raise ValueError(f"Cannot save untrained model {self.model_name}")
        
        model_file = os.path.join(self.model_path, f"{self.model_name}.joblib")
        os.makedirs(self.model_path, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        import joblib
        joblib.dump(model_data, model_file)
        logger.info(f"Model {self.model_name} saved to {model_file}")
    
    def load_model(self):
        """Override to load scaler as well"""
        import os
        import joblib
        
        model_file = os.path.join(self.model_path, f"{self.model_name}.joblib")
        
        if not os.path.exists(model_file):
            raise FileNotFoundError(f"Model file {model_file} not found")
        
        model_data = joblib.load(model_file)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']
        
        logger.info(f"Model {self.model_name} loaded from {model_file}")
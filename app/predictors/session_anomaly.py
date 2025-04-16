import logging
import json
import time
import numpy as np
from app.database import Database

logger = logging.getLogger(__name__)

class SessionAnomalyDetector:
    """
    Detects anomalies in user session behavior using various techniques
    including Markov chains and statistical analysis.
    """
    
    def __init__(self):
        self.db = Database()
        logger.info("SessionAnomalyDetector initialized")
        
        # Default transition matrix for new users
        self.default_transitions = {
            'login': {'view_dashboard': 0.6, 'view_profile': 0.3, 'view_settings': 0.1},
            'view_dashboard': {'view_account': 0.4, 'view_transactions': 0.3, 'logout': 0.2, 'view_profile': 0.1},
            'view_account': {'view_transactions': 0.5, 'view_dashboard': 0.3, 'logout': 0.2},
            'view_transactions': {'view_dashboard': 0.4, 'view_account': 0.3, 'logout': 0.3},
            'view_profile': {'view_dashboard': 0.5, 'edit_profile': 0.3, 'logout': 0.2},
            'edit_profile': {'view_profile': 0.7, 'view_dashboard': 0.2, 'logout': 0.1},
            'view_settings': {'view_dashboard': 0.5, 'edit_settings': 0.3, 'logout': 0.2},
            'edit_settings': {'view_settings': 0.7, 'view_dashboard': 0.2, 'logout': 0.1}
        }
        
        # Suspicious activities configuration
        self.suspicious_activities = {
            'change_email': 15,
            'change_password': 10,
            'add_payment_method': 20,
            'large_transaction': 25,
            'export_data': 15,
            'delete_account': 30,
            'multiple_failed_payments': 20,
            'api_access': 10,
            'change_security_questions': 20,
            'disable_2fa': 30
        }
        
        # Time thresholds (in seconds)
        self.time_thresholds = {
            'min_time_between_actions': 1,     # Minimum reasonable time between actions
            'max_time_for_sequence': 1800,     # Maximum time for a typical sequence
            'typical_session_length': 900      # Typical session length
        }
    
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
            if not session_events:
                return {
                    'risk_score': 0,
                    'status': 'insufficient_data',
                    'message': 'No session events provided for analysis',
                    'anomaly_score': 0
                }
            
            # Require at least 2 events for meaningful analysis
            if len(session_events) < 2:
                return {
                    'risk_score': 0,
                    'status': 'insufficient_data',
                    'message': 'Need at least 2 events for session analysis',
                    'anomaly_score': 0
                }
            
            # Sort events by timestamp if not already sorted
            sorted_events = sorted(session_events, key=lambda x: x.get('timestamp', 0))
            
            # Get user's behavioral model
            user_model = self._get_user_model(user_id)
            
            # Check for timing anomalies
            timing_anomalies = self._check_timing_anomalies(sorted_events)
            
            # Check for sequence anomalies using Markov chain
            sequence_anomalies = self._check_sequence_anomalies(sorted_events, user_model)
            
            # Check for suspicious activities
            activity_anomalies = self._check_activity_anomalies(sorted_events)
            
            # Combine anomaly scores
            anomaly_scores = [
                timing_anomalies.get('score', 0),
                sequence_anomalies.get('score', 0),
                activity_anomalies.get('score', 0)
            ]
            
            combined_score = max(anomaly_scores)
            
            # Calculate risk score based on anomaly score
            risk_score = self._calculate_risk_score(combined_score)
            
            # Determine status
            if risk_score >= 80:
                status = 'high_risk_behavior'
                message = 'Session exhibits highly suspicious behavior patterns'
            elif risk_score >= 50:
                status = 'suspicious_behavior'
                message = 'Session contains potentially suspicious behavior patterns'
            else:
                status = 'normal_behavior'
                message = 'Session behavior appears normal'
            
            # Update user model with this session (if not too anomalous)
            if combined_score < 0.7:  # Don't learn from very anomalous sessions
                self._update_user_model(user_id, sorted_events, user_model)
            
            # Prepare detailed anomalies
            anomalies = {}
            if timing_anomalies.get('detected', False):
                anomalies['timing'] = timing_anomalies
            
            if sequence_anomalies.get('detected', False):
                anomalies['sequence'] = sequence_anomalies
            
            if activity_anomalies.get('detected', False):
                anomalies['activities'] = activity_anomalies
            
            # Prepare result
            result = {
                'risk_score': risk_score,
                'status': status,
                'message': message,
                'anomaly_score': round(combined_score, 2),
                'anomalies': anomalies,
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
    
    def _get_user_model(self, user_id):
        """
        Get the user's behavioral model
        
        Args:
            user_id (str): User identifier
            
        Returns:
            dict: User behavioral model
        """
        # Get user model from database
        user_model = self.db.get_user_model(user_id)
        
        # If no model exists, create a new one with defaults
        if not user_model:
            user_model = {
                'transitions': self.default_transitions.copy(),
                'avg_session_length': self.time_thresholds['typical_session_length'],
                'avg_time_between_actions': 30,  # 30 seconds as default
                'common_actions': [],
                'session_count': 0
            }
        
        return user_model
    
    def _check_timing_anomalies(self, events):
        """
        Check for timing anomalies in the session
        
        Args:
            events (list): Session events sorted by timestamp
            
        Returns:
            dict: Timing anomaly details
        """
        anomalies = []
        anomaly_score = 0
        
        # Check time between events
        for i in range(1, len(events)):
            current_time = events[i].get('timestamp', 0)
            previous_time = events[i-1].get('timestamp', 0)
            time_diff = current_time - previous_time
            
            # Too fast (bot-like behavior)
            if time_diff < self.time_thresholds['min_time_between_actions']:
                anomalies.append({
                    'type': 'too_fast',
                    'event_index': i,
                    'time_diff': time_diff,
                    'threshold': self.time_thresholds['min_time_between_actions']
                })
                anomaly_score = max(anomaly_score, 0.8)
            
            # Unusually long gap
            elif time_diff > self.time_thresholds['max_time_for_sequence']:
                anomalies.append({
                    'type': 'long_gap',
                    'event_index': i,
                    'time_diff': time_diff,
                    'threshold': self.time_thresholds['max_time_for_sequence']
                })
                anomaly_score = max(anomaly_score, 0.6)
        
        # Check overall session length
        if len(events) >= 2:
            session_length = events[-1].get('timestamp', 0) - events[0].get('timestamp', 0)
            
            # Unusually long session
            if session_length > 5 * self.time_thresholds['typical_session_length']:
                anomalies.append({
                    'type': 'long_session',
                    'session_length': session_length,
                    'threshold': 5 * self.time_thresholds['typical_session_length']
                })
                anomaly_score = max(anomaly_score, 0.5)
        
        return {
            'detected': len(anomalies) > 0,
            'score': anomaly_score,
            'details': anomalies
        }
    
    def _check_sequence_anomalies(self, events, user_model):
        """
        Check for sequence anomalies using Markov chain
        
        Args:
            events (list): Session events sorted by timestamp
            user_model (dict): User behavioral model
            
        Returns:
            dict: Sequence anomaly details
        """
        anomalies = []
        anomaly_score = 0
        transitions = user_model.get('transitions', self.default_transitions)
        
        # Extract event types from the events
        event_types = [event.get('type') for event in events]
        
        # Check transitions
        for i in range(1, len(event_types)):
            prev_type = event_types[i-1]
            current_type = event_types[i]
            
            # Check if transition exists in model
            if prev_type in transitions and current_type in transitions.get(prev_type, {}):
                # Get transition probability
                probability = transitions[prev_type].get(current_type, 0)
                
                # If probability is very low, mark as anomalous
                if probability < 0.05:
                    anomalies.append({
                        'type': 'unlikely_transition',
                        'from': prev_type,
                        'to': current_type,
                        'probability': probability
                    })
                    anomaly_score = max(anomaly_score, 1 - (probability / 0.05))
            else:
                # Transition doesn't exist in model
                anomalies.append({
                    'type': 'unknown_transition',
                    'from': prev_type,
                    'to': current_type
                })
                anomaly_score = max(anomaly_score, 0.7)
        
        # Check for unusual patterns
        unusual_patterns = self._check_unusual_patterns(event_types)
        if unusual_patterns:
            anomalies.extend(unusual_patterns)
            anomaly_score = max(anomaly_score, 0.8)
        
        return {
            'detected': len(anomalies) > 0,
            'score': anomaly_score,
            'details': anomalies
        }
    
    def _check_unusual_patterns(self, event_types):
        """
        Check for specific unusual patterns in sequence
        
        Args:
            event_types (list): Sequence of event types
            
        Returns:
            list: Unusual patterns detected
        """
        patterns = []
        
        # Check for repeated actions (more than 3 times in a row)
        for i in range(len(event_types) - 3):
            if (event_types[i] == event_types[i+1] == 
                event_types[i+2] == event_types[i+3]):
                patterns.append({
                    'type': 'repeated_action',
                    'action': event_types[i],
                    'count': 4,
                    'index': i
                })
        
        # Check for cyclic patterns (A-B-A-B-A-B)
        for i in range(len(event_types) - 5):
            if (event_types[i] == event_types[i+2] == event_types[i+4] and
                event_types[i+1] == event_types[i+3] == event_types[i+5] and
                event_types[i] != event_types[i+1]):
                patterns.append({
                    'type': 'cyclic_pattern',
                    'actions': [event_types[i], event_types[i+1]],
                    'index': i
                })
        
        # Check for rapid navigation through many sections
        unique_actions = len(set(event_types[:10]))
        if unique_actions >= 7 and len(event_types) >= 10:
            patterns.append({
                'type': 'rapid_navigation',
                'unique_actions': unique_actions,
                'sequence_length': 10
            })
        
        return patterns
    
    def _check_activity_anomalies(self, events):
        """
        Check for suspicious activities in the session
        
        Args:
            events (list): Session events
            
        Returns:
            dict: Activity anomaly details
        """
        anomalies = []
        anomaly_score = 0
        
        # Count suspicious activities
        suspicious_count = 0
        total_risk = 0
        
        for i, event in enumerate(events):
            event_type = event.get('type', '')
            metadata = event.get('metadata', {})
            
            # Check if this is a suspicious activity
            if event_type in self.suspicious_activities:
                risk_level = self.suspicious_activities[event_type]
                suspicious_count += 1
                total_risk += risk_level
                
                anomalies.append({
                    'type': 'suspicious_activity',
                    'activity': event_type,
                    'risk_level': risk_level,
                    'index': i,
                    'metadata': metadata
                })
                
                # Calculate contribution to overall anomaly score
                activity_score = min(risk_level / 30, 1.0)  # Normalize to 0-1
                anomaly_score = max(anomaly_score, activity_score)
        
        # Check for multiple suspicious activities in one session
        if suspicious_count >= 3:
            anomalies.append({
                'type': 'multiple_suspicious',
                'count': suspicious_count,
                'total_risk': total_risk
            })
            anomaly_score = max(anomaly_score, 0.9)  # Very suspicious
        elif suspicious_count >= 2:
            anomaly_score = max(anomaly_score, 0.7)  # Quite suspicious
        
        return {
            'detected': len(anomalies) > 0,
            'score': anomaly_score,
            'details': anomalies
        }
    
    def _calculate_risk_score(self, anomaly_score):
        """
        Calculate risk score based on anomaly score
        
        Args:
            anomaly_score (float): Normalized anomaly score (0-1)
            
        Returns:
            int: Risk score (0-100)
        """
        # Simple linear scaling with threshold
        if anomaly_score < 0.2:
            # Low anomaly scores are considered normal
            return 0
        
        # Scale from 0.2-1.0 to 0-100
        scaled_score = (anomaly_score - 0.2) / 0.8 * 100
        return min(100, max(0, int(scaled_score)))
    
    def _update_user_model(self, user_id, events, current_model):
        """
        Update the user's behavioral model based on this session
        
        Args:
            user_id (str): User identifier
            events (list): Session events
            current_model (dict): Current user model
        """
        try:
            # Don't update if too few events
            if len(events) < 2:
                return
            
            # Extract event types
            event_types = [event.get('type') for event in events]
            
            # Update transition matrix
            transitions = current_model.get('transitions', {}).copy()
            
            for i in range(1, len(event_types)):
                prev_type = event_types[i-1]
                current_type = event_types[i]
                
                # Ensure prev_type exists in transitions
                if prev_type not in transitions:
                    transitions[prev_type] = {}
                
                # Update transition probability
                transition_count = transitions[prev_type].get(current_type, 0)
                transitions[prev_type][current_type] = transition_count + 0.1
                
                # Normalize probabilities
                total = sum(transitions[prev_type].values())
                for key in transitions[prev_type]:
                    transitions[prev_type][key] /= total
            
            # Update timing statistics
            session_length = events[-1].get('timestamp', 0) - events[0].get('timestamp', 0)
            current_avg_length = current_model.get('avg_session_length', 
                                                self.time_thresholds['typical_session_length'])
            
            time_diffs = []
            for i in range(1, len(events)):
                current_time = events[i].get('timestamp', 0)
                previous_time = events[i-1].get('timestamp', 0)
                time_diff = current_time - previous_time
                if time_diff > 0 and time_diff < self.time_thresholds['max_time_for_sequence']:
                    time_diffs.append(time_diff)
            
            avg_time_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 30
            current_avg_time_diff = current_model.get('avg_time_between_actions', 30)
            
            # Update session count
            session_count = current_model.get('session_count', 0) + 1
            
            # Weighted average to update model
            alpha = 0.8  # Weight for existing model (more weight = slower adaptation)
            
            updated_model = {
                'transitions': transitions,
                'avg_session_length': (alpha * current_avg_length + (1 - alpha) * session_length),
                'avg_time_between_actions': (alpha * current_avg_time_diff + (1 - alpha) * avg_time_diff),
                'common_actions': self._update_common_actions(current_model.get('common_actions', []), event_types),
                'session_count': session_count,
                'last_updated': int(time.time())
            }
            
            # Store updated model
            self.db.update_user_model(user_id, updated_model)
            
        except Exception as e:
            logger.error(f"Error updating user model: {str(e)}")
    
    def _update_common_actions(self, current_common, new_actions):
        """
        Update list of common actions for the user
        
        Args:
            current_common (list): Current common actions
            new_actions (list): New action types from this session
            
        Returns:
            list: Updated common actions
        """
        # Count frequencies
        action_counts = {}
        
        # Add existing common actions
        for action in current_common:
            action_counts[action] = action_counts.get(action, 0) + 2  # Higher weight
        
        # Add new actions
        for action in new_actions:
            action_counts[action] = action_counts.get(action, 0) + 1
        
        # Sort by count and take top 10
        sorted_actions = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)
        return [action for action, count in sorted_actions[:10]]

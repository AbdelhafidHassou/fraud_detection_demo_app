import logging
import time
import math
from app.database import Database

logger = logging.getLogger(__name__)

class PasswordAttackDetector:
    """
    Detects password-based attacks such as brute force, credential stuffing,
    and password spraying.
    """
    
    def __init__(self):
        self.db = Database()
        logger.info("PasswordAttackDetector initialized")
        
        # Attack thresholds
        self.thresholds = {
            'bruteforce': {
                'attempts': 5,
                'window_minutes': 10,
                'risk_score': 85
            },
            'credential_stuffing': {
                'user_count': 10,
                'ip_count': 3,
                'window_minutes': 30,
                'risk_score': 90
            },
            'password_spraying': {
                'user_count': 10,
                'ip_count': 1,
                'window_minutes': 60,
                'risk_score': 80
            },
            'generic_attack': {
                'attempts': 15,
                'window_minutes': 60,
                'risk_score': 75
            }
        }
    
    def detect(self, user_id, ip_address):
        """
        Detect password-based attacks
        
        Args:
            user_id (str): User identifier
            ip_address (str): IP address
            
        Returns:
            dict: Detection results including risk score and attack type
        """
        try:
            # Get failed login data
            user_failures = self.db.get_recent_failed_logins(
                username=user_id,
                minutes=self.thresholds['generic_attack']['window_minutes']
            )
            
            ip_failures = self.db.get_recent_failed_logins(
                ip_address=ip_address,
                minutes=self.thresholds['generic_attack']['window_minutes']
            )
            
            all_recent_failures = self.db.get_recent_failed_logins(
                minutes=self.thresholds['generic_attack']['window_minutes']
            )
            
            # Detect different attack types
            brute_force = self._detect_brute_force(user_id, ip_address, user_failures)
            credential_stuffing = self._detect_credential_stuffing(ip_address, all_recent_failures)
            password_spraying = self._detect_password_spraying(all_recent_failures)
            
            # Determine the most severe attack
            attacks = [brute_force, credential_stuffing, password_spraying]
            attacks = [a for a in attacks if a['detected']]
            
            if not attacks:
                # No attacks detected
                return {
                    'risk_score': 0,
                    'attack_detected': False,
                    'attack_type': None,
                    'message': "No password attacks detected",
                    'user_failures_count': len(user_failures),
                    'ip_failures_count': len(ip_failures)
                }
            
            # Get the most severe attack (highest risk score)
            most_severe = max(attacks, key=lambda x: x['risk_score'])
            
            # Calculate velocity and acceleration
            velocity, acceleration = self._calculate_attack_metrics(ip_failures)
            
            # Prepare result
            result = {
                'risk_score': most_severe['risk_score'],
                'attack_detected': True,
                'attack_type': most_severe['type'],
                'message': most_severe['message'],
                'attack_details': {
                    'user_failures_count': len(user_failures),
                    'ip_failures_count': len(ip_failures),
                    'velocity': velocity,
                    'acceleration': acceleration,
                    'ip_addresses': most_severe.get('ip_addresses', []),
                    'affected_users': most_severe.get('affected_users', [])
                }
            }
            
            # Log detected attacks
            logger.warning(
                f"Password attack detected: {most_severe['type']} against user {user_id} "
                f"from IP {ip_address}"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error in password attack detection: {str(e)}")
            return {
                'risk_score': 50,  # Medium risk due to error
                'attack_detected': False,
                'attack_type': 'detection_error',
                'message': f"Error in password attack detection: {str(e)}"
            }
    
    def _detect_brute_force(self, user_id, ip_address, user_failures):
        """
        Detect brute force attacks against a specific user
        
        Args:
            user_id (str): User identifier
            ip_address (str): IP address
            user_failures (list): Failed login attempts for the user
            
        Returns:
            dict: Detection results
        """
        # Filter failures by time window and IP
        threshold = self.thresholds['bruteforce']
        window_seconds = threshold['window_minutes'] * 60
        now = time.time()
        
        # Check failures from this IP against this user
        ip_failures_for_user = [
            f for f in user_failures 
            if f['ip_address'] == ip_address and now - f['timestamp'] <= window_seconds
        ]
        
        # Detect brute force attack
        detected = len(ip_failures_for_user) >= threshold['attempts']
        
        return {
            'type': 'bruteforce',
            'detected': detected,
            'risk_score': threshold['risk_score'] if detected else 0,
            'message': f"Brute force attack detected: {len(ip_failures_for_user)} failed attempts "
                      f"against user {user_id} from IP {ip_address}",
            'ip_addresses': [ip_address]
        }
    
    def _detect_credential_stuffing(self, ip_address, all_failures):
        """
        Detect credential stuffing attacks (multiple users, few IPs)
        
        Args:
            ip_address (str): Current IP address
            all_failures (list): All recent failed login attempts
            
        Returns:
            dict: Detection results
        """
        threshold = self.thresholds['credential_stuffing']
        window_seconds = threshold['window_minutes'] * 60
        now = time.time()
        
        # Get recent failures from this IP
        recent_ip_failures = [
            f for f in all_failures 
            if f['ip_address'] == ip_address and now - f['timestamp'] <= window_seconds
        ]
        
        # Count unique users
        unique_users = set(f['username'] for f in recent_ip_failures)
        
        # Detect credential stuffing
        detected = len(unique_users) >= threshold['user_count']
        
        return {
            'type': 'credential_stuffing',
            'detected': detected,
            'risk_score': threshold['risk_score'] if detected else 0,
            'message': f"Credential stuffing attack detected: {len(unique_users)} different users "
                      f"targeted from IP {ip_address}",
            'ip_addresses': [ip_address],
            'affected_users': list(unique_users)[:10]  # Limit to first 10
        }
    
    def _detect_password_spraying(self, all_failures):
        """
        Detect password spraying attacks (many users, common password)
        
        Args:
            all_failures (list): All recent failed login attempts
            
        Returns:
            dict: Detection results
        """
        threshold = self.thresholds['password_spraying']
        window_seconds = threshold['window_minutes'] * 60
        now = time.time()
        
        # Get very recent failures
        recent_failures = [f for f in all_failures if now - f['timestamp'] <= window_seconds]
        
        # Count unique users and IPs
        unique_users = set(f['username'] for f in recent_failures)
        unique_ips = set(f['ip_address'] for f in recent_failures)
        
        # Detect password spraying (many users, few IPs)
        detected = (
            len(unique_users) >= threshold['user_count'] and 
            len(unique_ips) <= threshold['ip_count'] * 3  # Allow some flexibility
        )
        
        return {
            'type': 'password_spraying',
            'detected': detected,
            'risk_score': threshold['risk_score'] if detected else 0,
            'message': f"Password spraying attack detected: {len(unique_users)} different users "
                      f"targeted from {len(unique_ips)} IP addresses",
            'ip_addresses': list(unique_ips),
            'affected_users': list(unique_users)[:10]  # Limit to first 10
        }
    
    def _calculate_attack_metrics(self, failures):
        """
        Calculate attack velocity and acceleration
        
        Args:
            failures (list): Failed login attempts
            
        Returns:
            tuple: (velocity, acceleration)
        """
        if not failures or len(failures) < 3:
            return 0, 0
        
        # Sort by timestamp
        sorted_failures = sorted(failures, key=lambda x: x['timestamp'])
        
        # Calculate time differences
        timestamps = [f['timestamp'] for f in sorted_failures]
        time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not time_diffs:
            return 0, 0
        
        # Calculate velocity (failures per minute)
        total_time = timestamps[-1] - timestamps[0]
        velocity = (len(failures) - 1) * 60 / total_time if total_time > 0 else 0
        
        # Calculate acceleration (change in velocity)
        if len(time_diffs) < 2:
            return velocity, 0
        
        first_half = time_diffs[:len(time_diffs)//2]
        second_half = time_diffs[len(time_diffs)//2:]
        
        velocity1 = len(first_half) * 60 / sum(first_half) if sum(first_half) > 0 else 0
        velocity2 = len(second_half) * 60 / sum(second_half) if sum(second_half) > 0 else 0
        
        acceleration = velocity2 - velocity1
        
        return round(velocity, 2), round(acceleration, 2)

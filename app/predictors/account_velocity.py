import logging
import time
from datetime import datetime
import re
import math
from app.database import Database

logger = logging.getLogger(__name__)

class AccountVelocityMonitor:
    """
    Monitors account creation and activity velocity to detect fraudulent patterns.
    Detects unusual patterns in registration rate, especially from the same source.
    """
    
    def __init__(self):
        self.db = Database()
        logger.info("AccountVelocityMonitor initialized")
        
        # Configuration
        self.time_windows = {
            'short': 60 * 5,       # 5 minutes (in seconds)
            'medium': 60 * 60,     # 1 hour
            'long': 60 * 60 * 24   # 24 hours
        }
        
        # Thresholds for different entity types
        self.thresholds = {
            'ip': {
                'short': 3,    # 3 accounts per 5 minutes
                'medium': 10,  # 10 accounts per hour
                'long': 30     # 30 accounts per day
            },
            'email_domain': {
                'short': 5,    # 5 accounts per 5 minutes
                'medium': 20,  # 20 accounts per hour
                'long': 50     # 50 accounts per day
            },
            'subnet': {
                'short': 8,    # 8 accounts per 5 minutes
                'medium': 25,  # 25 accounts per hour
                'long': 80     # 80 accounts per day
            }
        }
    
    def check(self, ip_address, email=''):
        """
        Check account creation velocity from an IP, subnet, or email domain
        
        Args:
            ip_address (str): IP address
            email (str): Email address (optional)
            
        Returns:
            dict: Velocity analysis results including risk score
        """
        try:
            # Extract email domain if email is provided
            email_domain = None
            if email and '@' in email:
                email_domain = email.split('@')[1].lower()
            
            # Extract subnet (for IPv4)
            subnet = self._get_subnet(ip_address)
            
            # Get registration history for different entities
            ip_registrations = self._get_registrations_by_entity('ip', ip_address)
            subnet_registrations = self._get_registrations_by_entity('subnet', subnet) if subnet else []
            domain_registrations = self._get_registrations_by_entity('email_domain', email_domain) if email_domain else []
            
            # Calculate velocities for different time windows
            current_time = int(time.time())
            
            velocities = {}
            risk_scores = []
            
            # Calculate IP-based velocities
            ip_velocities, ip_risk = self._calculate_velocities(
                'ip', ip_address, ip_registrations, current_time
            )
            velocities['ip'] = ip_velocities
            if ip_risk > 0:
                risk_scores.append(ip_risk)
            
            # Calculate subnet-based velocities
            if subnet:
                subnet_velocities, subnet_risk = self._calculate_velocities(
                    'subnet', subnet, subnet_registrations, current_time
                )
                velocities['subnet'] = subnet_velocities
                if subnet_risk > 0:
                    risk_scores.append(subnet_risk)
            
            # Calculate domain-based velocities
            if email_domain:
                domain_velocities, domain_risk = self._calculate_velocities(
                    'email_domain', email_domain, domain_registrations, current_time
                )
                velocities['email_domain'] = domain_velocities
                if domain_risk > 0:
                    risk_scores.append(domain_risk)
            
            # Calculate overall risk score
            risk_score = max(risk_scores) if risk_scores else 0
            
            # Determine status
            if risk_score >= 80:
                status = 'high_velocity'
                message = 'Account creation rate significantly exceeds normal patterns'
            elif risk_score >= 50:
                status = 'elevated_velocity'
                message = 'Account creation rate exceeds normal patterns'
            else:
                status = 'normal_velocity'
                message = 'Account creation rate within normal patterns'
            
            # Check for additional velocity patterns
            patterns = self._check_velocity_patterns(
                ip_registrations, subnet_registrations, domain_registrations, current_time
            )
            
            if patterns:
                if patterns['risk_score'] > risk_score:
                    risk_score = patterns['risk_score']
                    status = patterns['status']
                    message = patterns['message']
            
            # Prepare result
            result = {
                'risk_score': risk_score,
                'status': status,
                'message': message,
                'velocities': velocities
            }
            
            # Add pattern information if detected
            if patterns:
                result['patterns'] = patterns['details']
            
            # Log high-risk velocities
            if risk_score > 70:
                logger.warning(f"High-risk account velocity detected for IP {ip_address}")

            return result
            
        except Exception as e:
            logger.error(f"Error in account velocity analysis: {str(e)}")
            return {
                'risk_score': 50,  # Medium risk due to error
                'status': 'error',
                'message': f"Error in account velocity analysis: {str(e)}"
            }
    
    def _get_subnet(self, ip_address):
        """
        Get subnet from an IP address (for IPv4 only)
        
        Args:
            ip_address (str): IP address
            
        Returns:
            str: Subnet in CIDR notation or None if not IPv4
        """
        # Simple IPv4 pattern matching
        ipv4_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
        match = re.match(ipv4_pattern, ip_address)
        
        if match:
            # Extract the first three octets for a /24 subnet
            octets = ip_address.split('.')
            if len(octets) == 4:
                return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        
        return None
    
    def _get_registrations_by_entity(self, entity_type, entity_value):
        """
        Get registration history for an entity (IP, subnet, domain)
        
        Args:
            entity_type (str): Entity type ('ip', 'subnet', 'email_domain')
            entity_value (str): Entity value
            
        Returns:
            list: Registration timestamps
        """
        # In a real implementation, this would query the database
        # For this example, we'll use a simplified approach
        
        # Get registration records from the database
        registrations = self.db.get_registrations(entity_type, entity_value)
        
        # If no records, create a simulated baseline
        if not registrations:
            registrations = self._simulate_baseline_registrations(entity_type)
        
        return registrations
    
    def _simulate_baseline_registrations(self, entity_type):
        """
        Simulate baseline registration data for testing
        In a real system, this would not be needed
        
        Args:
            entity_type (str): Entity type
            
        Returns:
            list: Simulated registration timestamps
        """
        import random
        
        # Create a reasonable baseline
        current_time = int(time.time())
        count = {
            'ip': 5,
            'subnet': 15,
            'email_domain': 25
        }.get(entity_type, 5)
        
        # Generate timestamps within the last 24 hours
        timestamps = []
        for _ in range(count):
            time_offset = random.randint(0, 86400)  # Within last 24 hours
            timestamps.append(current_time - time_offset)
        
        return sorted(timestamps)
    
    def _calculate_velocities(self, entity_type, entity_value, registrations, current_time):
        """
        Calculate velocities for different time windows
        
        Args:
            entity_type (str): Entity type ('ip', 'subnet', 'email_domain')
            entity_value (str): Entity value
            registrations (list): Registration timestamps
            current_time (int): Current timestamp
            
        Returns:
            tuple: (velocities_dict, risk_score)
        """
        velocities = {}
        max_risk = 0
        
        for window_name, window_seconds in self.time_windows.items():
            # Count registrations in this time window
            window_registrations = [
                ts for ts in registrations 
                if current_time - ts <= window_seconds
            ]
            
            count = len(window_registrations)
            
            # Calculate velocity (registrations per hour)
            hours = window_seconds / 3600
            velocity = count / hours if hours > 0 else 0
            
            # Calculate risk based on thresholds
            threshold = self.thresholds.get(entity_type, {}).get(window_name, 1000)
            
            # No risk if below threshold
            if count <= threshold:
                risk = 0
            else:
                # Scale risk from 0-100 based on how far above threshold
                excess_ratio = count / threshold
                if excess_ratio >= 5:
                    risk = 100  # 5x or more above threshold is maximum risk
                else:
                    # Scale 1x-5x to 25-100
                    risk = 25 + 75 * (excess_ratio - 1) / 4
            
            velocities[window_name] = {
                'count': count,
                'threshold': threshold,
                'velocity_per_hour': round(velocity, 2),
                'risk': int(risk)
            }
            
            max_risk = max(max_risk, risk)
        
        return velocities, int(max_risk)
    
    def _check_velocity_patterns(self, ip_regs, subnet_regs, domain_regs, current_time):
        """
        Check for specific velocity patterns that indicate fraud
        
        Args:
            ip_regs (list): IP registration timestamps
            subnet_regs (list): Subnet registration timestamps
            domain_regs (list): Domain registration timestamps
            current_time (int): Current timestamp
            
        Returns:
            dict: Pattern details or None if no patterns detected
        """
        patterns = {}
        
        # Check for burst pattern (many registrations in a very short time)
        burst_pattern = self._check_burst_pattern(ip_regs, current_time)
        if burst_pattern:
            patterns['burst'] = burst_pattern
        
        # Check for cyclical pattern (registrations at regular intervals)
        cyclical_pattern = self._check_cyclical_pattern(subnet_regs)
        if cyclical_pattern:
            patterns['cyclical'] = cyclical_pattern
        
        # Check for distributed pattern (consistent registrations across subnet)
        distributed_pattern = self._check_distributed_pattern(subnet_regs, domain_regs)
        if distributed_pattern:
            patterns['distributed'] = distributed_pattern
        
        if not patterns:
            return None
        
        # Determine the most severe pattern
        risk_scores = {
            'burst': 90,
            'cyclical': 75,
            'distributed': 80
        }
        
        pattern_types = list(patterns.keys())
        most_severe = max(pattern_types, key=lambda p: risk_scores.get(p, 0))
        
        return {
            'status': f'{most_severe}_pattern',
            'message': f"Detected {most_severe} registration pattern",
            'risk_score': risk_scores.get(most_severe, 70),
            'details': patterns
        }
    
    def _check_burst_pattern(self, timestamps, current_time):
        """
        Check for burst pattern (many registrations in a very short time)
        
        Args:
            timestamps (list): Registration timestamps
            current_time (int): Current timestamp
            
        Returns:
            dict: Pattern details or None if not detected
        """
        # Focus on very recent registrations (last 10 minutes)
        recent_window = 10 * 60  # 10 minutes
        recent_regs = [ts for ts in timestamps if current_time - ts <= recent_window]
        
        if len(recent_regs) < 3:
            return None
        
        # Sort timestamps
        recent_regs.sort()
        
        # Look for 3 or more registrations within 30 seconds
        for i in range(len(recent_regs) - 2):
            if recent_regs[i+2] - recent_regs[i] <= 30:
                return {
                    'count': 3,
                    'seconds': recent_regs[i+2] - recent_regs[i],
                    'timestamp': recent_regs[i]
                }
        
        # Look for 5 or more registrations within 2 minutes
        if len(recent_regs) >= 5:
            for i in range(len(recent_regs) - 4):
                if recent_regs[i+4] - recent_regs[i] <= 120:
                    return {
                        'count': 5,
                        'seconds': recent_regs[i+4] - recent_regs[i],
                        'timestamp': recent_regs[i]
                    }
        
        return None
    
    def _check_cyclical_pattern(self, timestamps):
        """
        Check for cyclical pattern (registrations at regular intervals)
        
        Args:
            timestamps (list): Registration timestamps
            
        Returns:
            dict: Pattern details or None if not detected
        """
        if len(timestamps) < 5:
            return None
        
        # Sort timestamps
        sorted_ts = sorted(timestamps)
        
        # Calculate intervals
        intervals = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts)-1)]
        
        # Check for regular intervals (similar time gaps)
        if len(intervals) < 4:
            return None
        
        # Calculate average and standard deviation
        avg_interval = sum(intervals) / len(intervals)
        std_dev = math.sqrt(sum((x - avg_interval)**2 for x in intervals) / len(intervals))
        
        # Check if intervals are consistent (low standard deviation)
        if avg_interval > 0 and (std_dev / avg_interval) < 0.25:
            # Regular intervals with low variation detected
            return {
                'avg_interval_seconds': int(avg_interval),
                'std_dev': int(std_dev),
                'count': len(intervals) + 1
            }
        
        return None
    
    def _check_distributed_pattern(self, subnet_regs, domain_regs):
        """
        Check for distributed pattern (consistent registrations across sources)
        
        Args:
            subnet_regs (list): Subnet registration timestamps
            domain_regs (list): Domain registration timestamps
            
        Returns:
            dict: Pattern details or None if not detected
        """
        # Need both subnet and domain data
        if not subnet_regs or not domain_regs:
            return None
        
        # Sort timestamps
        subnet_sorted = sorted(subnet_regs)
        domain_sorted = sorted(domain_regs)
        
        # Check if registrations are interleaved (alternating sources)
        # In a real implementation, we'd need the actual source information,
        # not just timestamps, but this is a simplified example
        
        # Check if high velocity but distributed across the subnet
        if len(subnet_sorted) > 10 and len(domain_sorted) > 10:
            last_hour_subnet = [ts for ts in subnet_sorted if subnet_sorted[-1] - ts <= 3600]
            last_hour_domain = [ts for ts in domain_sorted if domain_sorted[-1] - ts <= 3600]
            
            if len(last_hour_subnet) > 5 and len(last_hour_domain) > 5:
                return {
                    'subnet_count': len(last_hour_subnet),
                    'domain_count': len(last_hour_domain),
                    'time_window': '1 hour'
                }
        
        return None

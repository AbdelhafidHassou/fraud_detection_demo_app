import logging
import time
import requests
from app.database import Database

logger = logging.getLogger(__name__)

class IPReputationChecker:
    """
    Checks IP reputation based on historical data and external sources.
    """
    
    def __init__(self):
        self.db = Database()
        
        # Initialize reputation database
        self.known_malicious_ips = set()
        self.known_proxy_ips = set()
        self.known_tor_exits = set()
        
        # Load reputation data
        self._load_reputation_data()
        
        logger.info("IPReputationChecker initialized")
    
    def check(self, ip_address):
        """
        Check reputation of an IP address
        
        Args:
            ip_address (str): IP address to check
            
        Returns:
            dict: Reputation analysis including risk score and flags
        """
        try:
            # Get existing reputation data from database
            current_reputation = self.db.get_ip_reputation(ip_address)
            
            # Check if we need to refresh the data
            if self._should_refresh_reputation(current_reputation):
                current_reputation = self._analyze_ip(ip_address, current_reputation)
                self.db.update_ip_reputation(ip_address, current_reputation)
            
            # Get location data
            location = self.db.get_ip_location(ip_address)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(current_reputation)
            
            # Determine reputation status
            status = self._get_reputation_status(risk_score)
            
            # Prepare result
            result = {
                'risk_score': risk_score,
                'status': status,
                'is_proxy': current_reputation.get('is_proxy', False),
                'is_tor': current_reputation.get('is_tor', False),
                'is_datacenter': current_reputation.get('is_datacenter', False),
                'is_vpn': current_reputation.get('is_vpn', False),
                'is_known_abuser': current_reputation.get('is_known_abuser', False),
                'failed_logins': current_reputation.get('failed_logins', 0),
                'countries_count': current_reputation.get('countries_count', 0),
                'raw_score': current_reputation.get('score', 50)
            }
            
            # Add location if available
            if location:
                result['location'] = {
                    'country': location.get('country', 'Unknown'),
                    'city': location.get('city', 'Unknown'),
                    'latitude': location.get('latitude'),
                    'longitude': location.get('longitude')
                }
            
            # Log high-risk IPs
            if risk_score > 70:
                logger.warning(f"High-risk IP detected: {ip_address} (Score: {risk_score})")
            
            return result
            
        except Exception as e:
            logger.error(f"Error checking IP reputation: {str(e)}")
            return {
                'risk_score': 50,  # Medium risk due to error
                'status': 'error',
                'message': f"Error checking IP reputation: {str(e)}"
            }
    
    def _load_reputation_data(self):
        """Load reputation data from files or external sources"""
        try:
            # In a real implementation, you would load from files or a database
            # For this example, we'll use a small sample
            
            # Sample malicious IPs (for demonstration only)
            self.known_malicious_ips = {
                '192.0.2.1', '192.0.2.2', '192.0.2.3', 
                '198.51.100.1', '198.51.100.2', '198.51.100.3'
            }
            
            # Sample proxy IPs (for demonstration only)
            self.known_proxy_ips = {
                '192.0.2.10', '192.0.2.11', '192.0.2.12',
                '198.51.100.10', '198.51.100.11', '198.51.100.12'
            }
            
            # Sample Tor exit nodes (for demonstration only)
            self.known_tor_exits = {
                '192.0.2.20', '192.0.2.21', '192.0.2.22',
                '198.51.100.20', '198.51.100.21', '198.51.100.22'
            }
            
            logger.info(f"Loaded IP reputation data: {len(self.known_malicious_ips)} malicious, "
                      f"{len(self.known_proxy_ips)} proxies, {len(self.known_tor_exits)} Tor exits")
            
        except Exception as e:
            logger.error(f"Error loading reputation data: {str(e)}")
    
    def _should_refresh_reputation(self, reputation_data):
        """
        Check if we should refresh the reputation data
        
        Args:
            reputation_data (dict): Current reputation data
            
        Returns:
            bool: True if refresh is needed
        """
        # Always refresh if no data
        if not reputation_data:
            return True
        
        # Check if data is stale (older than 24 hours)
        current_time = int(time.time())
        last_update = reputation_data.get('last_updated', 0)
        
        if current_time - last_update > 86400:  # 24 hours
            return True
        
        return False
    
    def _analyze_ip(self, ip_address, current_reputation):
        """
        Analyze an IP address for reputation data
        
        Args:
            ip_address (str): IP address to analyze
            current_reputation (dict): Current reputation data if available
            
        Returns:
            dict: Updated reputation data
        """
        # Start with current data or defaults
        reputation = current_reputation.copy() if current_reputation else {
            'score': 50,  # Neutral score
            'is_proxy': False,
            'is_vpn': False,
            'is_tor': False,
            'is_datacenter': False,
            'is_known_abuser': False,
            'failed_logins': 0,
            'countries_count': 0,
            'last_updated': 0
        }
        
        # Mark current time
        reputation['last_updated'] = int(time.time())
        
        # Check against known bad IPs
        if ip_address in self.known_malicious_ips:
            reputation['is_known_abuser'] = True
            reputation['score'] = max(reputation['score'], 90)
        
        # Check against known proxies
        if ip_address in self.known_proxy_ips:
            reputation['is_proxy'] = True
            reputation['score'] = max(reputation['score'], 70)
        
        # Check against known Tor exit nodes
        if ip_address in self.known_tor_exits:
            reputation['is_tor'] = True
            reputation['score'] = max(reputation['score'], 80)
        
        # Get failed logins from the last 24 hours
        recent_failed = self.db.get_recent_failed_logins(ip_address=ip_address, minutes=1440)
        reputation['failed_logins'] = len(recent_failed)
        
        # If many failed logins, increase risk
        if reputation['failed_logins'] > 10:
            reputation['score'] = max(reputation['score'], 75)
        elif reputation['failed_logins'] > 5:
            reputation['score'] = max(reputation['score'], 60)
        
        # In a real implementation, you would:
        # 1. Check against IP reputation services
        # 2. Check for datacenter IP ranges
        # 3. Check for VPN services
        # 4. Analyze historical login countries
        
        # For this example, we'll simulate an external API call for VPN detection
        if not reputation.get('is_vpn'):
            vpn_check_result = self._check_vpn_ip(ip_address)
            if vpn_check_result:
                reputation['is_vpn'] = vpn_check_result
                reputation['score'] = max(reputation['score'], 65)
        
        # For datacenter detection, we'd normally check against known datacenter IP ranges
        # For this example, just use a dummy check
        if ip_address.startswith('192.0.2.') or ip_address.startswith('198.51.100.'):
            reputation['is_datacenter'] = True
        
        # Get distinct countries for this IP (in a real system)
        # Here we'll just simulate it
        if 'countries_count' not in reputation or reputation['countries_count'] == 0:
            reputation['countries_count'] = 1
        
        return reputation
    
    def _check_vpn_ip(self, ip_address):
        """
        Check if an IP is a VPN
        In a real implementation, this would call an external API
        
        Args:
            ip_address (str): IP address to check
            
        Returns:
            bool: True if the IP is a VPN
        """
        # In a real implementation, you'd use a service like IPinfo.io, IPHub, etc.
        # For this example, we'll just do a simple check based on patterns
        
        # Simulate API call with a 5% chance of being a VPN for random IPs
        import random
        if random.random() < 0.05:
            return True
        
        # Check if the IP matches certain patterns
        if ip_address.startswith('10.8.') or ip_address.endswith('.99'):
            return True
        
        return False
    
    def _calculate_risk_score(self, reputation_data):
        """
        Calculate the risk score based on reputation data
        
        Args:
            reputation_data (dict): Reputation data
            
        Returns:
            int: Risk score (0-100)
        """
        # Start with the base score
        score = reputation_data.get('score', 50)
        
        # Adjust based on various factors
        if reputation_data.get('is_known_abuser'):
            score = max(score, 90)
        
        if reputation_data.get('is_tor'):
            score = max(score, 80)
        
        if reputation_data.get('is_proxy') or reputation_data.get('is_vpn'):
            score = max(score, 60)
        
        if reputation_data.get('is_datacenter'):
            score = max(score, 40)
        
        failed_logins = reputation_data.get('failed_logins', 0)
        if failed_logins > 20:
            score = max(score, 90)
        elif failed_logins > 10:
            score = max(score, 75)
        elif failed_logins > 5:
            score = max(score, 60)
        
        countries_count = reputation_data.get('countries_count', 0)
        if countries_count > 5:
            score = max(score, 80)
        elif countries_count > 2:
            score = max(score, 60)
        
        return min(100, score)
    
    def _get_reputation_status(self, risk_score):
        """
        Get reputation status based on risk score
        
        Args:
            risk_score (int): Risk score
            
        Returns:
            str: Reputation status
        """
        if risk_score >= 90:
            return 'critical'
        elif risk_score >= 70:
            return 'high_risk'
        elif risk_score >= 50:
            return 'medium_risk'
        elif risk_score >= 30:
            return 'low_risk'
        else:
            return 'trusted'

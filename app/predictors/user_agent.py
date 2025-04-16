import logging
from user_agents import parse
import re
from app.database import Database

logger = logging.getLogger(__name__)

class UserAgentAnalyzer:
    """
    Analyzes User-Agent strings to detect anomalies and spoofing attempts.
    """
    
    def __init__(self):
        self.db = Database()
        self.known_bots = [
            'googlebot', 'bingbot', 'yandexbot', 'baiduspider', 'twitterbot',
            'facebookexternalhit', 'slackbot', 'discordbot'
        ]
        logger.info("UserAgentAnalyzer initialized")
    
    def analyze(self, user_agent_string):
        """
        Analyze a User-Agent string for suspicious patterns
        
        Args:
            user_agent_string (str): The User-Agent string from HTTP headers
            
        Returns:
            dict: Analysis results including risk score and detected issues
        """
        if not user_agent_string:
            return {
                'risk_score': 90,
                'issues': ['empty_user_agent'],
                'is_suspicious': True,
                'user_agent_type': 'unknown'
            }
        
        # Parse the user agent
        try:
            user_agent = parse(user_agent_string)
            
            # Extract basic information
            browser_family = user_agent.browser.family
            browser_version = '.'.join([str(v) for v in user_agent.browser.version if v is not None])
            os_family = user_agent.os.family
            os_version = '.'.join([str(v) for v in user_agent.os.version if v is not None])
            device_family = user_agent.device.family
            is_mobile = user_agent.is_mobile
            is_tablet = user_agent.is_tablet
            is_pc = user_agent.is_pc
            is_bot = user_agent.is_bot
            
            # Detect issues
            issues = []
            
            # Check for known bot patterns
            if any(bot in user_agent_string.lower() for bot in self.known_bots):
                if not is_bot:
                    issues.append('bot_impersonation')
            
            # Check for uncommon browser/OS combinations
            if self._is_uncommon_combination(browser_family, os_family):
                issues.append('uncommon_browser_os_combination')
            
            # Check for inconsistencies in the User-Agent string
            if self._has_inconsistencies(user_agent_string, browser_family, os_family):
                issues.append('ua_string_inconsistency')
            
            # Check for outdated browsers (security risk)
            if self._is_outdated_browser(browser_family, browser_version):
                issues.append('outdated_browser')
            
            # Calculate risk score based on issues
            risk_score = self._calculate_risk_score(issues)
            
            # Determine user agent type
            ua_type = 'bot' if is_bot else ('mobile' if is_mobile else ('tablet' if is_tablet else 'desktop'))
            
            # Log suspicious User-Agents
            if risk_score > 50:
                logger.warning(f"Suspicious User-Agent detected: {user_agent_string}")
            
            # Prepare response
            return {
                'risk_score': risk_score,
                'issues': issues,
                'is_suspicious': risk_score > 50,
                'user_agent_type': ua_type,
                'browser': {
                    'family': browser_family,
                    'version': browser_version
                },
                'os': {
                    'family': os_family,
                    'version': os_version
                },
                'device': device_family,
                'is_mobile': is_mobile,
                'is_tablet': is_tablet,
                'is_pc': is_pc,
                'is_bot': is_bot
            }
            
        except Exception as e:
            logger.error(f"Error analyzing User-Agent: {str(e)}")
            return {
                'risk_score': 75,
                'issues': ['parsing_error'],
                'is_suspicious': True,
                'user_agent_type': 'unknown',
                'error': str(e)
            }
    
    def _is_uncommon_combination(self, browser_family, os_family):
        """Check if the browser and OS combination is uncommon"""
        uncommon_combinations = [
            ('Safari', 'Windows'),
            ('Edge', 'iOS'),
            ('Internet Explorer', 'Android'),
            ('Internet Explorer', 'iOS'),
            ('Internet Explorer', 'Mac OS X')
        ]
        
        return (browser_family, os_family) in uncommon_combinations
    
    def _has_inconsistencies(self, ua_string, browser_family, os_family):
        """Check for inconsistencies in the User-Agent string"""
        # Example: Check if Chrome UA has Safari token or vice versa
        if browser_family == 'Chrome' and 'Firefox' in ua_string:
            return True
        if browser_family == 'Firefox' and 'Chrome' in ua_string and 'Chromium' not in ua_string:
            return True
        
        # Example: Check if Windows UA claims to be from Mac or vice versa
        if os_family == 'Windows' and ('Mac OS' in ua_string or 'iPhone' in ua_string or 'iPad' in ua_string):
            return True
        if os_family == 'Mac OS X' and 'Windows' in ua_string:
            return True
        
        return False
    
    def _is_outdated_browser(self, browser_family, version):
        """Check if the browser version is outdated"""
        try:
            # Define minimum safe versions for common browsers
            min_versions = {
                'Chrome': '90.0',
                'Firefox': '85.0',
                'Safari': '14.0',
                'Edge': '90.0',
                'Internet Explorer': '11.0'  # All versions are considered outdated
            }
            
            if browser_family not in min_versions:
                return False
            
            min_version = min_versions[browser_family]
            
            # Simple version comparison (for more complex cases, use packaging.version)
            current_parts = [int(p) for p in version.split('.') if p.isdigit()]
            min_parts = [int(p) for p in min_version.split('.') if p.isdigit()]
            
            # Compare major version first, then minor
            for i in range(min(len(current_parts), len(min_parts))):
                if current_parts[i] < min_parts[i]:
                    return True
                elif current_parts[i] > min_parts[i]:
                    return False
            
            return len(current_parts) < len(min_parts)
            
        except Exception as e:
            logger.error(f"Error checking browser version: {str(e)}")
            return False
    
    def _calculate_risk_score(self, issues):
        """Calculate risk score based on detected issues"""
        # Base score
        score = 0
        
        # Add points for each issue
        issue_scores = {
            'empty_user_agent': 90,
            'bot_impersonation': 85,
            'ua_string_inconsistency': 75,
            'uncommon_browser_os_combination': 60,
            'outdated_browser': 40,
            'parsing_error': 75
        }
        
        for issue in issues:
            score = max(score, issue_scores.get(issue, 0))
        
        return score

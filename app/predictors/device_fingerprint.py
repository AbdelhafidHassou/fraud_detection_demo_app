import logging
import json
from app.database import Database

logger = logging.getLogger(__name__)

class DeviceFingerprinter:
    """
    Server-side component for device fingerprinting analysis.
    Processes fingerprint data collected by the client-side JavaScript.
    """
    
    def __init__(self):
        self.db = Database()
        logger.info("DeviceFingerprinter initialized")
    
    def analyze(self, fingerprint_data):
        """
        Analyze a device fingerprint for suspicious patterns
        
        Args:
            fingerprint_data (dict): Device fingerprint collected by the client
            
        Returns:
            dict: Analysis results including risk score and detected issues
        """
        try:
            # Validate input
            if not fingerprint_data or not isinstance(fingerprint_data, dict):
                return {
                    'risk_score': 75,
                    'issues': ['invalid_fingerprint_data'],
                    'is_suspicious': True,
                    'device_id': None
                }
            
            # Extract fingerprint hash or generate one if missing
            device_id = fingerprint_data.get('hash')
            
            if not device_id:
                logger.warning("Fingerprint data missing hash, generating one")
                device_id = self._generate_device_id(fingerprint_data)
            
            # Check if this is a known device
            is_known_device, device_history = self._check_known_device(device_id)
            
            # Detect issues
            issues = []
            
            # Look for reported inconsistencies
            if 'inconsistencies' in fingerprint_data and fingerprint_data['inconsistencies']:
                issues.extend(fingerprint_data['inconsistencies'])
            
            # Check for automation signs
            if self._check_automation_signs(fingerprint_data):
                issues.append('automation_detected')
            
            # Check for browser spoofing
            if self._check_browser_spoofing(fingerprint_data):
                issues.append('browser_spoofing')
            
            # Check for VPN/proxy usage
            if self._check_proxy_signs(fingerprint_data):
                issues.append('proxy_detected')
            
            # Check for fingerprint tampering
            if self._check_fingerprint_tampering(fingerprint_data):
                issues.append('fingerprint_tampering')
            
            # Calculate confidence score (how reliable is this fingerprint)
            confidence_score = self._calculate_confidence_score(fingerprint_data)
            
            # Calculate risk score based on issues
            risk_score = self._calculate_risk_score(issues, is_known_device)
            
            # Store fingerprint for future reference
            self._store_fingerprint(device_id, fingerprint_data, issues)
            
            # Prepare response
            result = {
                'risk_score': risk_score,
                'issues': issues,
                'is_suspicious': risk_score > 50,
                'device_id': device_id,
                'is_known_device': is_known_device,
                'confidence_score': confidence_score
            }
            
            # Add device history for known devices
            if is_known_device and device_history:
                result['device_history'] = {
                    'first_seen': device_history.get('first_seen'),
                    'last_seen': device_history.get('last_seen'),
                    'visit_count': device_history.get('visit_count', 1)
                }
            
            # Log suspicious devices
            if risk_score > 70:
                logger.warning(f"Suspicious device detected: {device_id} with issues: {issues}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing device fingerprint: {str(e)}")
            return {
                'risk_score': 60,
                'issues': ['analysis_error'],
                'is_suspicious': True,
                'device_id': None,
                'error': str(e)
            }
    
    def _generate_device_id(self, fingerprint_data):
        """Generate a device ID from fingerprint data"""
        # Create a simplified version of the fingerprint with stable properties
        stable_data = {}
        
        if 'userAgent' in fingerprint_data:
            stable_data['userAgent'] = fingerprint_data['userAgent']
        
        if 'screen' in fingerprint_data:
            stable_data['screen'] = fingerprint_data['screen']
        
        if 'language' in fingerprint_data:
            stable_data['language'] = fingerprint_data['language']
        
        if 'timezone' in fingerprint_data:
            stable_data['timezone'] = fingerprint_data['timezone'].get('offset')
        
        if 'webgl' in fingerprint_data and fingerprint_data['webgl'].get('supported'):
            stable_data['webgl'] = {
                'vendor': fingerprint_data['webgl'].get('vendor'),
                'renderer': fingerprint_data['webgl'].get('renderer')
            }
        
        if 'canvasHash' in fingerprint_data:
            stable_data['canvasHash'] = fingerprint_data['canvasHash']
        
        # Generate a hash from the stable data
        import hashlib
        data_str = json.dumps(stable_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _check_known_device(self, device_id):
        """
        Check if this is a known device
        
        Returns:
            tuple: (is_known_device, device_history)
        """
        # In a real implementation, this would check a database
        device_data = self.db.get_device_data(device_id)
        
        if device_data:
            return True, device_data
        
        return False, None
    
    def _check_automation_signs(self, fingerprint_data):
        """Check for signs of automation or headless browsers"""
        # Look for direct signs of automation
        if 'inconsistencies' in fingerprint_data:
            if 'automation_detected' in fingerprint_data['inconsistencies']:
                return True
            if 'missing_graphics_support' in fingerprint_data['inconsistencies']:
                return True
            if 'missing_audio_support' in fingerprint_data['inconsistencies']:
                return True
        
        # Check for WebDriver property
        if 'webdriver' in fingerprint_data and fingerprint_data['webdriver']:
            return True
        
        # Check for suspicious features
        features = fingerprint_data.get('features', {})
        
        if features.get('hardwareConcurrency') == 0:
            return True
        
        # Check for missing plugins (often the case in automation)
        plugins = fingerprint_data.get('plugins', [])
        if len(plugins) == 0 and 'chrome' in fingerprint_data.get('userAgent', '').lower():
            return True
        
        return False
    
    def _check_browser_spoofing(self, fingerprint_data):
        """Check for signs of browser spoofing"""
        # Already reported inconsistencies
        if 'inconsistencies' in fingerprint_data:
            if 'ua_platform_mismatch' in fingerprint_data['inconsistencies']:
                return True
            if 'browser_plugin_mismatch' in fingerprint_data['inconsistencies']:
                return True
        
        # Check for mismatched browser signs
        ua = fingerprint_data.get('userAgent', '').lower()
        
        # Check for WebGL vendor/renderer inconsistencies
        webgl = fingerprint_data.get('webgl', {})
        if webgl.get('supported'):
            vendor = webgl.get('vendor', '').lower()
            renderer = webgl.get('renderer', '').lower()
            
            # IE claiming to have WebGL
            if 'trident' in ua or 'msie' in ua:
                if webgl.get('supported'):
                    return True
            
            # Mobile claiming to have desktop GPU
            if 'mobile' in ua or 'android' in ua:
                desktop_gpus = ['nvidia', 'amd', 'intel hd graphics']
                if any(gpu in renderer for gpu in desktop_gpus):
                    return True
        
        return False
    
    def _check_proxy_signs(self, fingerprint_data):
        """Check for signs of VPN or proxy usage"""
        # This requires external data not available in the fingerprint itself
        # In a real implementation, you would check the IP against known proxy/VPN IPs
        # or look for timezone/language/locale mismatches with the IP geolocation
        
        # For this example, we'll just return False
        return False
    
    def _check_fingerprint_tampering(self, fingerprint_data):
        """Check for signs of fingerprint tampering or evasion"""
        # Check for missing expected properties
        required_props = ['userAgent', 'language', 'screen', 'timezone']
        
        for prop in required_props:
            if prop not in fingerprint_data:
                return True
        
        # Check for canvas/WebGL blocking (privacy tools)
        if 'canvasSupported' in fingerprint_data and not fingerprint_data['canvasSupported']:
            # Check if it's due to an older browser or if it's likely blocking
            ua = fingerprint_data.get('userAgent', '').lower()
            if not ('msie' in ua and 'trident' in ua):  # Not old IE
                return True
        
        # Look for blank/generic fingerprint data
        screen = fingerprint_data.get('screen', {})
        if screen.get('width') == 1024 and screen.get('height') == 768:
            # This is a very common spoofed resolution
            return True
        
        return False
    
    def _calculate_confidence_score(self, fingerprint_data):
        """
        Calculate a confidence score for the fingerprint
        
        Returns:
            float: Score from 0.0 to 1.0
        """
        score = 1.0
        deductions = []
        
        # Check for missing sections that reduce confidence
        if 'canvasHash' not in fingerprint_data:
            deductions.append(0.2)
        
        if 'webgl' not in fingerprint_data or not fingerprint_data.get('webgl', {}).get('supported'):
            deductions.append(0.2)
        
        if 'audio' not in fingerprint_data or not fingerprint_data.get('audio', {}).get('supported'):
            deductions.append(0.1)
        
        if 'inconsistencies' in fingerprint_data and fingerprint_data['inconsistencies']:
            deductions.append(0.3)
        
        # Apply deductions
        for deduction in deductions:
            score *= (1 - deduction)
        
        return max(0.1, round(score, 2))  # Ensure minimum confidence of 0.1
    
    def _calculate_risk_score(self, issues, is_known_device):
        """Calculate risk score based on detected issues"""
        if not issues and is_known_device:
            return 0  # Known device with no issues
        
        # Base score depends on whether it's a known device
        base_score = 25 if is_known_device else 50
        
        # Add points for each issue
        issue_scores = {
            'invalid_fingerprint_data': 75,
            'automation_detected': 85,
            'browser_spoofing': 80,
            'proxy_detected': 50,
            'fingerprint_tampering': 70,
            'ua_platform_mismatch': 75,
            'browser_plugin_mismatch': 65,
            'mobile_mismatch': 70,
            'unrealistic_hardware': 60,
            'missing_graphics_support': 65,
            'missing_audio_support': 40,
            'analysis_error': 60
        }
        
        max_issue_score = 0
        for issue in issues:
            issue_score = issue_scores.get(issue, 50)
            max_issue_score = max(max_issue_score, issue_score)
        
        # Calculate final score
        score = base_score
        if max_issue_score > base_score:
            score = max_issue_score
        
        return score
    
    def _store_fingerprint(self, device_id, fingerprint_data, issues):
        """Store fingerprint for future reference"""
        import time
        
        current_time = int(time.time())
        
        # In a real implementation, store in the database
        device_data = self.db.get_device_data(device_id) or {}
        
        if not device_data:
            # New device
            device_data = {
                'device_id': device_id,
                'first_seen': current_time,
                'last_seen': current_time,
                'visit_count': 1,
                'fingerprints': [fingerprint_data],
                'issues_history': issues
            }
        else:
            # Update existing device
            device_data['last_seen'] = current_time
            device_data['visit_count'] = device_data.get('visit_count', 0) + 1
            
            # Store most recent fingerprint
            fingerprints = device_data.get('fingerprints', [])
            fingerprints.append(fingerprint_data)
            
            # Keep only the most recent 5 fingerprints
            device_data['fingerprints'] = fingerprints[-5:]
            
            # Update issues history
            if issues:
                device_data['issues_history'] = list(set(device_data.get('issues_history', []) + issues))
        
        # Store the updated data
        self.db.store_device_data(device_id, device_data)

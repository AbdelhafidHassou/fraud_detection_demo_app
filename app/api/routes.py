from flask import Blueprint, request, jsonify
import logging
import time

# Import predictors
from app.predictors.user_agent import UserAgentAnalyzer
from app.predictors.geo_velocity import GeoVelocityDetector
from app.predictors.access_time import AccessTimeAnalyzer
from app.predictors.password_attack import PasswordAttackDetector
from app.predictors.device_fingerprint import DeviceFingerprinter
from app.predictors.account_velocity import AccountVelocityMonitor
from app.predictors.session_anomaly import SessionAnomalyDetector
from app.predictors.ip_reputation import IPReputationChecker

# Logger
logger = logging.getLogger(__name__)

# Create blueprint
api = Blueprint('api', __name__)

# Initialize predictors
user_agent_analyzer = UserAgentAnalyzer()
geo_velocity_detector = GeoVelocityDetector()
access_time_analyzer = AccessTimeAnalyzer()
password_attack_detector = PasswordAttackDetector()
device_fingerprinter = DeviceFingerprinter()
account_velocity_monitor = AccountVelocityMonitor()
session_anomaly_detector = SessionAnomalyDetector()
ip_reputation_checker = IPReputationChecker()

@api.route('/analyze', methods=['POST'])
def analyze_request():
    """
    Main endpoint to analyze a login/authentication request for fraud
    """
    try:
        data = request.json
        
        # Get request information
        user_id = data.get('user_id')
        ip_address = data.get('ip_address', request.remote_addr)
        user_agent = data.get('user_agent', request.headers.get('User-Agent'))
        timestamp = data.get('timestamp', int(time.time()))
        session_events = data.get('session_events', [])
        email = data.get('email', '')
        
        # Run all predictors
        results = {
            'user_agent': user_agent_analyzer.analyze(user_agent),
            'geo_velocity': geo_velocity_detector.detect(user_id, ip_address, timestamp),
            'access_time': access_time_analyzer.analyze(user_id, timestamp),
            'password_attack': password_attack_detector.detect(user_id, ip_address),
            'device': device_fingerprinter.analyze(data.get('device_fingerprint', {})),
            'account_velocity': account_velocity_monitor.check(ip_address, email),
            'session': session_anomaly_detector.detect(user_id, session_events),
            'ip_reputation': ip_reputation_checker.check(ip_address)
        }
        
        # Calculate overall risk score (weighted average)
        weights = {
            'user_agent': 0.10,
            'geo_velocity': 0.20,
            'access_time': 0.10,
            'password_attack': 0.15,
            'device': 0.15,
            'account_velocity': 0.10,
            'session': 0.10,
            'ip_reputation': 0.10
        }
        
        weighted_sum = sum(
            results[key].get('risk_score', 0) * weights[key]
            for key in weights
        )
        
        overall_risk = round(weighted_sum)
        
        # Prepare response
        response = {
            'overall_risk': overall_risk,
            'risk_level': get_risk_level(overall_risk),
            'predictors': results,
            'recommendation': get_recommendation(overall_risk)
        }
        
        # Log the analysis results
        logger.info(f"Risk analysis for user {user_id}: {overall_risk}")
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error analyzing request: {str(e)}")
        return jsonify({'error': str(e)}), 500


@api.route('/analyze/user-agent', methods=['POST'])
def analyze_user_agent():
    """Endpoint to analyze user agent only"""
    try:
        data = request.json
        user_agent = data.get('user_agent', request.headers.get('User-Agent'))
        
        result = user_agent_analyzer.analyze(user_agent)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing user agent: {str(e)}")
        return jsonify({'error': str(e)}), 500


@api.route('/analyze/geo-velocity', methods=['POST'])
def analyze_geo_velocity():
    """Endpoint to analyze geo velocity only"""
    try:
        data = request.json
        user_id = data.get('user_id')
        ip_address = data.get('ip_address', request.remote_addr)
        timestamp = data.get('timestamp', int(time.time()))
        
        result = geo_velocity_detector.detect(user_id, ip_address, timestamp)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing geo velocity: {str(e)}")
        return jsonify({'error': str(e)}), 500


@api.route('/analyze/access-time', methods=['POST'])
def analyze_access_time():
    """Endpoint to analyze access time only"""
    try:
        data = request.json
        user_id = data.get('user_id')
        timestamp = data.get('timestamp', int(time.time()))
        
        result = access_time_analyzer.analyze(user_id, timestamp)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing access time: {str(e)}")
        return jsonify({'error': str(e)}), 500


@api.route('/analyze/password-attack', methods=['POST'])
def analyze_password_attack():
    """Endpoint to analyze password attacks only"""
    try:
        data = request.json
        user_id = data.get('user_id')
        ip_address = data.get('ip_address', request.remote_addr)
        
        result = password_attack_detector.detect(user_id, ip_address)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing password attacks: {str(e)}")
        return jsonify({'error': str(e)}), 500


@api.route('/analyze/device-fingerprint', methods=['POST'])
def analyze_device_fingerprint():
    """Endpoint to analyze device fingerprint only"""
    try:
        data = request.json
        fingerprint = data.get('device_fingerprint', {})
        
        result = device_fingerprinter.analyze(fingerprint)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing device fingerprint: {str(e)}")
        return jsonify({'error': str(e)}), 500


@api.route('/analyze/account-velocity', methods=['POST'])
def analyze_account_velocity():
    """Endpoint to analyze account velocity only"""
    try:
        data = request.json
        ip_address = data.get('ip_address', request.remote_addr)
        email = data.get('email', '')
        
        result = account_velocity_monitor.check(ip_address, email)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing account velocity: {str(e)}")
        return jsonify({'error': str(e)}), 500


@api.route('/analyze/session-anomaly', methods=['POST'])
def analyze_session_anomaly():
    """Endpoint to analyze session anomalies only"""
    try:
        data = request.json
        user_id = data.get('user_id')
        session_events = data.get('session_events', [])
        
        result = session_anomaly_detector.detect(user_id, session_events)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing session anomalies: {str(e)}")
        return jsonify({'error': str(e)}), 500


@api.route('/analyze/ip-reputation', methods=['POST'])
def analyze_ip_reputation():
    """Endpoint to analyze IP reputation only"""
    try:
        data = request.json
        ip_address = data.get('ip_address', request.remote_addr)
        
        result = ip_reputation_checker.check(ip_address)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing IP reputation: {str(e)}")
        return jsonify({'error': str(e)}), 500


def get_risk_level(score):
    """Convert numerical risk score to categorical level"""
    if score < 25:
        return "low"
    elif score < 50:
        return "medium"
    elif score < 75:
        return "high"
    else:
        return "critical"


def get_recommendation(score):
    """Provide action recommendation based on risk score"""
    if score < 25:
        return "allow"
    elif score < 50:
        return "monitor"
    elif score < 75:
        return "challenge"
    else:
        return "block"

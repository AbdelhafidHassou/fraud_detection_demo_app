from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import os
from dotenv import load_dotenv

# Import predictors
from app.predictors.user_agent import UserAgentAnalyzer
from app.predictors.geo_velocity import GeoVelocityDetector
from app.predictors.access_time import AccessTimeAnalyzer
from app.predictors.password_attack import PasswordAttackDetector
from app.predictors.device_fingerprint import DeviceFingerprinter
from app.predictors.account_velocity import AccountVelocityMonitor
from app.predictors.session_anomaly import SessionAnomalyDetector
from app.predictors.ip_reputation import IPReputationChecker

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("data/logs/app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize predictors
user_agent_analyzer = UserAgentAnalyzer()
geo_velocity_detector = GeoVelocityDetector()
access_time_analyzer = AccessTimeAnalyzer()
password_attack_detector = PasswordAttackDetector()
device_fingerprinter = DeviceFingerprinter()
account_velocity_monitor = AccountVelocityMonitor()
session_anomaly_detector = SessionAnomalyDetector()
ip_reputation_checker = IPReputationChecker()

@app.route('/api/analyze', methods=['POST'])
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
        timestamp = data.get('timestamp')
        session_events = data.get('session_events', [])
        
        # Run all predictors
        results = {
            'user_agent': user_agent_analyzer.analyze(user_agent),
            'geo_velocity': geo_velocity_detector.detect(user_id, ip_address, timestamp),
            'access_time': access_time_analyzer.analyze(user_id, timestamp),
            'password_attack': password_attack_detector.detect(user_id, ip_address),
            'device': device_fingerprinter.analyze(data.get('device_fingerprint', {})),
            'account_velocity': account_velocity_monitor.check(ip_address, data.get('email', '')),
            'session': session_anomaly_detector.detect(user_id, session_events),
            'ip_reputation': ip_reputation_checker.check(ip_address)
        }
        
        # Calculate overall risk score (simple average for now)
        risk_scores = [
            result.get('risk_score', 0) 
            for result in results.values() 
            if 'risk_score' in result
        ]
        
        overall_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
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


if __name__ == '__main__':
    # Create log directory if not exists
    os.makedirs('data/logs', exist_ok=True)
    
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000)

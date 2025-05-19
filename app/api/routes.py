from flask import Blueprint, request, jsonify
import logging
import time
import sys
import os
import json

# Add MongoDB-related imports
from app.main_app import get_recommendation, get_risk_level
from app.utils.db_utils import get_mongodb_client, MockDatabase
from app.utils.test_data_generator import initialize_if_empty

# Import ML predictors
from app.predictors.ml_access_time import MLAccessTimeAnalyzer
from app.predictors.ml_auth_behavior import MLAuthBehaviorAnalyzer
from app.predictors.ml_session_anomaly import MLSessionAnomalyDetector
from core.config import settings

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

# Get MongoDB connection
client, mongodb = get_mongodb_client()

# Initialize database if empty
initialize_if_empty(mongodb)

# Initialize predictors
user_agent_analyzer = UserAgentAnalyzer()
geo_velocity_detector = GeoVelocityDetector()
access_time_analyzer = AccessTimeAnalyzer()
password_attack_detector = PasswordAttackDetector()
device_fingerprinter = DeviceFingerprinter()
account_velocity_monitor = AccountVelocityMonitor()
session_anomaly_detector = SessionAnomalyDetector()
ip_reputation_checker = IPReputationChecker()

# Initialize ML predictors
ml_access_time_analyzer = MLAccessTimeAnalyzer()
ml_auth_behavior_analyzer = MLAuthBehaviorAnalyzer()
ml_session_anomaly_detector = MLSessionAnomalyDetector()

# [Keep all your original API route handlers]

# Add new MongoDB-related endpoints

@api.route('/database-stats', methods=['GET'])
def get_database_stats():
    """Get statistics about the current database"""
    try:
        stats = {
            'users': mongodb.users.count_documents({}),
            'devices': mongodb.devices.count_documents({}),
            'logins': mongodb.logins.count_documents({}),
            'failed_logins': mongodb.failed_logins.count_documents({}),
            'ip_data': mongodb.ip_data.count_documents({}),
            'user_models': mongodb.user_models.count_documents({}),
            'registrations': mongodb.registrations.count_documents({}),
            'sessions': mongodb.sessions.count_documents({})
        }
        
        # Fetch user list for dropdown (limited to basic info)
        user_list = list(mongodb.users.find({}, {'_id': 0, 'user_id': 1, 'email': 1}))
        
        return jsonify({
            'status': 'success',
            'stats': stats,
            'userList': user_list
        })
    except Exception as e:
        logger.error(f"Error getting database stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api.route('/user/<user_id>', methods=['GET'])
def get_user_data(user_id):
    """Get all data for a specific user"""
    try:
        # Get basic user information
        user = mongodb.users.find_one({'user_id': user_id})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Convert ObjectId to string for JSON serialization
        user['_id'] = str(user['_id'])
        
        # Get user's login history
        logins = list(mongodb.logins.find({'user_id': user_id}).sort('timestamp', -1))
        for login in logins:
            login['_id'] = str(login['_id'])
        
        # Get user's devices
        devices = list(mongodb.devices.find({'user_id': user_id}))
        for device in devices:
            device['_id'] = str(device['_id'])
        
        # Get user's behavior model
        model = mongodb.user_models.find_one({'user_id': user_id})
        if model:
            model['_id'] = str(model['_id'])
        
        # Get user's session events
        sessions = {}
        events = list(mongodb.sessions.find({'user_id': user_id}))
        for event in events:
            event['_id'] = str(event['_id'])
            session_id = event['session_id']
            if session_id not in sessions:
                sessions[session_id] = []
            sessions[session_id].append(event)
        
        # Get failed logins for user
        failed_logins = list(mongodb.failed_logins.find({'username': user_id}))
        for failed in failed_logins:
            failed['_id'] = str(failed['_id'])
        
        # Assemble the complete user profile
        result = {
            'user': user,
            'logins': logins,
            'devices': devices,
            'behavior_model': model,
            'sessions': list(sessions.values()),
            'failed_logins': failed_logins
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error retrieving user data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api.route('/analyze-user/<user_id>', methods=['POST'])
def analyze_user(user_id):
    """Run full fraud analysis for a specific user"""
    try:
        # Get request data
        data = request.json or {}
        ip_address = data.get('ip_address', request.remote_addr)
        user_agent = data.get('user_agent', request.headers.get('User-Agent'))
        device_fingerprint = data.get('device_fingerprint', {})
        session_events = data.get('session_events', [])
        
        # Get user
        user = mongodb.users.find_one({'user_id': user_id})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get various pieces of data
        devices = list(mongodb.devices.find({'user_id': user_id}))
        logins = list(mongodb.logins.find({'user_id': user_id}).sort('timestamp', -1).limit(5))
        
        # Get IP reputation
        ip_data = mongodb.ip_data.find_one({'ip_address': ip_address})
        ip_reputation = None
        if ip_data and 'reputation' in ip_data:
            ip_reputation = ip_data['reputation']
        
        # Create mock database instance for predictors
        mock_db = MockDatabase(mongodb)
        
        # Patch database in predictors
        import app.predictors.user_agent
        import app.predictors.geo_velocity
        import app.predictors.access_time
        import app.predictors.device_fingerprint
        import app.predictors.ip_reputation
        import app.predictors.password_attack
        import app.predictors.account_velocity
        import app.predictors.session_anomaly
        
        # Replace Database instances with our mock
        app.predictors.user_agent.Database = lambda: mock_db
        app.predictors.geo_velocity.Database = lambda: mock_db
        app.predictors.access_time.Database = lambda: mock_db
        app.predictors.device_fingerprint.Database = lambda: mock_db
        app.predictors.ip_reputation.Database = lambda: mock_db
        app.predictors.password_attack.Database = lambda: mock_db
        app.predictors.account_velocity.Database = lambda: mock_db
        app.predictors.session_anomaly.Database = lambda: mock_db
        
        # Get session events if not provided in request
        if not session_events:
            session_events = list(mongodb.sessions.find({'user_id': user_id}))
            
        # Get device fingerprint if not provided
        if not device_fingerprint and devices and 'fingerprints' in devices[0] and devices[0]['fingerprints']:
            device_fingerprint = devices[0]['fingerprints'][0]
        
        # Current timestamp for analysis
        current_timestamp = int(time.time())
        
        # Run all predictors
        results = {}
        
        # User agent analysis
        results['user_agent'] = user_agent_analyzer.analyze(user_agent)
        
        # Geo-velocity analysis
        results['geo_velocity'] = geo_velocity_detector.detect(user_id, ip_address, current_timestamp)
        
        # Access time analysis
        results['access_time'] = access_time_analyzer.analyze(user_id, current_timestamp)
        
        # Device fingerprint analysis
        results['device'] = device_fingerprinter.analyze(device_fingerprint)
        
        # IP reputation analysis
        results['ip_reputation'] = ip_reputation_checker.check(ip_address)
        
        # Password attack analysis
        results['password_attack'] = password_attack_detector.detect(user_id, ip_address)
        
        # Account velocity analysis
        results['account_velocity'] = account_velocity_monitor.check(ip_address, user.get('email', ''))
        
        # Session anomaly analysis
        results['session'] = session_anomaly_detector.detect(user_id, session_events)
        
        # Calculate weighted risk score
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
        
        # Determine risk level and recommendation
        risk_level = get_risk_level(overall_risk)
        recommendation = get_recommendation(overall_risk)
        
        # Prepare response
        response = {
            'overall_risk': overall_risk,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'predictors': results,
            'user_info': {
                'user_id': user_id,
                'email': user.get('email'),
                'known_devices_count': len(devices),
                'login_history_count': mongodb.logins.count_documents({'user_id': user_id})
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error analyzing user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api.route('/generate-database', methods=['POST'])
def generate_test_database():
    """API endpoint to regenerate the test database"""
    try:
        from app.utils.test_data_generator import generate_database
        stats = generate_database(mongodb)
        return jsonify({
            'status': 'success',
            'message': 'Test database generated successfully',
            'stats': stats
        })
    except Exception as e:
        logger.error(f"Error generating database: {str(e)}")
        return jsonify({'error': str(e)}), 500
import pymongo
import random
import time
import uuid
from datetime import datetime, timedelta
import ipaddress
from faker import Faker
import logging
import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app - REMOVE THE DUPLICATE INITIALIZATION
app = Flask(__name__)
CORS(app)

# Initialize Faker
fake = Faker()

# MongoDB connection
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
DB_NAME = os.environ.get('MONGO_DB', 'fraud_detection_test')

client = pymongo.MongoClient(MONGO_URI)
db = client[DB_NAME]

# Serve static files
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

# Constants for data generation
NUM_USERS = 100
NUM_DEVICES_PER_USER = 3
NUM_LOGINS_PER_USER = 20
NUM_FAILED_LOGINS = 200
NUM_KNOWN_BAD_IPS = 50
NUM_REGISTRATIONS = 300

# Functions to generate test data
def generate_ip():
    """Generate a random IP address"""
    return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

def generate_timestamp(days_back=30):
    """Generate a random timestamp within the last X days"""
    now = datetime.now()
    random_days = random.uniform(0, days_back)
    random_time = now - timedelta(days=random_days)
    return int(random_time.timestamp())

def generate_location(ip_address):
    """Generate a random geolocation for an IP address"""
    # In a real system, this would use a GeoIP database
    continents = ['North America', 'Europe', 'Asia', 'South America', 'Africa', 'Australia']
    continent = random.choice(continents)
    
    # Different location options based on continent
    locations = {
        'North America': {
            'countries': ['USA', 'Canada', 'Mexico'],
            'cities': {
                'USA': ['New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix'],
                'Canada': ['Toronto', 'Montreal', 'Vancouver', 'Calgary', 'Ottawa'],
                'Mexico': ['Mexico City', 'Guadalajara', 'Monterrey', 'Puebla', 'Tijuana']
            },
            'lat_range': (25.0, 50.0),
            'long_range': (-125.0, -70.0)
        },
        'Europe': {
            'countries': ['UK', 'France', 'Germany', 'Italy', 'Spain'],
            'cities': {
                'UK': ['London', 'Manchester', 'Birmingham', 'Glasgow', 'Liverpool'],
                'France': ['Paris', 'Marseille', 'Lyon', 'Toulouse', 'Nice'],
                'Germany': ['Berlin', 'Hamburg', 'Munich', 'Cologne', 'Frankfurt'],
                'Italy': ['Rome', 'Milan', 'Naples', 'Turin', 'Palermo'],
                'Spain': ['Madrid', 'Barcelona', 'Valencia', 'Seville', 'Zaragoza']
            },
            'lat_range': (36.0, 60.0),
            'long_range': (-10.0, 30.0)
        },
        'Asia': {
            'countries': ['China', 'Japan', 'India', 'South Korea', 'Thailand'],
            'cities': {
                'China': ['Beijing', 'Shanghai', 'Guangzhou', 'Shenzhen', 'Chengdu'],
                'Japan': ['Tokyo', 'Osaka', 'Kyoto', 'Yokohama', 'Sapporo'],
                'India': ['Mumbai', 'Delhi', 'Bangalore', 'Hyderabad', 'Chennai'],
                'South Korea': ['Seoul', 'Busan', 'Incheon', 'Daegu', 'Daejeon'],
                'Thailand': ['Bangkok', 'Chiang Mai', 'Phuket', 'Pattaya', 'Krabi']
            },
            'lat_range': (10.0, 50.0),
            'long_range': (70.0, 140.0)
        },
        'South America': {
            'countries': ['Brazil', 'Argentina', 'Colombia', 'Chile', 'Peru'],
            'cities': {
                'Brazil': ['São Paulo', 'Rio de Janeiro', 'Brasília', 'Salvador', 'Fortaleza'],
                'Argentina': ['Buenos Aires', 'Córdoba', 'Rosario', 'Mendoza', 'La Plata'],
                'Colombia': ['Bogotá', 'Medellín', 'Cali', 'Barranquilla', 'Cartagena'],
                'Chile': ['Santiago', 'Valparaíso', 'Concepción', 'La Serena', 'Antofagasta'],
                'Peru': ['Lima', 'Arequipa', 'Trujillo', 'Chiclayo', 'Piura']
            },
            'lat_range': (-55.0, 10.0),
            'long_range': (-80.0, -35.0)
        },
        'Africa': {
            'countries': ['South Africa', 'Nigeria', 'Egypt', 'Kenya', 'Morocco'],
            'cities': {
                'South Africa': ['Johannesburg', 'Cape Town', 'Durban', 'Pretoria', 'Port Elizabeth'],
                'Nigeria': ['Lagos', 'Kano', 'Ibadan', 'Abuja', 'Port Harcourt'],
                'Egypt': ['Cairo', 'Alexandria', 'Giza', 'Shubra El-Kheima', 'Port Said'],
                'Kenya': ['Nairobi', 'Mombasa', 'Kisumu', 'Nakuru', 'Eldoret'],
                'Morocco': ['Casablanca', 'Rabat', 'Fes', 'Marrakesh', 'Tangier']
            },
            'lat_range': (-35.0, 35.0),
            'long_range': (-20.0, 50.0)
        },
        'Australia': {
            'countries': ['Australia', 'New Zealand'],
            'cities': {
                'Australia': ['Sydney', 'Melbourne', 'Brisbane', 'Perth', 'Adelaide'],
                'New Zealand': ['Auckland', 'Wellington', 'Christchurch', 'Hamilton', 'Tauranga']
            },
            'lat_range': (-45.0, -10.0),
            'long_range': (115.0, 180.0)
        }
    }
    
    # Generate random location data
    location_data = locations[continent]
    country = random.choice(location_data['countries'])
    city = random.choice(location_data['cities'][country])
    latitude = random.uniform(*location_data['lat_range'])
    longitude = random.uniform(*location_data['long_range'])
    
    return {
        'country': country,
        'city': city,
        'latitude': latitude,
        'longitude': longitude,
        'postal_code': fake.postcode(),
        'timezone': fake.timezone()
    }

def generate_user_agent():
    """Generate a random user agent string"""
    browsers = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
    ]
    return random.choice(browsers)

def generate_device_fingerprint():
    """Generate a random device fingerprint"""
    ua = generate_user_agent()
    
    # Decide if this is a normal or suspicious fingerprint
    is_suspicious = random.random() < 0.1  # 10% chance of being suspicious
    
    # Generate inconsistencies for suspicious fingerprints
    inconsistencies = []
    if is_suspicious:
        possible_inconsistencies = [
            'automation_detected',
            'browser_spoofing',
            'ua_platform_mismatch',
            'missing_graphics_support',
            'fingerprint_tampering',
            'missing_audio_support'
        ]
        # Add 1-3 inconsistencies
        for _ in range(random.randint(1, 3)):
            if possible_inconsistencies:
                inconsistency = random.choice(possible_inconsistencies)
                inconsistencies.append(inconsistency)
                possible_inconsistencies.remove(inconsistency)
    
    # Generate the fingerprint
    fingerprint = {
        'userAgent': ua,
        'language': random.choice(['en-US', 'en-GB', 'fr-FR', 'de-DE', 'es-ES', 'zh-CN', 'ja-JP']),
        'platform': random.choice(['Win32', 'MacIntel', 'Linux x86_64', 'iPhone', 'iPad', 'Android']),
        'timezone': {
            'offset': random.choice([-480, -420, -360, -300, -240, -120, 0, 60, 120, 180, 240, 300, 360, 480, 540, 600]),
            'timezone': fake.timezone()
        },
        'screen': {
            'width': random.choice([1366, 1440, 1536, 1600, 1680, 1920, 2560, 3440, 3840]),
            'height': random.choice([768, 900, 1024, 1080, 1200, 1440, 2160]),
            'colorDepth': random.choice([24, 32]),
            'pixelRatio': random.choice([1, 1.5, 2, 3])
        },
        'canvasSupported': not is_suspicious or random.random() > 0.3,  # Only sometimes disabled for suspicious
        'webgl': {
            'supported': not is_suspicious or random.random() > 0.3,  # Only sometimes disabled for suspicious
            'vendor': 'Google Inc.' if not is_suspicious else None,
            'renderer': 'ANGLE (Intel, Intel(R) HD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)' if not is_suspicious else None
        },
        'audio': {
            'supported': not is_suspicious or random.random() > 0.3  # Only sometimes disabled for suspicious
        },
        'inconsistencies': inconsistencies
    }
    
    # Generate a device ID (hash)
    device_id = str(uuid.uuid4())
    
    return device_id, fingerprint

def generate_session_events():
    """Generate a random sequence of session events"""
    common_events = [
        'login',
        'view_dashboard',
        'view_account',
        'view_transactions',
        'view_profile',
        'logout'
    ]
    
    suspicious_events = [
        'change_email',
        'change_password',
        'add_payment_method',
        'large_transaction',
        'export_data',
        'disable_2fa'
    ]
    
    # Decide if this is a normal or suspicious session
    is_suspicious = random.random() < 0.1  # 10% chance of being suspicious
    
    # Generate session length
    if is_suspicious:
        session_length = random.randint(4, 10)  # Suspicious sessions tend to be longer
    else:
        session_length = random.randint(2, 6)  # Normal sessions
    
    # Generate events
    events = []
    
    # Always start with login
    events.append({
        'type': 'login',
        'timestamp': int(time.time()) - random.randint(60, 3600)  # Between 1 minute and 1 hour ago
    })
    
    # Generate middle events
    available_events = common_events.copy()
    if is_suspicious:
        available_events.extend(suspicious_events)
    
    for i in range(session_length - 2):  # -2 because we manually add login and logout
        event_type = random.choice(available_events)
        # If we picked a suspicious event, remove it to avoid repetition
        if event_type in suspicious_events:
            available_events.remove(event_type)
        
        # Add the event with a timestamp that's after the previous event
        events.append({
            'type': event_type,
            'timestamp': events[-1]['timestamp'] + random.randint(30, 300)  # 30 seconds to 5 minutes after previous
        })
    
    # Always end with logout (usually)
    if random.random() < 0.9:  # 90% chance of having logout
        events.append({
            'type': 'logout',
            'timestamp': events[-1]['timestamp'] + random.randint(30, 300)
        })
    
    return events

def generate_reputation_data(ip_address, is_malicious=False):
    """Generate IP reputation data"""
    # Base reputation
    if is_malicious:
        is_proxy = random.random() < 0.5
        is_tor = random.random() < 0.3
        is_datacenter = random.random() < 0.6
        is_vpn = random.random() < 0.7
        is_known_abuser = True
        score = random.randint(70, 95)
    else:
        is_proxy = random.random() < 0.05
        is_tor = random.random() < 0.01
        is_datacenter = random.random() < 0.1
        is_vpn = random.random() < 0.1
        is_known_abuser = False
        score = random.randint(10, 40)
    
    return {
        'ip_address': ip_address,
        'reputation': {
            'score': score,
            'is_proxy': is_proxy,
            'is_tor': is_tor,
            'is_datacenter': is_datacenter,
            'is_vpn': is_vpn,
            'is_known_abuser': is_known_abuser,
            'failed_logins': random.randint(0, 10) if not is_malicious else random.randint(5, 30),
            'countries_count': random.randint(1, 2) if not is_malicious else random.randint(2, 8),
            'last_updated': generate_timestamp(days_back=7)
        },
        'location': generate_location(ip_address)
    }

def generate_user_model(user_id):
    """Generate a behavioral model for a user"""
    # Define possible transitions between pages
    transitions = {
        'login': {'view_dashboard': 0.7, 'view_profile': 0.2, 'view_settings': 0.1},
        'view_dashboard': {'view_account': 0.4, 'view_transactions': 0.4, 'logout': 0.1, 'view_profile': 0.1},
        'view_account': {'view_transactions': 0.5, 'view_dashboard': 0.3, 'logout': 0.2},
        'view_transactions': {'view_dashboard': 0.4, 'view_account': 0.3, 'logout': 0.3},
        'view_profile': {'view_dashboard': 0.5, 'edit_profile': 0.3, 'logout': 0.2},
        'edit_profile': {'view_profile': 0.7, 'view_dashboard': 0.2, 'logout': 0.1},
        'view_settings': {'view_dashboard': 0.5, 'edit_settings': 0.3, 'logout': 0.2},
        'edit_settings': {'view_settings': 0.7, 'view_dashboard': 0.2, 'logout': 0.1}
    }
    
    # Add some randomness to the transitions
    for from_state in transitions:
        for to_state in transitions[from_state]:
            # Add or subtract up to 0.1
            transitions[from_state][to_state] += random.uniform(-0.1, 0.1)
        
        # Normalize to ensure probabilities sum to 1
        total = sum(transitions[from_state].values())
        for to_state in transitions[from_state]:
            transitions[from_state][to_state] /= total
    
    return {
        'user_id': user_id,
        'transitions': transitions,
        'avg_session_length': random.randint(300, 1800),  # 5 to 30 minutes
        'avg_time_between_actions': random.randint(20, 120),  # 20 seconds to 2 minutes
        'common_actions': ['view_dashboard', 'view_account', 'view_transactions'],
        'session_count': random.randint(5, 100),
        'last_updated': generate_timestamp(days_back=14)
    }

def generate_users(num_users):
    """Generate user accounts"""
    users = []
    for i in range(num_users):
        user_id = f"user{i+1:03d}"
        email = f"{user_id}@example.com"
        
        users.append({
            'user_id': user_id,
            'email': email,
            'created_at': generate_timestamp(days_back=90),
            'last_login': None  # Will be updated later
        })
    
    return users

def generate_database():
    """Generate the entire test database"""
    logger.info("Clearing existing database...")
    # Drop existing collections
    for collection in db.list_collection_names():
        db[collection].drop()
    
    logger.info(f"Generating {NUM_USERS} users...")
    users = generate_users(NUM_USERS)
    db.users.insert_many(users)
    
    logger.info("Generating IP data...")
    # Generate IP data including some known bad IPs
    ip_data = []
    bad_ips = []
    
    # Generate known bad IPs
    for _ in range(NUM_KNOWN_BAD_IPS):
        ip = generate_ip()
        bad_ips.append(ip)
        ip_data.append(generate_reputation_data(ip, is_malicious=True))
    
    # Insert IP data
    if ip_data:
        db.ip_data.insert_many(ip_data)
    
    logger.info("Generating device fingerprints...")
    # Generate device fingerprints for users
    devices = []
    
    for user in users:
        user_id = user['user_id']
        # Generate 1-3 devices per user
        for _ in range(random.randint(1, NUM_DEVICES_PER_USER)):
            device_id, fingerprint = generate_device_fingerprint()
            
            device_data = {
                'device_id': device_id,
                'user_id': user_id,
                'first_seen': generate_timestamp(days_back=60),
                'last_seen': generate_timestamp(days_back=10),
                'visit_count': random.randint(1, 50),
                'fingerprints': [fingerprint],
                'issues_history': fingerprint.get('inconsistencies', [])
            }
            
            devices.append(device_data)
    
    if devices:
        db.devices.insert_many(devices)
    
    logger.info("Generating login history...")
    # Generate login history
    logins = []
    
    for user in users:
        user_id = user['user_id']
        user_logins = []
        
        # Generate multiple logins per user
        for _ in range(random.randint(5, NUM_LOGINS_PER_USER)):
            # Get one of the user's devices
            user_devices = [d for d in devices if d['user_id'] == user_id]
            device = random.choice(user_devices) if user_devices else None
            
            # Generate location and IP
            ip_address = generate_ip()
            location = generate_location(ip_address)
            
            # 5% chance of using a known bad IP
            if random.random() < 0.05 and bad_ips:
                ip_address = random.choice(bad_ips)
            
            timestamp = generate_timestamp(days_back=30)
            
            login_data = {
                'user_id': user_id,
                'ip': ip_address,
                'location': location,
                'timestamp': timestamp,
                'device_id': device['device_id'] if device else None,
                'user_agent': generate_user_agent()
            }
            
            logins.append(login_data)
            user_logins.append(login_data)
        
        # Sort logins by timestamp
        user_logins.sort(key=lambda x: x['timestamp'])
        
        # Update user's last login
        if user_logins:
            db.users.update_one(
                {'user_id': user_id},
                {'$set': {'last_login': user_logins[-1]}}
            )
    
    if logins:
        db.logins.insert_many(logins)
    
    logger.info("Generating failed logins...")
    # Generate failed logins
    failed_logins = []
    
    for _ in range(NUM_FAILED_LOGINS):
        # 80% of failed logins are for real users, 20% for non-existent users
        if random.random() < 0.8:
            user = random.choice(users)
            username = user['user_id']
        else:
            username = f"nonuser{random.randint(1, 1000)}"
        
        # 10% chance of using a known bad IP
        if random.random() < 0.1 and bad_ips:
            ip_address = random.choice(bad_ips)
        else:
            ip_address = generate_ip()
        
        timestamp = generate_timestamp(days_back=7)  # More recent
        
        failed_logins.append({
            'username': username,
            'ip_address': ip_address,
            'timestamp': timestamp
        })
    
    if failed_logins:
        db.failed_logins.insert_many(failed_logins)
    
    logger.info("Generating user behavior models...")
    # Generate user behavior models
    user_models = []
    
    for user in users:
        user_id = user['user_id']
        user_models.append(generate_user_model(user_id))
    
    if user_models:
        db.user_models.insert_many(user_models)
    
    logger.info("Generating registrations...")
    # Generate account registrations
    registrations = []
    
    for _ in range(NUM_REGISTRATIONS):
        timestamp = generate_timestamp(days_back=90)
        ip_address = generate_ip()
        
        # 5% chance of using a known bad IP
        if random.random() < 0.05 and bad_ips:
            ip_address = random.choice(bad_ips)
        
        email_domain = random.choice(['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'example.com'])
        
        registrations.append({
            'timestamp': timestamp,
            'ip_address': ip_address,
            'email_domain': email_domain,
            'success': random.random() < 0.9  # 90% success rate
        })
    
    if registrations:
        db.registrations.insert_many(registrations)
    
    logger.info("Generating session events...")
    # Generate session events
    all_sessions = []
    
    for user in users:
        user_id = user['user_id']
        # Generate 3-10 sessions per user
        for _ in range(random.randint(3, 10)):
            events = generate_session_events()
            
            session_id = str(uuid.uuid4())
            for event in events:
                event['user_id'] = user_id
                event['session_id'] = session_id
                all_sessions.append(event)
    
    if all_sessions:
        db.sessions.insert_many(all_sessions)
    
    logger.info("Database generation complete!")
    return {
        'users': len(users),
        'devices': len(devices),
        'logins': len(logins),
        'failed_logins': len(failed_logins),
        'ip_data': len(ip_data),
        'user_models': len(user_models),
        'registrations': len(registrations),
        'sessions': len(all_sessions)
    }

# API route to get user data
@app.route('/api/user/<user_id>', methods=['GET'])
def get_user_data(user_id):
    """Get all data for a specific user"""
    try:
        # Get basic user information
        user = db.users.find_one({'user_id': user_id})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Convert ObjectId to string for JSON serialization
        user['_id'] = str(user['_id'])
        
        # Get user's login history
        logins = list(db.logins.find({'user_id': user_id}).sort('timestamp', -1))
        for login in logins:
            login['_id'] = str(login['_id'])
        
        # Get user's devices
        devices = list(db.devices.find({'user_id': user_id}))
        for device in devices:
            device['_id'] = str(device['_id'])
        
        # Get user's behavior model
        model = db.user_models.find_one({'user_id': user_id})
        if model:
            model['_id'] = str(model['_id'])
        
        # Get user's session events
        sessions = {}
        events = list(db.sessions.find({'user_id': user_id}))
        for event in events:
            event['_id'] = str(event['_id'])
            session_id = event['session_id']
            if session_id not in sessions:
                sessions[session_id] = []
            sessions[session_id].append(event)
        
        # Get failed logins for user
        failed_logins = list(db.failed_logins.find({'username': user_id}))
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

# API route to run full fraud analysis
@app.route('/api/analyze/<user_id>', methods=['POST'])
def analyze_user(user_id):
    """Run full fraud analysis for a user"""
    try:
        # For real analysis, we would integrate with your fraud detection modules here
        # This is a simplified placeholder response
        data = request.json or {}
        ip_address = data.get('ip_address', request.remote_addr)
        
        # Get user
        user = db.users.find_one({'user_id': user_id})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get a few pieces of data to demonstrate the concept
        devices = list(db.devices.find({'user_id': user_id}))
        logins = list(db.logins.find({'user_id': user_id}).sort('timestamp', -1).limit(5))
        
        # Get IP reputation
        ip_data = db.ip_data.find_one({'ip_address': ip_address})
        ip_reputation = None
        if ip_data and 'reputation' in ip_data:
            ip_reputation = ip_data['reputation']
        
        # Mock analysis results
        results = {
            'user_agent': {
                'risk_score': random.randint(0, 100),
                'status': random.choice(['normal', 'suspicious', 'highly_suspicious']),
                'message': "User agent analysis complete"
            },
            'geo_velocity': {
                'risk_score': random.randint(0, 100),
                'status': random.choice(['normal_travel', 'suspicious_travel', 'impossible_travel']),
                'message': "Geo-velocity analysis complete"
            },
            'access_time': {
                'risk_score': random.randint(0, 100),
                'status': random.choice(['normal', 'medium_anomaly', 'high_anomaly']),
                'message': "Access time analysis complete"
            },
            'device': {
                'risk_score': random.randint(0, 100),
                'status': random.choice(['normal', 'suspicious', 'unknown_device']),
                'message': "Device analysis complete"
            },
            'ip_reputation': {
                'risk_score': ip_reputation['score'] if ip_reputation else random.randint(0, 100),
                'status': random.choice(['trusted', 'low_risk', 'medium_risk', 'high_risk', 'critical']),
                'message': "IP reputation analysis complete"
            },
            'password_attack': {
                'risk_score': random.randint(0, 100),
                'attack_detected': random.random() < 0.2,
                'attack_type': random.choice([None, 'bruteforce', 'credential_stuffing', 'password_spraying']),
                'message': "Password attack analysis complete"
            },
            'account_velocity': {
                'risk_score': random.randint(0, 100),
                'status': random.choice(['normal_velocity', 'elevated_velocity', 'high_velocity']),
                'message': "Account velocity analysis complete"
            },
            'session': {
                'risk_score': random.randint(0, 100),
                'status': random.choice(['normal_behavior', 'suspicious_behavior', 'high_risk_behavior']),
                'message': "Session analysis complete"
            }
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
        
        # Determine risk level and recommendation (Thresholds)
        if overall_risk < 25:
            risk_level = "low"
            recommendation = "allow"
        elif overall_risk < 50:
            risk_level = "medium"
            recommendation = "monitor"
        elif overall_risk < 75:
            risk_level = "high"
            recommendation = "challenge"
        else:
            risk_level = "critical"
            recommendation = "block"
        
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
                'login_history_count': db.logins.count_documents({'user_id': user_id})
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error analyzing user: {str(e)}")
        return jsonify({'error': str(e)}), 500

# API route to generate test database
@app.route('/api/generate-database', methods=['POST'])
def api_generate_database():
    """API endpoint to regenerate the test database"""
    try:
        stats = generate_database()
        return jsonify({
            'status': 'success',
            'message': 'Test database generated successfully',
            'stats': stats
        })
    except Exception as e:
        logger.error(f"Error generating database: {str(e)}")
        return jsonify({'error': str(e)}), 500

# API route to get database stats
@app.route('/api/database-stats', methods=['GET'])
def get_database_stats():
    """Get statistics about the current database"""
    try:
        stats = {
            'users': db.users.count_documents({}),
            'devices': db.devices.count_documents({}),
            'logins': db.logins.count_documents({}),
            'failed_logins': db.failed_logins.count_documents({}),
            'ip_data': db.ip_data.count_documents({}),
            'user_models': db.user_models.count_documents({}),
            'registrations': db.registrations.count_documents({}),
            'sessions': db.sessions.count_documents({})
        }
        
        return jsonify({
            'status': 'success',
            'stats': stats
        })
    except Exception as e:
        logger.error(f"Error getting database stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Main function to run the server
if __name__ == '__main__':
    # Generate test database if it doesn't exist
    if db.users.count_documents({}) == 0:
        logger.info("No users found in database. Generating test data...")
        generate_database()
    
    # Start the Flask server
    app.run(debug=True, host='0.0.0.0', port=5000)
import pymongo
import random
import time
import uuid
from datetime import datetime, timedelta
import ipaddress
import logging
import os
from faker import Faker

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Faker
fake = Faker()

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
        # [Keep all other continent definitions as in your original code]
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
        # [Keep all other browser user agents as in your original code]
    ]
    return random.choice(browsers)

def generate_device_fingerprint():
    """Generate a random device fingerprint"""
    # [Keep your original function implementation]

def generate_session_events():
    """Generate a random sequence of session events"""
    # [Keep your original function implementation]

def generate_reputation_data(ip_address, is_malicious=False):
    """Generate IP reputation data"""
    # [Keep your original function implementation]

def generate_user_model(user_id):
    """Generate a behavioral model for a user"""
    # [Keep your original function implementation]

def generate_users(num_users):
    """Generate user accounts"""
    # [Keep your original function implementation]

def generate_database(db):
    """Generate the entire test database"""
    logger.info("Clearing existing database...")
    # Drop existing collections
    for collection in db.list_collection_names():
        db[collection].drop()
    
    logger.info(f"Generating {NUM_USERS} users...")
    users = generate_users(NUM_USERS)
    db.users.insert_many(users)
    
    # [Keep all other data generation steps as in your original code]
    
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

# Function to initialize the database if it's empty
def initialize_if_empty(db):
    """Initialize the database if it's empty"""
    if db.users.count_documents({}) == 0:
        logger.info("No users found in database. Generating test data...")
        generate_database(db)
        return True
    return False
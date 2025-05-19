import os
import pymongo
import logging

logger = logging.getLogger(__name__)

# MongoDB connection
def get_mongodb_client():
    """Get MongoDB client instance"""
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    DB_NAME = os.environ.get('MONGO_DB', 'fraud_detection_test')
    
    client = pymongo.MongoClient(MONGO_URI)
    db = client[DB_NAME]
    
    return client, db

# Mock database class for integrating with predictors
class MockDatabase:
    def __init__(self, db_instance):
        self.db = db_instance
    
    def get_login_history(self, user_id, limit=10):
        return list(self.db.logins.find({'user_id': user_id}).sort('timestamp', -1).limit(limit))
    
    def get_last_login(self, user_id):
        logins = list(self.db.logins.find({'user_id': user_id}).sort('timestamp', -1).limit(1))
        return logins[0] if logins else None
    
    def store_login(self, login_data):
        # In test mode, we don't need to store anything
        pass
    
    def get_ip_location(self, ip_address):
        ip_data = self.db.ip_data.find_one({'ip_address': ip_address})
        if ip_data and 'location' in ip_data:
            return ip_data['location']
        return None
    
    def get_ip_reputation(self, ip_address):
        ip_data = self.db.ip_data.find_one({'ip_address': ip_address})
        if ip_data and 'reputation' in ip_data:
            return ip_data['reputation']
        return None
    
    def update_ip_reputation(self, ip_address, reputation_data):
        # In test mode, we don't need to update anything
        pass
    
    def get_device_data(self, device_id=None, user_id=None):
        if device_id:
            return self.db.devices.find_one({'device_id': device_id})
        elif user_id:
            return list(self.db.devices.find({'user_id': user_id}))
        return None
    
    def store_device_data(self, device_id, device_data):
        # In test mode, we don't need to store anything
        pass
    
    def get_recent_failed_logins(self, username=None, ip_address=None, minutes=30):
        cutoff_time = int(time.time()) - (minutes * 60)
        query = {'timestamp': {'$gt': cutoff_time}}
        
        if username:
            query['username'] = username
        if ip_address:
            query['ip_address'] = ip_address
            
        return list(self.db.failed_logins.find(query))
    
    def get_user_model(self, user_id):
        return self.db.user_models.find_one({'user_id': user_id})
    
    def update_user_model(self, user_id, model_data):
        # In test mode, we don't need to update anything
        pass
    
    def get_registrations(self, entity_type=None, entity_value=None):
        """
        Get registration timestamps for an entity (IP, subnet, domain)
        """
        query = {}
        
        if entity_type == 'ip':
            query['ip_address'] = entity_value
        elif entity_type == 'subnet':
            # For subnet, we need to match IPs that start with the subnet prefix
            subnet_prefix = entity_value.split('/')[0]  # Get the network part without mask
            subnet_prefix = subnet_prefix.rsplit('.', 1)[0]  # Remove the last octet
            query['ip_address'] = {'$regex': f'^{subnet_prefix}'}
        elif entity_type == 'email_domain':
            query['email_domain'] = entity_value
            
        # Get registrations matching query
        registrations = list(self.db.registrations.find(query))
        
        # Extract timestamps
        return [r['timestamp'] for r in registrations]
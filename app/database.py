import os
import json
import logging
from datetime import datetime
import time
import pymongo
import redis
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class Database:
    """
    Database handling class for storing and retrieving fraud detection data.
    For simplicity, this implementation can work with either MongoDB or file storage.
    """
    
    def __init__(self):
        # Initialize database connection based on configuration
        self.db_type = os.getenv('DB_TYPE', 'file')
        
        if self.db_type == 'mongodb':
            # MongoDB connection
            mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
            self.mongo_client = pymongo.MongoClient(mongo_uri)
            self.mongo_db = self.mongo_client[os.getenv('MONGO_DB', 'fraud_detection')]
            
            # Redis connection for caching and rate limiting
            redis_host = os.getenv('REDIS_HOST', 'localhost')
            redis_port = int(os.getenv('REDIS_PORT', 6379))
            self.redis_client = redis.Redis(
                host=redis_host, 
                port=redis_port,
                decode_responses=True
            )
            
            logger.info("Database initialized with MongoDB and Redis")
        else:
            # File-based storage for development/testing
            self.data_dir = os.getenv('DATA_DIR', 'data')
            os.makedirs(f"{self.data_dir}/logins", exist_ok=True)
            os.makedirs(f"{self.data_dir}/users", exist_ok=True)
            os.makedirs(f"{self.data_dir}/ip_data", exist_ok=True)
            
            logger.info("Database initialized with file-based storage")
    
    def store_login(self, login_data):
        """
        Store login information
        
        Args:
            login_data (dict): Login data including user_id, ip, location, timestamp
        """
        try:
            user_id = login_data.get('user_id')
            
            if self.db_type == 'mongodb':
                # Store in MongoDB
                self.mongo_db.logins.insert_one(login_data)
                
                # Update user's last login
                self.mongo_db.users.update_one(
                    {'user_id': user_id},
                    {'$set': {'last_login': login_data}},
                    upsert=True
                )
            else:
                # Store in file system
                login_file = f"{self.data_dir}/logins/{user_id}.json"
                
                # Read existing logins
                if os.path.exists(login_file):
                    with open(login_file, 'r') as f:
                        logins = json.load(f)
                else:
                    logins = []
                
                # Add new login
                logins.append(login_data)
                
                # Keep only last 10 logins
                logins = logins[-10:]
                
                # Write back to file
                with open(login_file, 'w') as f:
                    json.dump(logins, f)
                
                # Update user's last login
                user_file = f"{self.data_dir}/users/{user_id}.json"
                user_data = {'user_id': user_id, 'last_login': login_data}
                
                with open(user_file, 'w') as f:
                    json.dump(user_data, f)
                
            logger.debug(f"Stored login for user {user_id}")
            
        except Exception as e:
            logger.error(f"Error storing login data: {str(e)}")
    
    def get_last_login(self, user_id):
        """
        Get the most recent login for a user
        
        Args:
            user_id (str): User identifier
            
        Returns:
            dict: Most recent login information or None if not found
        """
        try:
            if self.db_type == 'mongodb':
                # Fetch from MongoDB
                user = self.mongo_db.users.find_one({'user_id': user_id})
                if user and 'last_login' in user:
                    return user['last_login']
            else:
                # Fetch from file system
                user_file = f"{self.data_dir}/users/{user_id}.json"
                
                if os.path.exists(user_file):
                    with open(user_file, 'r') as f:
                        user_data = json.load(f)
                        if 'last_login' in user_data:
                            return user_data['last_login']
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting last login for user {user_id}: {str(e)}")
            return None
    
    def get_login_history(self, user_id, limit=10):
        """
        Get login history for a user
        
        Args:
            user_id (str): User identifier
            limit (int): Maximum number of logins to return
            
        Returns:
            list: List of login records
        """
        try:
            if self.db_type == 'mongodb':
                # Fetch from MongoDB
                logins = list(
                    self.mongo_db.logins.find(
                        {'user_id': user_id}
                    ).sort('timestamp', -1).limit(limit)
                )
                return logins
            else:
                # Fetch from file system
                login_file = f"{self.data_dir}/logins/{user_id}.json"
                
                if os.path.exists(login_file):
                    with open(login_file, 'r') as f:
                        logins = json.load(f)
                        logins.sort(key=lambda x: x['timestamp'], reverse=True)
                        return logins[:limit]
                
                return []
                
        except Exception as e:
            logger.error(f"Error getting login history for user {user_id}: {str(e)}")
            return []
    
    def store_ip_data(self, ip_address, data):
        """
        Store data about an IP address
        
        Args:
            ip_address (str): IP address
            data (dict): Data to store
        """
        try:
            if self.db_type == 'mongodb':
                # Store in MongoDB
                data['ip_address'] = ip_address
                data['updated_at'] = int(time.time())
                
                self.mongo_db.ip_data.update_one(
                    {'ip_address': ip_address},
                    {'$set': data},
                    upsert=True
                )
            else:
                # Store in file system
                ip_file = f"{self.data_dir}/ip_data/{ip_address.replace(':', '_')}.json"
                
                # Read existing data
                if os.path.exists(ip_file):
                    with open(ip_file, 'r') as f:
                        existing_data = json.load(f)
                else:
                    existing_data = {}
                
                # Update data
                existing_data.update(data)
                existing_data['updated_at'] = int(time.time())
                
                # Write back to file
                with open(ip_file, 'w') as f:
                    json.dump(existing_data, f)
                
            logger.debug(f"Stored data for IP {ip_address}")
            
        except Exception as e:
            logger.error(f"Error storing IP data: {str(e)}")
    
    def get_ip_data(self, ip_address):
        """
        Get data about an IP address
        
        Args:
            ip_address (str): IP address
            
        Returns:
            dict: IP data or None if not found
        """
        try:
            if self.db_type == 'mongodb':
                # Fetch from MongoDB
                return self.mongo_db.ip_data.find_one({'ip_address': ip_address})
            else:
                # Fetch from file system
                ip_file = f"{self.data_dir}/ip_data/{ip_address.replace(':', '_')}.json"
                
                if os.path.exists(ip_file):
                    with open(ip_file, 'r') as f:
                        return json.load(f)
                
                return None
                
        except Exception as e:
            logger.error(f"Error getting data for IP {ip_address}: {str(e)}")
            return None
    
    def get_ip_location(self, ip_address):
        """
        Get geolocation data for an IP address from the database
        
        Args:
            ip_address (str): IP address
            
        Returns:
            dict: Location data or None if not found
        """
        ip_data = self.get_ip_data(ip_address)
        if ip_data and 'location' in ip_data:
            return ip_data['location']
        return None
    
    def record_failed_login(self, username, ip_address):
        """
        Record a failed login attempt
        
        Args:
            username (str): Username
            ip_address (str): IP address
        """
        timestamp = int(time.time())
        
        try:
            if self.db_type == 'mongodb':
                # Store in MongoDB
                self.mongo_db.failed_logins.insert_one({
                    'username': username,
                    'ip_address': ip_address,
                    'timestamp': timestamp
                })
                
                # Increment count in Redis for rate limiting
                key = f"failed_login:{username}:{ip_address}"
                self.redis_client.incr(key)
                self.redis_client.expire(key, 3600)  # Expire after 1 hour
            else:
                # Store in file system
                failed_dir = f"{self.data_dir}/failed_logins"
                os.makedirs(failed_dir, exist_ok=True)
                
                failed_file = f"{failed_dir}/{username}.json"
                
                # Read existing failed logins
                if os.path.exists(failed_file):
                    with open(failed_file, 'r') as f:
                        failed_logins = json.load(f)
                else:
                    failed_logins = []
                
                # Add new failed login
                failed_logins.append({
                    'ip_address': ip_address,
                    'timestamp': timestamp
                })
                
                # Keep only recent failed logins (last 24 hours)
                cutoff_time = timestamp - 86400
                failed_logins = [login for login in failed_logins if login['timestamp'] > cutoff_time]
                
                # Write back to file
                with open(failed_file, 'w') as f:
                    json.dump(failed_logins, f)
                
            logger.info(f"Recorded failed login for {username} from {ip_address}")
            
        except Exception as e:
            logger.error(f"Error recording failed login: {str(e)}")
    
    def get_recent_failed_logins(self, username=None, ip_address=None, minutes=30):
        """
        Get recent failed login attempts
        
        Args:
            username (str): Optional username filter
            ip_address (str): Optional IP address filter
            minutes (int): Time window in minutes
            
        Returns:
            list: List of failed login records
        """
        cutoff_time = int(time.time()) - (minutes * 60)
        
        try:
            if self.db_type == 'mongodb':
                # Build query
                query = {'timestamp': {'$gt': cutoff_time}}
                if username:
                    query['username'] = username
                if ip_address:
                    query['ip_address'] = ip_address
                
                # Fetch from MongoDB
                return list(self.mongo_db.failed_logins.find(query))
            else:
                # Fetch from file system
                failed_dir = f"{self.data_dir}/failed_logins"
                
                if username:
                    # If username is provided, only check that file
                    failed_file = f"{failed_dir}/{username}.json"
                    
                    if os.path.exists(failed_file):
                        with open(failed_file, 'r') as f:
                            all_failed = json.load(f)
                    else:
                        all_failed = []
                else:
                    # Otherwise, check all files
                    all_failed = []
                    
                    if os.path.exists(failed_dir):
                        for filename in os.listdir(failed_dir):
                            if filename.endswith('.json'):
                                file_path = os.path.join(failed_dir, filename)
                                with open(file_path, 'r') as f:
                                    user_failed = json.load(f)
                                    # Add username to each record
                                    for record in user_failed:
                                        record['username'] = filename[:-5]
                                    all_failed.extend(user_failed)
                
                # Filter by timestamp and IP if needed
                filtered_failed = [
                    login for login in all_failed 
                    if login['timestamp'] > cutoff_time and
                    (not ip_address or login['ip_address'] == ip_address)
                ]
                
                return filtered_failed
                
        except Exception as e:
            logger.error(f"Error getting recent failed logins: {str(e)}")
            return []
    
    def get_ip_reputation(self, ip_address):
        """
        Get reputation data for an IP
        
        Args:
            ip_address (str): IP address
            
        Returns:
            dict: Reputation data or default values if not found
        """
        ip_data = self.get_ip_data(ip_address)
        
        if ip_data and 'reputation' in ip_data:
            return ip_data['reputation']
        
        # Default reputation for new IPs
        return {
            'score': 50,  # Neutral score
            'is_proxy': False,
            'is_datacenter': False,
            'is_tor': False,
            'failed_logins': 0,
            'countries_count': 0
        }
    
    def update_ip_reputation(self, ip_address, reputation_data):
        """
        Update reputation data for an IP
        
        Args:
            ip_address (str): IP address
            reputation_data (dict): Reputation data to update
        """
        self.store_ip_data(ip_address, {'reputation': reputation_data})

    # Add these methods to your Database class

    def get_device_data(self, device_id=None, user_id=None):
        """
        Get stored device fingerprint data
        
        Args:
            device_id (str): Optional device identifier
            user_id (str): Optional user identifier
            
        Returns:
            dict or list: Device data or a list of devices if only user_id is provided
        """
        try:
            if self.db_type == 'mongodb':
                # Build query
                query = {}
                if device_id:
                    query['device_id'] = device_id
                if user_id:
                    query['user_id'] = user_id
                
                if device_id:  # Return single device
                    return self.mongo_db.devices.find_one(query)
                else:  # Return all devices for user
                    return list(self.mongo_db.devices.find(query))
            else:
                # File-based implementation
                devices_dir = f"{self.data_dir}/devices"
                os.makedirs(devices_dir, exist_ok=True)
                
                if device_id:
                    # Try to find by device ID
                    device_file = f"{devices_dir}/{device_id}.json"
                    if os.path.exists(device_file):
                        with open(device_file, 'r') as f:
                            return json.load(f)
                    return None
                
                elif user_id:
                    # Find all devices for user
                    user_devices = []
                    if os.path.exists(devices_dir):
                        for filename in os.listdir(devices_dir):
                            if filename.endswith('.json'):
                                file_path = os.path.join(devices_dir, filename)
                                with open(file_path, 'r') as f:
                                    device_data = json.load(f)
                                    if device_data.get('user_id') == user_id:
                                        user_devices.append(device_data)
                    return user_devices
                
                return None
                
        except Exception as e:
            logger.error(f"Error getting device data: {str(e)}")
            return None

    def store_device_data(self, device_data, user_id=None):
        """
        Store device fingerprint data
        
        Args:
            device_data (dict or str): Device fingerprint data or device ID string
            user_id (str, optional): User identifier to associate with the device
        """
        try:
            # Handle case where device_data is a string (device ID)
            if isinstance(device_data, str):
                device_id = device_data
                device_data = {'device_id': device_id}
            else:
                device_id = device_data.get('device_id')
                
            if not device_id:
                logger.error("Cannot store device data without device_id")
                return
            
            # Associate with user if provided
            if user_id:
                device_data['user_id'] = user_id
            
            if self.db_type == 'mongodb':
                # Store in MongoDB
                device_data['updated_at'] = int(time.time())
                
                self.mongo_db.devices.update_one(
                    {'device_id': device_id},
                    {'$set': device_data},
                    upsert=True
                )
            else:
                # Store in file system
                devices_dir = f"{self.data_dir}/devices"
                os.makedirs(devices_dir, exist_ok=True)
                
                device_file = f"{devices_dir}/{device_id}.json"
                
                # Update timestamp
                device_data['updated_at'] = int(time.time())
                
                # Write to file
                with open(device_file, 'w') as f:
                    json.dump(device_data, f)
                    
            logger.debug(f"Stored data for device {device_id}")
            
        except Exception as e:
            logger.error(f"Error storing device data: {str(e)}")

    def get_registrations(self, start_time=None, end_time=None, ip_address=None):
        """
        Get account registrations within a time period
        
        Args:
            start_time (int): Optional start timestamp
            end_time (int): Optional end timestamp
            ip_address (str): Optional IP address filter
            
        Returns:
            list: List of registration records
        """
        try:
            if not start_time:
                start_time = 0
            if not end_time:
                end_time = int(time.time())
                
            if self.db_type == 'mongodb':
                # Build query
                query = {
                    'timestamp': {'$gte': start_time, '$lte': end_time}
                }
                if ip_address:
                    query['ip_address'] = ip_address
                    
                # Fetch from MongoDB
                return list(self.mongo_db.registrations.find(query))
            else:
                # Fetch from file system
                regs_dir = f"{self.data_dir}/registrations"
                os.makedirs(regs_dir, exist_ok=True)
                
                all_regs = []
                
                if os.path.exists(regs_dir):
                    for filename in os.listdir(regs_dir):
                        if filename.endswith('.json'):
                            file_path = os.path.join(regs_dir, filename)
                            with open(file_path, 'r') as f:
                                reg_data = json.load(f)
                                # Filter by time and IP
                                if (reg_data.get('timestamp', 0) >= start_time and
                                    reg_data.get('timestamp', 0) <= end_time and
                                    (not ip_address or reg_data.get('ip_address') == ip_address)):
                                    all_regs.append(reg_data)
                
                return all_regs
                
        except Exception as e:
            logger.error(f"Error getting registrations: {str(e)}")
            return []

    def get_user_model(self, user_id):
        """
        Get behavior model for a user
        
        Args:
            user_id (str): User identifier
            
        Returns:
            dict: User behavior model or None if not found
        """
        try:
            if self.db_type == 'mongodb':
                # Fetch from MongoDB
                return self.mongo_db.user_models.find_one({'user_id': user_id})
            else:
                # Fetch from file system
                models_dir = f"{self.data_dir}/user_models"
                os.makedirs(models_dir, exist_ok=True)
                
                model_file = f"{models_dir}/{user_id}.json"
                
                if os.path.exists(model_file):
                    with open(model_file, 'r') as f:
                        return json.load(f)
                
                return None
                
        except Exception as e:
            logger.error(f"Error getting user model for {user_id}: {str(e)}")
            return None

    def update_user_model(self, user_id, model_data):
        """
        Update behavior model for a user
        
        Args:
            user_id (str): User identifier
            model_data (dict): User behavior model data
        """
        try:
            if self.db_type == 'mongodb':
                # Store in MongoDB
                model_data['user_id'] = user_id
                model_data['updated_at'] = int(time.time())
                
                self.mongo_db.user_models.update_one(
                    {'user_id': user_id},
                    {'$set': model_data},
                    upsert=True
                )
            else:
                # Store in file system
                models_dir = f"{self.data_dir}/user_models"
                os.makedirs(models_dir, exist_ok=True)
                
                model_file = f"{models_dir}/{user_id}.json"
                
                # Update user_id and timestamp
                model_data['user_id'] = user_id
                model_data['updated_at'] = int(time.time())
                
                # Write to file
                with open(model_file, 'w') as f:
                    json.dump(model_data, f)
                    
            logger.debug(f"Updated model for user {user_id}")
            
        except Exception as e:
            logger.error(f"Error updating user model: {str(e)}")
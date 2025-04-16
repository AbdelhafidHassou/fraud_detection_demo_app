import logging
import geoip2.database
import geoip2.errors
import math
import time
from datetime import datetime
import os
from app.database import Database

logger = logging.getLogger(__name__)

class GeoVelocityDetector:
    """
    Detects impossible travel scenarios based on geographic distance and time.
    """
    
    def __init__(self, geoip_db_path=None):
        self.db = Database()
        
        # Default GeoIP database path
        if geoip_db_path is None:
            geoip_db_path = os.getenv('GEOIP_DB_PATH', 'data/GeoLite2-City.mmdb')
        
        try:
            self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            logger.info("GeoVelocityDetector initialized with database")
        except Exception as e:
            self.geoip_reader = None
            logger.error(f"Failed to initialize GeoIP database: {str(e)}")
            logger.warning("GeoVelocityDetector will use a fallback mechanism")
    
    def detect(self, user_id, ip_address, current_timestamp=None):
        """
        Detect impossible travel based on geographic distance and time
        
        Args:
            user_id (str): User identifier
            ip_address (str): Current IP address
            current_timestamp (int): Current timestamp (defaults to now)
            
        Returns:
            dict: Detection results including risk score and travel speed
        """
        try:
            # Default to current time if not provided
            if current_timestamp is None:
                current_timestamp = int(time.time())
            
            # Get current location
            current_location = self._get_location(ip_address)
            
            if current_location is None:
                return {
                    'risk_score': 50,  # Medium risk due to inability to determine location
                    'status': 'unknown_location',
                    'message': 'Could not determine location from IP address'
                }
            
            # Get previous login information
            previous_login = self._get_previous_login(user_id)
            
            # If no previous login, store current login and return
            if previous_login is None:
                self._store_login(user_id, ip_address, current_location, current_timestamp)
                return {
                    'risk_score': 0,
                    'status': 'first_login',
                    'message': 'First login from this user'
                }
            
            # Calculate time difference in hours
            time_diff_hours = (current_timestamp - previous_login['timestamp']) / 3600.0
            
            # If time difference is too small (less than 1 minute), it might be a duplicate request
            if time_diff_hours < 0.0167:  # Less than 1 minute
                return {
                    'risk_score': 0,
                    'status': 'duplicate_request',
                    'message': 'Request too close to previous login'
                }
            
            # If it's been more than 7 days, don't consider it for impossible travel
            if time_diff_hours > 168:  # 7 days
                self._store_login(user_id, ip_address, current_location, current_timestamp)
                return {
                    'risk_score': 0,
                    'status': 'extended_time_gap',
                    'message': 'More than 7 days since last login'
                }
            
            # Calculate distance between locations
            distance_km = self._calculate_distance(
                previous_login['location']['latitude'],
                previous_login['location']['longitude'],
                current_location['latitude'],
                current_location['longitude']
            )
            
            # If locations are very close, no need to check velocity
            if distance_km < 10:
                self._store_login(user_id, ip_address, current_location, current_timestamp)
                return {
                    'risk_score': 0,
                    'status': 'same_area',
                    'message': 'Login from same geographic area'
                }
            
            # Calculate travel speed in km/h
            travel_speed = distance_km / time_diff_hours if time_diff_hours > 0 else float('inf')
            
            # Assess risk based on travel speed
            risk_score, status, message = self._assess_travel_risk(travel_speed, distance_km)
            
            # Store current login
            self._store_login(user_id, ip_address, current_location, current_timestamp)
            
            # Format timestamps for readability
            prev_time_str = datetime.fromtimestamp(previous_login['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            curr_time_str = datetime.fromtimestamp(current_timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # Prepare result
            result = {
                'risk_score': risk_score,
                'status': status,
                'message': message,
                'travel_speed_kmh': round(travel_speed, 2),
                'distance_km': round(distance_km, 2),
                'time_difference_hours': round(time_diff_hours, 2),
                'previous_login': {
                    'ip': previous_login['ip'],
                    'timestamp': prev_time_str,
                    'location': {
                        'country': previous_login['location'].get('country', 'Unknown'),
                        'city': previous_login['location'].get('city', 'Unknown'),
                        'latitude': previous_login['location']['latitude'],
                        'longitude': previous_login['location']['longitude']
                    }
                },
                'current_login': {
                    'ip': ip_address,
                    'timestamp': curr_time_str,
                    'location': {
                        'country': current_location.get('country', 'Unknown'),
                        'city': current_location.get('city', 'Unknown'),
                        'latitude': current_location['latitude'],
                        'longitude': current_location['longitude']
                    }
                }
            }
            
            # Log high-risk velocity detections
            if risk_score > 70:
                logger.warning(f"High-risk travel velocity detected for user {user_id}: {travel_speed} km/h")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in geo-velocity detection: {str(e)}")
            return {
                'risk_score': 50,  # Medium risk due to error
                'status': 'error',
                'message': f"Error in geo-velocity analysis: {str(e)}"
            }
    
    def _get_location(self, ip_address):
        """Get geolocation data for an IP address"""
        try:
            # First check if we have the GeoIP reader
            if self.geoip_reader:
                response = self.geoip_reader.city(ip_address)
                return {
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'country': response.country.name,
                    'city': response.city.name,
                    'postal_code': response.postal.code,
                    'timezone': response.location.time_zone
                }
            else:
                # Fallback to database lookup if available
                location = self.db.get_ip_location(ip_address)
                if location:
                    return location
                
                # Last resort - use a free geolocation API
                # Note: In a production system, you would use a reliable paid service
                import requests
                response = requests.get(f"https://ipapi.co/{ip_address}/json/")
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'latitude': data.get('latitude'),
                        'longitude': data.get('longitude'),
                        'country': data.get('country_name'),
                        'city': data.get('city'),
                        'postal_code': data.get('postal'),
                        'timezone': data.get('timezone')
                    }
                
                logger.warning(f"Could not determine location for IP: {ip_address}")
                return None
                
        except geoip2.errors.AddressNotFoundError:
            logger.info(f"IP address not found in GeoIP database: {ip_address}")
            return None
        except Exception as e:
            logger.error(f"Error getting location for IP {ip_address}: {str(e)}")
            return None
    
    def _get_previous_login(self, user_id):
        """Get the most recent login for a user"""
        # In a real implementation, this would fetch from your database
        return self.db.get_last_login(user_id)
    
    def _store_login(self, user_id, ip_address, location, timestamp):
        """Store login information for future comparison"""
        # In a real implementation, this would store to your database
        login_data = {
            'user_id': user_id,
            'ip': ip_address,
            'location': location,
            'timestamp': timestamp
        }
        self.db.store_login(login_data)
    
    def _calculate_distance(self, lat1, lon1, lat2, lon2):
        """
        Calculate the great circle distance between two points
        on the earth (specified in decimal degrees)
        """
        # Convert decimal degrees to radians
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        
        # Haversine formula
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        r = 6371  # Radius of earth in kilometers
        return c * r
    
    def _assess_travel_risk(self, speed, distance):
        """
        Assess the risk based on travel speed and distance
        
        Returns:
            tuple: (risk_score, status, message)
        """
        # Define speed thresholds in km/h
        walking_speed = 7      # Average walking speed
        driving_speed = 120    # Fast highway driving
        train_speed = 300      # High-speed train
        airplane_speed = 900   # Commercial airplane
        
        # Adjust thresholds based on distance
        if distance < 50:  # Short distances make speed calculation less reliable
            airplane_speed = 700
            train_speed = 200
        
        if speed > airplane_speed:
            risk_level = 100
            status = 'impossible_travel'
            message = 'Travel speed exceeds physical possibility'
        elif speed > train_speed:
            # Might be possible with airplane, but still suspicious
            risk_level = 80
            status = 'highly_suspicious_travel'
            message = 'Travel speed suggests impossible journey without air travel'
        elif speed > driving_speed:
            # Possible with high-speed train
            risk_level = 60
            status = 'suspicious_travel'
            message = 'Travel speed is suspicious but possible with high-speed transport'
        elif speed > walking_speed:
            # Normal speed for driving
            risk_level = 0
            status = 'normal_travel'
            message = 'Travel speed is within normal range for driving'
        else:
            # Walking or very slow movement
            risk_level = 0
            status = 'slow_travel'
            message = 'Travel speed is very slow or user is stationary'
        
        return risk_level, status, message

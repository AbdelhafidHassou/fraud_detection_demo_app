from flask import Flask
from flask_cors import CORS
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_app():
    """Create and configure the Flask application"""
    
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
    
    # Create log directory if not exists
    os.makedirs('data/logs', exist_ok=True)
    
    # Initialize Flask app
    app = Flask(__name__, static_folder='static')
    CORS(app)
    
    # Set configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['DEBUG'] = os.getenv('FLASK_ENV', 'development') == 'development'
    
    # Register blueprints
    from app.api.routes import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')
    
    # Root route for health check
    @app.route('/')
    def health_check():
        return {
            'status': 'ok',
            'name': 'Xayone Protect Project',
            'version': '1.0.0'
        }
    
    logger.info("Application initialized")
    return app

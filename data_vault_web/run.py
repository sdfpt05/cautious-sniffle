#!/usr/bin/env python3
import os
import sys
import logging
from app import create_app
from dotenv import load_dotenv
from flask.cli import FlaskGroup
from shared.models import Base
from sqlalchemy import create_engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/data_vault_web.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_directories():
    """Create necessary directories if they don't exist"""
    directories = ['logs', 'data']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"Created directory: {directory}")

def init_database():
    """Initialize the database and create tables"""
    try:
        # Get database URL from environment or use default
        db_url = os.environ.get('DATABASE_URL', 'sqlite:///data/data_vault.db')
        
        # Create engine and initialize database
        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        
        logger.info(f"Database initialized successfully at {db_url}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        return False

def main():
    """Main entry point for the web application"""
    try:
        # Load environment variables
        load_dotenv()
        
        create_directories()
        
        # Check if database exists, initialize if not
        db_path = os.path.join('data', 'data_vault.db')
        if not os.path.exists(db_path) and 'sqlite' in os.environ.get('DATABASE_URL', 'sqlite:///'):
            init_database()
        
        # Determine environment and configuration
        env = os.environ.get('FLASK_ENV', 'production')
        if env == 'development':
            from config import DevConfig
            config_class = DevConfig
        elif env == 'testing':
            from config import TestConfig
            config_class = TestConfig
        else:
            from config import ProdConfig
            config_class = ProdConfig
        
        # Create app with the appropriate configuration
        app = create_app(config_class)
        
        # Get host and port from environment or use defaults
        host = os.environ.get('HOST', '127.0.0.1')
        port = int(os.environ.get('PORT', 5000))
        
        # Run the app
        logger.info(f"Starting web server in {env} mode on {host}:{port}")
        app.run(host=host, port=port, debug=(env == 'development'))
        
        return 0
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        print(f"An unexpected error occurred: {str(e)}")
        return 1

def cli():
    """CLI entry point for Flask commands"""
    load_dotenv()
    from config import Config
    app = create_app(Config)
    cli = FlaskGroup(create_app=lambda: app)
    return cli()

if __name__ == '__main__':
    sys.exit(main())
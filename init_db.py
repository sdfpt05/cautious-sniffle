#!/usr/bin/env python3
"""
Simple standalone script to initialize the database without relying on the package structure.
Run this directly with: python init_db.py
"""
import os
import sys
from sqlalchemy import create_engine
from dotenv import load_dotenv

# Add the current directory to the path to ensure imports work
sys.path.insert(0, os.path.abspath('.'))

def create_directories():
    """Create necessary directories if they don't exist"""
    directories = ['logs', 'data']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

def init_database():
    """Initialize the database and create tables"""
    try:
        # Load environment variables
        load_dotenv()
        
        # Import here after path is set
        from shared.models import Base
        
        # Get database URL from environment or use default
        db_url = os.environ.get('DATABASE_URL', 'sqlite:///data/data_vault.db')
        
        print(f"Using database URL: {db_url}")
        
        # Create engine and initialize database
        engine = create_engine(db_url)
        print("Created database engine")
        
        # Create tables
        Base.metadata.create_all(engine)
        print("Created database tables")
        
        print(f"Database initialized successfully at {db_url}")
        return True
    except Exception as e:
        print(f"Failed to initialize database: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Starting database initialization...")
    create_directories()
    success = init_database()
    if success:
        print("Database initialization completed successfully!")
    else:
        print("Database initialization failed.")
        sys.exit(1)
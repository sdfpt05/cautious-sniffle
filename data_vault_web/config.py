import os
from dotenv import load_dotenv
from shared.encryption import EncryptionManager

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///data_vault.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or os.urandom(32)
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    ENCRYPTION_SECRET = os.environ.get('ENCRYPTION_SECRET') or EncryptionManager.generate_key()
    
    # Security headers
    SECURE_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
    }

    # Rate limiting
    RATELIMIT_DEFAULT = "200 per day;50 per hour;1 per second"
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or "memory://"

    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'

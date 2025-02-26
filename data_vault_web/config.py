import os
from dotenv import load_dotenv
from shared.encryption import EncryptionManager
from datetime import timedelta

# Load environment variables
load_dotenv()

class Config:
    """Base configuration"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    DEBUG = False
    TESTING = False
    ENV = 'production'
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///data_vault.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT settings
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or os.urandom(32).hex()
    JWT_ACCESS_TOKEN_MINUTES = 30  # 30 minutes
    JWT_REFRESH_TOKEN_DAYS = 14  # 14 days
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # Encryption settings
    ENCRYPTION_SECRET = os.environ.get('ENCRYPTION_SECRET') or EncryptionManager.generate_key().decode()
    
    # Security headers
    SECURE_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    
    # Content Security Policy
    CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com",
        'style-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        'img-src': "'self' data:",
        'font-src': "'self' https://cdnjs.cloudflare.com",
        'connect-src': "'self'",
        'frame-src': "'none'",
        'object-src': "'none'"
    }
    
    # CORS settings
    CORS_ORIGINS = ['http://localhost:3000', 'https://vault.example.com']
    
    # Rate limiting
    RATELIMIT_DEFAULT = "200 per day;50 per hour;1 per second"
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or "memory://"
    
    # HTTPS settings
    FORCE_HTTPS = False
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    
    # Password policy
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_CHECK_BREACH = True
    
    # MFA settings
    MFA_TOTP_ISSUER = 'Data Privacy Vault'
    MFA_BACKUP_CODES_COUNT = 10

class DevConfig(Config):
    """Development configuration"""
    DEBUG = True
    ENV = 'development'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///data_vault_dev.db'
    FORCE_HTTPS = False
    
    # Relaxed CORS for development
    CORS_ORIGINS = ['*']
    
    # Relaxed rate limiting for development
    RATELIMIT_DEFAULT = "1000 per day;200 per hour;10 per second"

class TestConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    ENV = 'testing'
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'sqlite:///data_vault_test.db'
    
    # Disable rate limiting for tests
    RATELIMIT_ENABLED = False
    
    # Use shorter token times for testing
    JWT_ACCESS_TOKEN_MINUTES = 1
    JWT_REFRESH_TOKEN_DAYS = 1

class ProdConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    # In production, enforce HTTPS
    FORCE_HTTPS = True
    
    # Stricter CSP for production
    CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': "'self' https://cdnjs.cloudflare.com",
        'style-src': "'self' https://cdnjs.cloudflare.com",
        'img-src': "'self' data:",
        'font-src': "'self' https://cdnjs.cloudflare.com",
        'connect-src': "'self'",
        'frame-src': "'none'",
        'object-src': "'none'",
        'base-uri': "'self'",
        'form-action': "'self'",
        'frame-ancestors': "'none'"
    }
    
    # More restrictive CORS settings for production
    CORS_ORIGINS = [os.environ.get('ALLOWED_ORIGIN', 'https://vault.example.com')]
    
    # Additional security headers for production
    SECURE_HEADERS = {
        **Config.SECURE_HEADERS,
        'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()'
    }

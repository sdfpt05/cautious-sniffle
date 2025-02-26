from flask import Flask, request, g, redirect
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from config import Config, ProdConfig
from shared.models import init_db, TokenBlacklist
from auth import auth
from api import api
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timezone

# Initialize extensions
migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()
talisman = Talisman()

# Initialize token blocklist
jwt_blocklist = set()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # In production, use HTTPS
    if os.environ.get('FLASK_ENV') == 'production':
        app.config.from_object(ProdConfig)
    
    # Initialize extensions
    jwt.init_app(app)
    migrate.init_app(app)
    limiter.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": app.config['CORS_ORIGINS']}})
    csrf.init_app(app)
    talisman.init_app(
        app,
        content_security_policy=app.config['CONTENT_SECURITY_POLICY'],
        force_https=app.config['FORCE_HTTPS']
    )
    
    # Initialize database session
    app.db_session = init_db(app.config['SQLALCHEMY_DATABASE_URI'])
    
    # JWT token blocklist checker
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        
        # Check in-memory blocklist first (for performance)
        if jti in jwt_blocklist:
            return True
        
        # Check database blocklist for persistence
        token = app.db_session.query(TokenBlacklist).filter_by(jti=jti).first()
        return token is not None
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return {"msg": "Token has been revoked"}, 401
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {"msg": "Token has expired"}, 401
    
    # Register blueprints
    app.register_blueprint(auth, url_prefix='/auth')
    app.register_blueprint(api, url_prefix='/api')
    
    # Setup logging
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/data_vault.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Data Vault startup')
    
    # Request middleware for security headers
    @app.before_request
    def before_request():
        # Force HTTPS in production
        if app.config['FORCE_HTTPS'] and not request.is_secure and app.config['ENV'] == 'production':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
        
        # Set security headers
        for header, value in app.config.get('SECURE_HEADERS', {}).items():
            if header not in response.headers:
                response.headers[header] = value
    
    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return {"msg": "Not found"}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        app.db_session.rollback()
        app.logger.error('Server Error: %s', error)
        return {"msg": "Internal server error"}, 500
    
    # Cleanup database connection
    @app.teardown_appcontext
    def cleanup(error):
        if hasattr(g, 'db_session'):
            g.db_session.close()
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=os.environ.get('FLASK_DEBUG', 'False') == 'True')
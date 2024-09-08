from flask import Flask
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from config import Config
from models import init_db
from auth import auth
from api import api
import logging
from logging.handlers import RotatingFileHandler
import os

migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    jwt.init_app(app)
    migrate.init_app(app)
    limiter.init_app(app)
    CORS(app)

    # Initialize database session
    app.db_session = init_db(app.config['SQLALCHEMY_DATABASE_URI'])

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

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
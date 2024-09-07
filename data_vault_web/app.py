from flask import Flask
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db
from config import Config
from auth import init_auth
from api import api

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    Migrate(app, db)

    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=[Config.RATE_LIMIT]
    )

    init_auth(app)
    app.register_blueprint(api, url_prefix='/api')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import User
from flask import jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

jwt = JWTManager()

def init_auth(app):
    jwt.init_app(app)

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
        if User.query.filter_by(username=data['username']).first():
            return jsonify({"msg": "Username already exists"}), 400
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"msg": "Email already exists"}), 400
        
        new_user = User(username=data['username'], email=data['email'])
        new_user.set_password(data['password'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg": "User created successfully"}), 201

    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))
            return jsonify(access_token=access_token), 200
        return jsonify({"msg": "Invalid username or password"}), 401

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({"msg": "Token has expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({"msg": "Invalid token"}), 401

    return app
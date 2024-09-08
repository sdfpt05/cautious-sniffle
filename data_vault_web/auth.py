from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, create_refresh_token, get_jwt
from models import User
from werkzeug.security import check_password_hash
from datetime import timedelta
from sqlalchemy.exc import IntegrityError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

auth = Blueprint('auth', __name__)
limiter = Limiter(key_func=get_remote_address)

@auth.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    data = request.get_json()
    try:
        new_user = User(username=data['username'], email=data['email'])
        new_user.set_password(data['password'])
        current_app.db_session.add(new_user)
        current_app.db_session.commit()
        return jsonify({"msg": "User registered successfully", "user_id": new_user.public_id}), 201
    except IntegrityError:
        current_app.db_session.rollback()
        return jsonify({"msg": "Username or email already exists"}), 400
    except KeyError:
        return jsonify({"msg": "Missing username, email or password"}), 400

@auth.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    user = current_app.db_session.query(User).filter_by(username=data['username']).first()
    if user and check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=user.public_id, expires_delta=timedelta(hours=1))
        refresh_token = create_refresh_token(identity=user.public_id)
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200
    return jsonify({"msg": "Invalid username or password"}), 401

@auth.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user, expires_delta=timedelta(hours=1))
    return jsonify(access_token=new_token), 200

@auth.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    # Here you would typically add the token to a blocklist
    # For simplicity, we'll just return a success message
    return jsonify({"msg": "Successfully logged out"}), 200

@auth.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    return jsonify(logged_in_as=current_user_id), 200
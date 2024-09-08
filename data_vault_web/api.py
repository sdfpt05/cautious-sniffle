# Imports
from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from shared.models import Credential, User
from shared.encryption import EncryptionManager
from sqlalchemy.exc import IntegrityError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime

# Blueprint and Limiter initialization
api = Blueprint('api', __name__)
limiter = Limiter(key_func=get_remote_address)

# Encryption manager initialization
encryption_manager = EncryptionManager(current_app.config['ENCRYPTION_SECRET'])

# Routes

@api.route('/credentials', methods=['GET'])
@jwt_required()
@limiter.limit("30 per minute")
def get_credentials():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    credentials = current_app.db_session.query(Credential).filter_by(user_id=user.id).all()
    return jsonify([
        {
            'id': cred.public_id,
            'name': cred.name,
            'data': encryption_manager.decrypt_data(cred.encrypted_data.encode())
        } for cred in credentials
    ]), 200

@api.route('/credentials', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def add_credential():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    data = request.get_json()
    try:
        encrypted_data = encryption_manager.encrypt_data(data['data'])
        new_credential = Credential(name=data['name'], encrypted_data=encrypted_data, user_id=user.id)
        current_app.db_session.add(new_credential)
        current_app.db_session.commit()
        return jsonify({"msg": "Credential added successfully", "id": new_credential.public_id}), 201
    except KeyError:
        return jsonify({"msg": "Missing name or data"}), 400
    except IntegrityError:
        current_app.db_session.rollback()
        return jsonify({"msg": "Error adding credential"}), 400

@api.route('/credentials/<string:cred_public_id>', methods=['PUT'])
@jwt_required()
@limiter.limit("10 per minute")
def update_credential(cred_public_id):
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    credential = current_app.db_session.query(Credential).filter_by(public_id=cred_public_id, user_id=user.id).first()
    if not credential:
        return jsonify({"msg": "Credential not found"}), 404
    
    data = request.get_json()
    try:
        if 'name' in data:
            credential.name = data['name']
        if 'data' in data:
            credential.encrypted_data = encryption_manager.encrypt_data(data['data'])
        current_app.db_session.commit()
        return jsonify({"msg": "Credential updated successfully"}), 200
    except IntegrityError:
        current_app.db_session.rollback()
        return jsonify({"msg": "Error updating credential"}), 400

@api.route('/credentials/<string:cred_public_id>', methods=['DELETE'])
@jwt_required()
@limiter.limit("10 per minute")
def delete_credential(cred_public_id):
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    credential = current_app.db_session.query(Credential).filter_by(public_id=cred_public_id, user_id=user.id).first()
    if not credential:
        return jsonify({"msg": "Credential not found"}), 404
    
    current_app.db_session.delete(credential)
    current_app.db_session.commit()
    return jsonify({"msg": "Credential deleted successfully"}), 200

# New Routes for Synchronization

@api.route('/sync_credential', methods=['POST'])
@jwt_required()
def sync_credential():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    data = request.get_json()
    try:
        credential = current_app.db_session.query(Credential).filter_by(name=data['name'], user_id=user.id).first()
        if credential:
            if datetime.fromisoformat(data['last_modified']) > credential.updated_at:
                credential.data = data['data']
                credential.updated_at = datetime.fromisoformat(data['last_modified'])
        else:
            new_credential = Credential(name=data['name'], data=data['data'], user_id=user.id)
            current_app.db_session.add(new_credential)
        
        current_app.db_session.commit()
        return jsonify({"msg": "Credential synced successfully"}), 200
    except KeyError:
        return jsonify({"msg": "Missing required data"}), 400
    except IntegrityError:
        current_app.db_session.rollback()
        return jsonify({"msg": "Error syncing credential"}), 400

@api.route('/get_credentials', methods=['GET'])
@jwt_required()
def get_credentials_for_sync():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    credentials = current_app.db_session.query(Credential).filter_by(user_id=user.id).all()
    return jsonify([
        {
            'name': cred.name,
            'data': cred.data,
            'last_modified': str(cred.updated_at)
        } for cred in credentials
    ]), 200

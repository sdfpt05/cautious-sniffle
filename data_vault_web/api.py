from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Credential, User
from encryption import EncryptionManager
from config import Config

api = Blueprint('api', __name__)
encryption_manager = EncryptionManager(Config.ENCRYPTION_KEY)

@api.route('/credentials', methods=['GET'])
@jwt_required()
def get_credentials():
    user_id = get_jwt_identity()
    credentials = Credential.query.filter_by(user_id=user_id).all()
    return jsonify([
        {
            'id': cred.id,
            'name': cred.name,
            'data': encryption_manager.decrypt_data(cred.encrypted_data)
        } for cred in credentials
    ]), 200

@api.route('/credentials', methods=['POST'])
@jwt_required()
def add_credential():
    user_id = get_jwt_identity()
    data = request.get_json()
    encrypted_data = encryption_manager.encrypt_data(data['data'])
    new_credential = Credential(name=data['name'], encrypted_data=encrypted_data, user_id=user_id)
    db.session.add(new_credential)
    db.session.commit()
    return jsonify({"msg": "Credential added successfully"}), 201

@api.route('/credentials/<int:cred_id>', methods=['PUT'])
@jwt_required()
def update_credential(cred_id):
    user_id = get_jwt_identity()
    credential = Credential.query.filter_by(id=cred_id, user_id=user_id).first()
    if not credential:
        return jsonify({"msg": "Credential not found"}), 404
    data = request.get_json()
    credential.name = data.get('name', credential.name)
    if 'data' in data:
        credential.encrypted_data = encryption_manager.encrypt_data(data['data'])
    db.session.commit()
    return jsonify({"msg": "Credential updated successfully"}), 200

@api.route('/credentials/<int:cred_id>', methods=['DELETE'])
@jwt_required()
def delete_credential(cred_id):
    user_id = get_jwt_identity()
    credential = Credential.query.filter_by(id=cred_id, user_id=user_id).first()
    if not credential:
        return jsonify({"msg": "Credential not found"}), 404
    db.session.delete(credential)
    db.session.commit()
    return jsonify({"msg": "Credential deleted successfully"}), 200
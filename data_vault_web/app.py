from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import sessionmaker
from shared.models import User, Credential, init_db
from shared.encryption import EncryptionManager, generate_key
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///data_vault.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(app)
engine = init_db(app.config['SQLALCHEMY_DATABASE_URI'])
Session = sessionmaker(bind=engine)
migrate = Migrate(app, engine)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

encryption_key, _ = generate_key(os.getenv('ENCRYPTION_PASSWORD', 'default_password'))
encryption_manager = EncryptionManager(encryption_key)

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    session = Session()
    if session.query(User).filter_by(username=data['username']).first():
        return jsonify({"msg": "Username already exists"}), 400
    if session.query(User).filter_by(email=data['email']).first():
        return jsonify({"msg": "Email already exists"}), 400
    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])
    session.add(new_user)
    session.commit()
    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    session = Session()
    user = session.query(User).filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({"msg": "Invalid username or password"}), 401

@app.route('/credentials', methods=['GET'])
@jwt_required()
def get_credentials():
    user_id = get_jwt_identity()
    session = Session()
    credentials = session.query(Credential).filter_by(user_id=user_id).all()
    return jsonify([
        {
            'id': cred.id,
            'name': cred.name,
            'data': encryption_manager.decrypt_data(cred.encrypted_data.encode())
        } for cred in credentials
    ]), 200

@app.route('/credentials', methods=['POST'])
@jwt_required()
def add_credential():
    user_id = get_jwt_identity()
    data = request.get_json()
    session = Session()
    encrypted_data = encryption_manager.encrypt_data(data['data'])
    new_credential = Credential(name=data['name'], encrypted_data=encrypted_data, user_id=user_id)
    session.add(new_credential)
    session.commit()
    return jsonify({"msg": "Credential added successfully"}), 201

@app.route('/credentials/<int:cred_id>', methods=['PUT'])
@jwt_required()
def update_credential(cred_id):
    user_id = get_jwt_identity()
    session = Session()
    credential = session.query(Credential).filter_by(id=cred_id, user_id=user_id).first()
    if not credential:
        return jsonify({"msg": "Credential not found"}), 404
    data = request.get_json()
    credential.name = data.get('name', credential.name)
    if 'data' in data:
        credential.encrypted_data = encryption_manager.encrypt_data(data['data'])
    session.commit()
    return jsonify({"msg": "Credential updated successfully"}), 200

@app.route('/credentials/<int:cred_id>', methods=['DELETE'])
@jwt_required()
def delete_credential(cred_id):
    user_id = get_jwt_identity()
    session = Session()
    credential = session.query(Credential).filter_by(id=cred_id, user_id=user_id).first()
    if not credential:
        return jsonify({"msg": "Credential not found"}), 404
    session.delete(credential)
    session.commit()
    return jsonify({"msg": "Credential deleted successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True)
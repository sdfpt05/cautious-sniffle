from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from shared.models import Credential, User, AuditLog
from shared.encryption import EncryptionManager
from sqlalchemy.exc import IntegrityError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import uuid
import json
from sqlalchemy import desc

# Blueprint and Limiter initialization
api = Blueprint('api', __name__)
limiter = Limiter(key_func=get_remote_address)

# Decorator for logging API access
def log_api_access(action):
    def decorator(f):
        def wrapper(*args, **kwargs):
            # Get user info before the function runs
            user_public_id = get_jwt_identity()
            user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
            
            # Execute the function
            result = f(*args, **kwargs)
            
            # Log the access
            if user:
                log_entry = AuditLog(
                    user_id=user.id,
                    action=action,
                    details=f"API access: {request.method} {request.path}",
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', '')
                )
                current_app.db_session.add(log_entry)
                current_app.db_session.commit()
                
            return result
        return wrapper
    return decorator

# Routes
@api.route('/credentials', methods=['GET'])
@jwt_required()
@limiter.limit("30 per minute")
@log_api_access("get_credentials")
def get_credentials():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    # Get query parameters
    category = request.args.get('category', None)
    search = request.args.get('search', None)
    favorite = request.args.get('favorite', None)
    sort_by = request.args.get('sort_by', 'name')
    sort_direction = request.args.get('sort_direction', 'asc')
    
    # Base query
    query = current_app.db_session.query(Credential).filter_by(user_id=user.id)
    
    # Apply filters
    if category:
        query = query.filter_by(category=category)
    if search:
        query = query.filter(Credential.name.ilike(f'%{search}%'))
    if favorite:
        favorite_bool = favorite.lower() == 'true'
        query = query.filter_by(favorite=favorite_bool)
    
    # Apply sorting
    if sort_by not in ['name', 'category', 'created_at', 'updated_at']:
        sort_by = 'name'
    
    if sort_direction.lower() == 'desc':
        query = query.order_by(desc(getattr(Credential, sort_by)))
    else:
        query = query.order_by(getattr(Credential, sort_by))
    
    # Execute query
    credentials = query.all()
    
    # Prepare response
    try:
        # Create EncryptionManager for decryption
        encryption_manager = EncryptionManager(user.encryption_key)
        
        response_data = []
        for cred in credentials:
            try:
                decrypted_data = encryption_manager.decrypt_data(cred.encrypted_data.encode())
                response_data.append({
                    'id': cred.public_id,
                    'name': cred.name,
                    'data': decrypted_data,
                    'category': cred.category,
                    'url': cred.url,
                    'notes': cred.notes,
                    'favorite': cred.favorite,
                    'created_at': cred.created_at.isoformat() if cred.created_at else None,
                    'updated_at': cred.updated_at.isoformat() if cred.updated_at else None
                })
            except Exception as e:
                current_app.logger.error(f"Error decrypting credential {cred.id}: {str(e)}")
                # Skip credentials that can't be decrypted
                continue
        
        return jsonify(response_data), 200
    except Exception as e:
        current_app.logger.error(f"Error processing credentials: {str(e)}")
        return jsonify({"msg": "Error retrieving credentials"}), 500

@api.route('/credentials', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
@log_api_access("add_credential")
def add_credential():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    data = request.get_json()
    required_fields = ['name', 'data']
    for field in required_fields:
        if field not in data:
            return jsonify({"msg": f"Missing required field: {field}"}), 400
    
    try:
        # Check if credential with this name already exists
        existing = current_app.db_session.query(Credential).filter_by(
            name=data['name'], 
            user_id=user.id
        ).first()
        
        if existing:
            return jsonify({"msg": "Credential with this name already exists"}), 409
        
        # Create encryption manager
        encryption_manager = EncryptionManager(user.encryption_key)
        
        # Encrypt the data
        encrypted_data = encryption_manager.encrypt_data(data['data'])
        
        # Create new credential
        new_credential = Credential(
            public_id=str(uuid.uuid4()),
            name=data['name'],
            encrypted_data=encrypted_data,
            user_id=user.id,
            category=data.get('category'),
            url=data.get('url'),
            notes=data.get('notes'),
            favorite=data.get('favorite', False)
        )
        
        current_app.db_session.add(new_credential)
        current_app.db_session.commit()
        
        return jsonify({
            "msg": "Credential added successfully", 
            "id": new_credential.public_id
        }), 201
        
    except IntegrityError:
        current_app.db_session.rollback()
        return jsonify({"msg": "Error adding credential - duplicate name"}), 400
    except Exception as e:
        current_app.db_session.rollback()
        current_app.logger.error(f"Error adding credential: {str(e)}")
        return jsonify({"msg": "Error adding credential"}), 500

@api.route('/credentials/<string:cred_public_id>', methods=['GET'])
@jwt_required()
@limiter.limit("20 per minute")
@log_api_access("get_credential")
def get_credential(cred_public_id):
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    credential = current_app.db_session.query(Credential).filter_by(
        public_id=cred_public_id, 
        user_id=user.id
    ).first()
    
    if not credential:
        return jsonify({"msg": "Credential not found"}), 404
    
    try:
        # Create encryption manager
        encryption_manager = EncryptionManager(user.encryption_key)
        
        # Decrypt the data
        decrypted_data = encryption_manager.decrypt_data(credential.encrypted_data.encode())
        
        return jsonify({
            'id': credential.public_id,
            'name': credential.name,
            'data': decrypted_data,
            'category': credential.category,
            'url': credential.url,
            'notes': credential.notes,
            'favorite': credential.favorite,
            'created_at': credential.created_at.isoformat() if credential.created_at else None,
            'updated_at': credential.updated_at.isoformat() if credential.updated_at else None
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error retrieving credential: {str(e)}")
        return jsonify({"msg": "Error retrieving credential"}), 500

@api.route('/credentials/<string:cred_public_id>', methods=['PUT'])
@jwt_required()
@limiter.limit("10 per minute")
@log_api_access("update_credential")
def update_credential(cred_public_id):
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    credential = current_app.db_session.query(Credential).filter_by(
        public_id=cred_public_id, 
        user_id=user.id
    ).first()
    
    if not credential:
        return jsonify({"msg": "Credential not found"}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({"msg": "No data provided"}), 400
    
    try:
        # Update fields
        if 'name' in data and data['name'] != credential.name:
            # Check if name conflicts with existing credential
            existing = current_app.db_session.query(Credential).filter_by(
                name=data['name'], 
                user_id=user.id
            ).first()
            
            if existing and existing.id != credential.id:
                return jsonify({"msg": "Credential with this name already exists"}), 409
            
            credential.name = data['name']
        
        # Update data if provided
        if 'data' in data:
            encryption_manager = EncryptionManager(user.encryption_key)
            credential.encrypted_data = encryption_manager.encrypt_data(data['data'])
        
        # Update other fields
        if 'category' in data:
            credential.category = data['category']
        if 'url' in data:
            credential.url = data['url']
        if 'notes' in data:
            credential.notes = data['notes']
        if 'favorite' in data:
            credential.favorite = data['favorite']
        
        credential.updated_at = datetime.now()
        current_app.db_session.commit()
        
        return jsonify({"msg": "Credential updated successfully"}), 200
        
    except IntegrityError:
        current_app.db_session.rollback()
        return jsonify({"msg": "Error updating credential - duplicate name"}), 400
    except Exception as e:
        current_app.db_session.rollback()
        current_app.logger.error(f"Error updating credential: {str(e)}")
        return jsonify({"msg": "Error updating credential"}), 500

@api.route('/credentials/<string:cred_public_id>', methods=['DELETE'])
@jwt_required()
@limiter.limit("10 per minute")
@log_api_access("delete_credential")
def delete_credential(cred_public_id):
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    credential = current_app.db_session.query(Credential).filter_by(
        public_id=cred_public_id, 
        user_id=user.id
    ).first()
    
    if not credential:
        return jsonify({"msg": "Credential not found"}), 404
    
    try:
        current_app.db_session.delete(credential)
        current_app.db_session.commit()
        
        return jsonify({"msg": "Credential deleted successfully"}), 200
        
    except Exception as e:
        current_app.db_session.rollback()
        current_app.logger.error(f"Error deleting credential: {str(e)}")
        return jsonify({"msg": "Error deleting credential"}), 500

@api.route('/categories', methods=['GET'])
@jwt_required()
@limiter.limit("20 per minute")
def get_categories():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    try:
        # Get distinct categories for the user
        categories = current_app.db_session.query(Credential.category) \
            .filter_by(user_id=user.id) \
            .filter(Credential.category.isnot(None)) \
            .distinct() \
            .all()
        
        # Extract categories from result
        category_list = [c[0] for c in categories if c[0]]
        
        return jsonify(category_list), 200
        
    except Exception as e:
        current_app.logger.error(f"Error retrieving categories: {str(e)}")
        return jsonify({"msg": "Error retrieving categories"}), 500

@api.route('/export', methods=['GET'])
@jwt_required()
@limiter.limit("5 per hour")
@log_api_access("export_data")
def export_data():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    format_type = request.args.get('format', 'json')
    encrypt = request.args.get('encrypt', 'true').lower() == 'true'
    
    try:
        # Get all credentials for the user
        credentials = current_app.db_session.query(Credential).filter_by(user_id=user.id).all()
        
        # Create encryption manager
        encryption_manager = EncryptionManager(user.encryption_key)
        
        if format_type == 'json':
            # Prepare JSON export
            export_data = {
                'metadata': {
                    'export_date': datetime.now().isoformat(),
                    'username': user.username,
                    'email': user.email,
                    'credential_count': len(credentials)
                },
                'credentials': []
            }
            
            for cred in credentials:
                # Decrypt the data
                decrypted_data = encryption_manager.decrypt_data(cred.encrypted_data.encode())
                
                export_data['credentials'].append({
                    'name': cred.name,
                    'data': decrypted_data,
                    'category': cred.category,
                    'url': cred.url,
                    'notes': cred.notes,
                    'favorite': cred.favorite,
                    'created_at': cred.created_at.isoformat() if cred.created_at else None,
                    'updated_at': cred.updated_at.isoformat() if cred.updated_at else None
                })
            
            if encrypt:
                # Encrypt the entire export
                export_json = json.dumps(export_data)
                encrypted_export = encryption_manager.encrypt_data(export_json)
                
                return jsonify({
                    'encrypted_data': encrypted_export.decode(),
                    'format': 'json',
                    'encrypted': True
                }), 200
            else:
                return jsonify(export_data), 200
                
        elif format_type == 'csv':
            # Prepare CSV export
            import csv
            import io
            
            output = io.StringIO()
            fieldnames = ['name', 'data', 'category', 'url', 'notes', 'favorite', 'created_at', 'updated_at']
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for cred in credentials:
                # Decrypt the data
                decrypted_data = encryption_manager.decrypt_data(cred.encrypted_data.encode())
                
                writer.writerow({
                    'name': cred.name,
                    'data': decrypted_data,
                    'category': cred.category or '',
                    'url': cred.url or '',
                    'notes': cred.notes or '',
                    'favorite': 'Yes' if cred.favorite else 'No',
                    'created_at': cred.created_at.isoformat() if cred.created_at else '',
                    'updated_at': cred.updated_at.isoformat() if cred.updated_at else ''
                })
            
            csv_data = output.getvalue()
            
            if encrypt:
                # Encrypt the CSV data
                encrypted_csv = encryption_manager.encrypt_data(csv_data)
                
                return jsonify({
                    'encrypted_data': encrypted_csv.decode(),
                    'format': 'csv',
                    'encrypted': True
                }), 200
            else:
                return jsonify({
                    'csv_data': csv_data,
                    'format': 'csv',
                    'encrypted': False
                }), 200
        else:
            return jsonify({"msg": "Unsupported export format"}), 400
            
    except Exception as e:
        current_app.logger.error(f"Error exporting data: {str(e)}")
        return jsonify({"msg": "Error exporting data"}), 500

@api.route('/import', methods=['POST'])
@jwt_required()
@limiter.limit("5 per hour")
@log_api_access("import_data")
def import_data():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({"msg": "No data provided"}), 400
    
    format_type = data.get('format', 'json')
    is_encrypted = data.get('encrypted', False)
    replace_existing = data.get('replace_existing', False)
    
    try:
        # Create encryption manager
        encryption_manager = EncryptionManager(user.encryption_key)
        
        if format_type == 'json':
            import_data = None
            
            if is_encrypted:
                # Decrypt the data
                if 'encrypted_data' not in data:
                    return jsonify({"msg": "Missing encrypted_data field"}), 400
                
                decrypted_json = encryption_manager.decrypt_data(data['encrypted_data'].encode())
                import_data = json.loads(decrypted_json)
            else:
                if 'credentials' not in data:
                    return jsonify({"msg": "Missing credentials field"}), 400
                
                import_data = data
            
            if 'credentials' not in import_data:
                return jsonify({"msg": "Invalid import file format"}), 400
            
            imported_count = 0
            skipped_count = 0
            
            for cred_data in import_data['credentials']:
                name = cred_data.get('name')
                if not name:
                    skipped_count += 1
                    continue
                
                # Check if credential already exists
                existing_cred = current_app.db_session.query(Credential).filter_by(
                    name=name, 
                    user_id=user.id
                ).first()
                
                if existing_cred and not replace_existing:
                    skipped_count += 1
                    continue
                
                # Encrypt the credential data
                encrypted_data = encryption_manager.encrypt_data(cred_data.get('data', ''))
                
                if existing_cred:
                    # Update existing
                    existing_cred.encrypted_data = encrypted_data
                    existing_cred.category = cred_data.get('category')
                    existing_cred.url = cred_data.get('url')
                    existing_cred.notes = cred_data.get('notes')
                    existing_cred.favorite = cred_data.get('favorite', False)
                    existing_cred.updated_at = datetime.now()
                else:
                    # Create new
                    new_cred = Credential(
                        public_id=str(uuid.uuid4()),
                        name=name,
                        encrypted_data=encrypted_data,
                        user_id=user.id,
                        category=cred_data.get('category'),
                        url=cred_data.get('url'),
                        notes=cred_data.get('notes'),
                        favorite=cred_data.get('favorite', False)
                    )
                    current_app.db_session.add(new_cred)
                
                imported_count += 1
            
            current_app.db_session.commit()
            
            return jsonify({
                "msg": f"Imported {imported_count} credentials, skipped {skipped_count}"
            }), 200
            
        elif format_type == 'csv':
            if is_encrypted:
                # Decrypt the data
                if 'encrypted_data' not in data:
                    return jsonify({"msg": "Missing encrypted_data field"}), 400
                
                decrypted_csv = encryption_manager.decrypt_data(data['encrypted_data'].encode())
                csv_data = decrypted_csv
            else:
                if 'csv_data' not in data:
                    return jsonify({"msg": "Missing csv_data field"}), 400
                
                csv_data = data['csv_data']
            
            import csv
            import io
            
            imported_count = 0
            skipped_count = 0
            
            csv_file = io.StringIO(csv_data)
            reader = csv.DictReader(csv_file)
            
            for row in reader:
                name = row.get('name')
                if not name:
                    skipped_count += 1
                    continue
                
                # Check if credential already exists
                existing_cred = current_app.db_session.query(Credential).filter_by(
                    name=name, 
                    user_id=user.id
                ).first()
                
                if existing_cred and not replace_existing:
                    skipped_count += 1
                    continue
                
                # Encrypt the credential data
                encrypted_data = encryption_manager.encrypt_data(row.get('data', ''))
                
                if existing_cred:
                    # Update existing
                    existing_cred.encrypted_data = encrypted_data
                    existing_cred.category = row.get('category')
                    existing_cred.url = row.get('url')
                    existing_cred.notes = row.get('notes')
                    existing_cred.favorite = row.get('favorite', '').lower() == 'yes'
                    existing_cred.updated_at = datetime.now()
                else:
                    # Create new
                    new_cred = Credential(
                        public_id=str(uuid.uuid4()),
                        name=name,
                        encrypted_data=encrypted_data,
                        user_id=user.id,
                        category=row.get('category'),
                        url=row.get('url'),
                        notes=row.get('notes'),
                        favorite=row.get('favorite', '').lower() == 'yes'
                    )
                    current_app.db_session.add(new_cred)
                
                imported_count += 1
            
            current_app.db_session.commit()
            
            return jsonify({
                "msg": f"Imported {imported_count} credentials, skipped {skipped_count}"
            }), 200
        else:
            return jsonify({"msg": "Unsupported import format"}), 400
            
    except Exception as e:
        current_app.db_session.rollback()
        current_app.logger.error(f"Error importing data: {str(e)}")
        return jsonify({"msg": f"Error importing data: {str(e)}"}), 500

# Routes for Synchronization
@api.route('/sync_credential', methods=['POST'])
@jwt_required()
@limiter.limit("30 per minute")
def sync_credential():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    data = request.get_json()
    try:
        if 'name' not in data or 'data' not in data or 'last_modified' not in data:
            return jsonify({"msg": "Missing required fields"}), 400
        
        credential = current_app.db_session.query(Credential).filter_by(
            name=data['name'], 
            user_id=user.id
        ).first()
        
        remote_modified = datetime.fromisoformat(data['last_modified'])
        
        if credential:
            if not credential.updated_at or remote_modified > credential.updated_at:
                credential.encrypted_data = data['data']
                credential.category = data.get('category', credential.category)
                credential.url = data.get('url', credential.url)
                credential.notes = data.get('notes', credential.notes)
                credential.favorite = data.get('favorite', credential.favorite)
                credential.updated_at = remote_modified
        else:
            new_credential = Credential(
                public_id=str(uuid.uuid4()),
                name=data['name'],
                encrypted_data=data['data'],
                user_id=user.id,
                category=data.get('category'),
                url=data.get('url'),
                notes=data.get('notes'),
                favorite=data.get('favorite', False),
                updated_at=remote_modified
            )
            current_app.db_session.add(new_credential)
        
        current_app.db_session.commit()
        
        # Log the sync
        log_entry = AuditLog(
            user_id=user.id,
            action="sync_credential",
            details=f"Synchronized credential: {data['name']}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        current_app.db_session.add(log_entry)
        current_app.db_session.commit()
        
        return jsonify({"msg": "Credential synced successfully"}), 200
        
    except KeyError:
        return jsonify({"msg": "Missing required data"}), 400
    except IntegrityError:
        current_app.db_session.rollback()
        return jsonify({"msg": "Error syncing credential"}), 400
    except Exception as e:
        current_app.db_session.rollback()
        current_app.logger.error(f"Error syncing credential: {str(e)}")
        return jsonify({"msg": f"Error syncing credential: {str(e)}"}), 500

@api.route('/get_credentials_for_sync', methods=['GET'])
@jwt_required()
@limiter.limit("10 per minute")
def get_credentials_for_sync():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    try:
        credentials = current_app.db_session.query(Credential).filter_by(user_id=user.id).all()
        
        # Log the sync request
        log_entry = AuditLog(
            user_id=user.id,
            action="get_credentials_for_sync",
            details="Retrieved credentials for synchronization",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        current_app.db_session.add(log_entry)
        current_app.db_session.commit()
        
        return jsonify([
            {
                'name': cred.name,
                'data': cred.encrypted_data,
                'category': cred.category,
                'url': cred.url,
                'notes': cred.notes,
                'favorite': cred.favorite,
                'last_modified': cred.updated_at.isoformat() if cred.updated_at else datetime.now().isoformat()
            } for cred in credentials
        ]), 200
        
    except Exception as e:
        current_app.logger.error(f"Error retrieving credentials for sync: {str(e)}")
        return jsonify({"msg": "Error retrieving credentials"}), 500

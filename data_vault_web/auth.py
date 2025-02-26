from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, 
    create_refresh_token, get_jwt
)
from shared.models import User, AuditLog, TokenBlacklist
from datetime import timedelta, datetime
from sqlalchemy.exc import IntegrityError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from shared.password_checker import PasswordValidator
from shared.mfa import MFAManager
import json
import re

auth = Blueprint('auth', __name__)
limiter = Limiter(key_func=get_remote_address)

@auth.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    data = request.get_json()
    
    try:
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({"msg": f"Missing required field: {field}"}), 400
        
        username = data['username']
        email = data['email']
        password = data['password']
        
        # Validate username
        if len(username) < 3:
            return jsonify({"msg": "Username must be at least 3 characters long"}), 400
        
        # Validate email format
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return jsonify({"msg": "Invalid email format"}), 400
        
        # Validate password strength
        is_valid, message = PasswordValidator.validate_password(password)
        if not is_valid:
            return jsonify({"msg": message}), 400
        
        # Check if username or email already exists
        existing_user = current_app.db_session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                return jsonify({"msg": "Username already exists"}), 400
            else:
                return jsonify({"msg": "Email already exists"}), 400
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        # Generate encryption key
        from shared.encryption import generate_key
        encryption_key = generate_key()[0]
        new_user.encryption_key = encryption_key
        
        current_app.db_session.add(new_user)
        current_app.db_session.commit()
        
        # Log the registration
        client_info = request.headers.get('User-Agent', '')
        ip_address = request.remote_addr
        
        log_entry = AuditLog(
            user_id=new_user.id,
            action="register",
            details="New user registration",
            ip_address=ip_address,
            user_agent=client_info
        )
        current_app.db_session.add(log_entry)
        current_app.db_session.commit()
        
        return jsonify({
            "msg": "User registered successfully", 
            "user_id": new_user.public_id
        }), 201
        
    except IntegrityError:
        current_app.db_session.rollback()
        return jsonify({"msg": "Username or email already exists"}), 400
    except Exception as e:
        current_app.db_session.rollback()
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({"msg": "An error occurred during registration"}), 500

@auth.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    
    # Check required fields
    if 'username' not in data or 'password' not in data:
        return jsonify({"msg": "Missing username or password"}), 400
    
    user = current_app.db_session.query(User).filter_by(username=data['username']).first()
    
    # User not found
    if not user:
        return jsonify({"msg": "Invalid username or password"}), 401
    
    # Check if account is locked
    if user.failed_login_attempts >= 5:
        return jsonify({
            "msg": "Account is locked due to too many failed login attempts. Please try again later."
        }), 401
    
    # Verify password
    if user.check_password(data['password']):
        # Check MFA if enabled
        if user.mfa_enabled:
            if 'mfa_code' not in data:
                return jsonify({
                    "msg": "MFA code required", 
                    "require_mfa": True
                }), 401
            
            mfa_manager = MFAManager(user.mfa_secret)
            if not mfa_manager.verify_code(data['mfa_code']):
                # Increment failed login attempts
                user.increment_failed_login_attempts()
                current_app.db_session.commit()
                
                # Log failed MFA attempt
                log_failed_login(user, request, "Failed MFA validation")
                
                return jsonify({"msg": "Invalid MFA code"}), 401
        
        # Reset failed login attempts and update last login
        user.reset_failed_login_attempts()
        current_app.db_session.commit()
        
        # Generate tokens
        access_token = create_access_token(
            identity=user.public_id, 
            expires_delta=timedelta(minutes=current_app.config['JWT_ACCESS_TOKEN_MINUTES'])
        )
        refresh_token = create_refresh_token(
            identity=user.public_id,
            expires_delta=timedelta(days=current_app.config['JWT_REFRESH_TOKEN_DAYS'])
        )
        
        # Log successful login
        log_entry = AuditLog(
            user_id=user.id,
            action="login",
            details="Successful login",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        current_app.db_session.add(log_entry)
        current_app.db_session.commit()
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "username": user.username,
                "email": user.email,
                "mfa_enabled": user.mfa_enabled
            }
        }), 200
    else:
        # Increment failed login attempts
        user.increment_failed_login_attempts()
        current_app.db_session.commit()
        
        # Log failed login
        log_failed_login(user, request, "Invalid password")
        
        return jsonify({"msg": "Invalid username or password"}), 401

def log_failed_login(user, request, details):
    """Log a failed login attempt"""
    log_entry = AuditLog(
        user_id=user.id,
        action="login_failed",
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')
    )
    current_app.db_session.add(log_entry)
    current_app.db_session.commit()

@auth.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=current_user_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    # Generate new access token
    new_token = create_access_token(
        identity=current_user_id, 
        expires_delta=timedelta(minutes=current_app.config['JWT_ACCESS_TOKEN_MINUTES'])
    )
    
    # Log token refresh
    log_entry = AuditLog(
        user_id=user.id,
        action="token_refresh",
        details="Refreshed access token",
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')
    )
    current_app.db_session.add(log_entry)
    current_app.db_session.commit()
    
    return jsonify({"access_token": new_token}), 200

@auth.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    user_id = get_jwt_identity()
    
    # Add token to blocklist
    current_app.jwt_blocklist.add(jti)
    
    # Add token to database blocklist for persistence
    token_exp = get_jwt()['exp']
    expires_at = datetime.fromtimestamp(token_exp)
    
    blacklist_token = TokenBlacklist(
        jti=jti,
        expires_at=expires_at
    )
    current_app.db_session.add(blacklist_token)
    
    # Log logout
    user = current_app.db_session.query(User).filter_by(public_id=user_id).first()
    if user:
        log_entry = AuditLog(
            user_id=user.id,
            action="logout",
            details="User logged out",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        current_app.db_session.add(log_entry)
    
    current_app.db_session.commit()
    
    return jsonify({"msg": "Successfully logged out"}), 200

@auth.route('/mfa/setup', methods=['GET'])
@jwt_required()
def setup_mfa():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    # Generate new MFA secret for user
    mfa_manager = MFAManager()
    
    # Generate QR code
    qr_code = mfa_manager.get_qr_code_image(user.username)
    
    # Store temporary secret (will be confirmed later)
    user.mfa_secret = mfa_manager.secret_key
    current_app.db_session.commit()
    
    return jsonify({
        "secret": mfa_manager.secret_key,
        "qr_code": qr_code
    }), 200

@auth.route('/mfa/verify', methods=['POST'])
@jwt_required()
def verify_mfa():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user or not user.mfa_secret:
        return jsonify({"msg": "MFA not set up for user"}), 400
    
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"msg": "Missing verification code"}), 400
    
    mfa_manager = MFAManager(user.mfa_secret)
    if mfa_manager.verify_code(data['code']):
        user.mfa_enabled = True
        
        # Log MFA setup
        log_entry = AuditLog(
            user_id=user.id,
            action="mfa_setup",
            details="MFA enabled",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        current_app.db_session.add(log_entry)
        current_app.db_session.commit()
        
        # Generate backup codes
        backup_codes = mfa_manager.generate_backup_codes()
        
        return jsonify({
            "msg": "MFA verified and enabled",
            "backup_codes": backup_codes
        }), 200
    else:
        return jsonify({"msg": "Invalid verification code"}), 400

@auth.route('/mfa/disable', methods=['POST'])
@jwt_required()
def disable_mfa():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user or not user.mfa_enabled:
        return jsonify({"msg": "MFA not enabled for user"}), 400
    
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"msg": "Missing verification code"}), 400
    
    mfa_manager = MFAManager(user.mfa_secret)
    if mfa_manager.verify_code(data['code']):
        user.mfa_secret = None
        user.mfa_enabled = False
        
        # Log MFA disable
        log_entry = AuditLog(
            user_id=user.id,
            action="mfa_disable",
            details="MFA disabled",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        current_app.db_session.add(log_entry)
        current_app.db_session.commit()
        
        return jsonify({"msg": "MFA disabled successfully"}), 200
    else:
        return jsonify({"msg": "Invalid verification code"}), 400

@auth.route('/change-password', methods=['POST'])
@jwt_required()
@limiter.limit("3 per minute")
def change_password():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    data = request.get_json()
    if not data or 'current_password' not in data or 'new_password' not in data:
        return jsonify({"msg": "Missing current_password or new_password"}), 400
    
    # Verify current password
    if not user.check_password(data['current_password']):
        # Log failed password change
        log_entry = AuditLog(
            user_id=user.id,
            action="change_password_failed",
            details="Failed password change - incorrect current password",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        current_app.db_session.add(log_entry)
        current_app.db_session.commit()
        
        return jsonify({"msg": "Current password is incorrect"}), 401
    
    # Validate new password
    is_valid, message = PasswordValidator.validate_password(data['new_password'])
    if not is_valid:
        return jsonify({"msg": message}), 400
    
    # Update password
    user.set_password(data['new_password'])
    
    # Log password change
    log_entry = AuditLog(
        user_id=user.id,
        action="change_password",
        details="Password changed successfully",
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')
    )
    current_app.db_session.add(log_entry)
    current_app.db_session.commit()
    
    # Invalidate all existing tokens for this user
    # This is a security measure after password change
    token_jti = get_jwt()['jti']
    blacklist_token = TokenBlacklist(
        jti=token_jti,
        expires_at=datetime.fromtimestamp(get_jwt()['exp'])
    )
    current_app.db_session.add(blacklist_token)
    current_app.db_session.commit()
    
    # Issue new tokens
    access_token = create_access_token(
        identity=user.public_id, 
        expires_delta=timedelta(minutes=current_app.config['JWT_ACCESS_TOKEN_MINUTES'])
    )
    refresh_token = create_refresh_token(
        identity=user.public_id,
        expires_delta=timedelta(days=current_app.config['JWT_REFRESH_TOKEN_DAYS'])
    )
    
    return jsonify({
        "msg": "Password changed successfully",
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200

@auth.route('/user', methods=['GET'])
@jwt_required()
def get_user_info():
    user_public_id = get_jwt_identity()
    user = current_app.db_session.query(User).filter_by(public_id=user_public_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    # Count credentials
    from shared.models import Credential
    credential_count = current_app.db_session.query(Credential).filter_by(user_id=user.id).count()
    
    return jsonify({
        "username": user.username,
        "email": user.email,
        "mfa_enabled": user.mfa_enabled,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "credential_count": credential_count
    }), 200

@auth.route('/generate-password', methods=['GET'])
def generate_password():
    length = request.args.get('length', 16, type=int)
    include_uppercase = request.args.get('uppercase', 'true').lower() == 'true'
    include_lowercase = request.args.get('lowercase', 'true').lower() == 'true'
    include_digits = request.args.get('digits', 'true').lower() == 'true'
    include_symbols = request.args.get('symbols', 'true').lower() == 'true'
    
    # Generate password
    password = PasswordValidator.generate_password(
        length=length,
        include_uppercase=include_uppercase,
        include_lowercase=include_lowercase,
        include_digits=include_digits,
        include_symbols=include_symbols
    )
    
    return jsonify({"password": password}), 200
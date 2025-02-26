import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta

class MFAManager:
    """Manager for multi-factor authentication using TOTP"""
    
    def __init__(self, secret_key=None):
        """Initialize MFA manager with optional secret key"""
        self.secret_key = secret_key or pyotp.random_base32()
    
    def generate_totp(self):
        """Generate TOTP based on secret key"""
        return pyotp.TOTP(self.secret_key)
    
    def verify_code(self, code):
        """Verify TOTP code"""
        totp = self.generate_totp()
        return totp.verify(code)
    
    def get_current_code(self):
        """Get current TOTP code"""
        totp = self.generate_totp()
        return totp.now()
    
    def get_provisioning_uri(self, user_name, issuer_name="Data Privacy Vault"):
        """Get provisioning URI for QR code generation"""
        totp = self.generate_totp()
        return totp.provisioning_uri(name=user_name, issuer_name=issuer_name)
    
    def get_qr_code_image(self, user_name, issuer_name="Data Privacy Vault"):
        """Generate QR code image for TOTP setup"""
        uri = self.get_provisioning_uri(user_name, issuer_name)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = io.BytesIO()
        img.save(buffered)
        return base64.b64encode(buffered.getvalue()).decode()
    
    def generate_backup_codes(self, count=10):
        """Generate backup codes for when TOTP is unavailable"""
        codes = []
        for _ in range(count):
            code = pyotp.random_base32(length=10)[:10].upper()
            codes.append(code)
        return codes
    
    def store_mfa_details(self, user, session):
        """Store MFA details for a user"""
        user.mfa_secret = self.secret_key
        user.mfa_enabled = True
        session.commit()
    
    def disable_mfa(self, user, session):
        """Disable MFA for a user"""
        user.mfa_secret = None
        user.mfa_enabled = False
        session.commit()
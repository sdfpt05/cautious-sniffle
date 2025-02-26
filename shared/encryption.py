from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import json

def generate_key(password: str = None, salt: bytes = None) -> tuple:
    """Generate an encryption key from a password and salt, or generate a random key if no password"""
    if password is None:
        # Generate a random key
        key = Fernet.generate_key()
        return key, None
    
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypt data using the provided key"""
    f = Fernet(key)
    return f.encrypt(data.encode())


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt data using the provided key"""
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()


class EncryptionManager:
    """Class to manage encryption and decryption of data"""
    
    def __init__(self, key):
        self.fernet = Fernet(key)
    
    def encrypt_data(self, data: str) -> bytes:
        """Encrypt data"""
        return self.fernet.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt data"""
        return self.fernet.decrypt(encrypted_data).decode()
    
    def encrypt_json(self, data: dict) -> bytes:
        """Encrypt a dictionary as JSON"""
        json_data = json.dumps(data)
        return self.encrypt_data(json_data)
    
    def decrypt_json(self, encrypted_data: bytes) -> dict:
        """Decrypt JSON data to a dictionary"""
        json_data = self.decrypt_data(encrypted_data)
        return json.loads(json_data)
    
    @staticmethod
    def generate_key():
        """Generate a random encryption key"""
        return Fernet.generate_key()
    
    @staticmethod
    def rotate_key(old_key: bytes, data_to_reencrypt: list):
        """Rotate an encryption key and re-encrypt data with the new key"""
        new_key = Fernet.generate_key()
        old_fernet = Fernet(old_key)
        new_fernet = Fernet(new_key)
        
        reencrypted_data = []
        for item in data_to_reencrypt:
            decrypted = old_fernet.decrypt(item)
            reencrypted = new_fernet.encrypt(decrypted)
            reencrypted_data.append(reencrypted)
            
        return new_key, reencrypted_data
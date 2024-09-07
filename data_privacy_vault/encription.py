from cryptography.fernet import Fernet
from passlib.context import CryptContext
import os

password_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Generate a key for Fernet encryption
def generate_key():
    return Fernet.generate_key()

# Initialize Fernet with the key
fernet = Fernet(os.environ.get('ENCRYPTION_KEY') or generate_key())

def hash_password(password: str) -> str:
    return password_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)

def encrypt_data(data: str) -> bytes:
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes) -> str:
    return fernet.decrypt(encrypted_data).decode()


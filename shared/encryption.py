from passlib.context import CryptContext
from cryptography.fernet import Fernet
import os
import base64

password_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> tuple:
    salt = os.urandom(16)
    hashed = password_context.hash(password + base64.b64encode(salt).decode())
    return hashed, base64.b64encode(salt).decode()

def verify_password(plain_password: str, hashed_password: str, salt: str) -> bool:
    return password_context.verify(plain_password + salt, hashed_password)

def generate_key() -> bytes:
    return Fernet.generate_key()

def encrypt_data(key: bytes, data: str) -> bytes:
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(key: bytes, encrypted_data: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()
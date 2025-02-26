from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean, Text, LargeBinary
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.sql import func
from sqlalchemy.ext.hybrid import hybrid_property
from argon2 import PasswordHasher
import uuid
import os
from datetime import datetime

Base = declarative_base()
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    public_id = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    encryption_key = Column(LargeBinary(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    
    # MFA fields
    mfa_secret = Column(String(32), nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    
    credentials = relationship("Credential", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = ph.hash(password.strip())

    def check_password(self, password):
        try:
            return ph.verify(self.password_hash, password.strip())
        except:
            return False

    def reset_failed_login_attempts(self):
        self.failed_login_attempts = 0
        self.last_login = datetime.now()

    def increment_failed_login_attempts(self):
        self.failed_login_attempts += 1

    @hybrid_property
    def is_authenticated(self):
        return True

    @hybrid_property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.public_id


class Credential(Base):
    __tablename__ = 'credentials'

    id = Column(Integer, primary_key=True)
    public_id = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    encrypted_data = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    category = Column(String(50), nullable=True)
    notes = Column(Text, nullable=True)
    url = Column(String(255), nullable=True)
    icon = Column(String(255), nullable=True)
    favorite = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="credentials")


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(100), nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    details = Column(Text, nullable=True)
    
    user = relationship("User")


class TokenBlacklist(Base):
    __tablename__ = 'token_blacklist'
    
    id = Column(Integer, primary_key=True)
    jti = Column(String(36), nullable=False, index=True)
    blacklisted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)


def init_db(db_url=None):
    if db_url is None:
        db_url = os.environ.get('DATABASE_URL', 'sqlite:///data_vault.db')
    
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()
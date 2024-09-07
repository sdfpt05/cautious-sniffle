from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, LargeBinary
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from cryptography.fernet import Fernet
import os

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    encryption_key = Column(LargeBinary, nullable=False)
    credentials = relationship("Credential", back_populates="user", cascade="all, delete-orphan")

class Credential(Base):
    __tablename__ = 'creds'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    _encrypted_data = Column(LargeBinary, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="credentials")

    @hybrid_property
    def data(self):
        key = Fernet(self.user.encryption_key)
        return key.decrypt(self._encrypted_data).decode()

    @data.setter
    def data(self, value):
        key = Fernet(self.user.encryption_key)
        self._encrypted_data = key.encrypt(value.encode())

def init_db():
    db_url = os.getenv('DATABASE_URL', 'sqlite:///data_vault.db')
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    return engine
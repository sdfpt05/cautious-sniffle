from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)

class Credential(Base):
    __tablename__ = 'creds'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    data = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))
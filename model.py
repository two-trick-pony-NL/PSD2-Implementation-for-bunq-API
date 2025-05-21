from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class BunqUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    access_token = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

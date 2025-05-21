from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from model import Base, BunqUser

DATABASE_URL = "sqlite:///./bunq_users.db"

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def save_token(access_token: str):
    session = SessionLocal()
    user = BunqUser(access_token=access_token)
    session.add(user)
    session.commit()
    session.refresh(user)
    session.close()
    return user

def get_user(user_id: int) -> BunqUser | None:
    session = SessionLocal()
    user = session.query(BunqUser).get(user_id)
    session.close()
    return user

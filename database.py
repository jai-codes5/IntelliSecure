from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# MySQL path badulu asalu instant lag-free SQLite local DB architecture context direct configure chestunnam
DATABASE_URL = "sqlite:///./intellisecure_db.db"

# SQLite internal thread connection safety context support settings
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
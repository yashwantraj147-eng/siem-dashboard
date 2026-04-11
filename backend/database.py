from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import os

DB_PATH = os.getenv("DB_PATH", "./siem.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"
# For PostgreSQL use: "postgresql://user:password@postgresserver/db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class LogEventDB(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    host = Column(String, index=True)
    severity = Column(String, index=True)
    category = Column(String, index=True)
    message = Column(Text)
    raw = Column(Text)

class AlertDB(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    rule_name = Column(String, index=True)
    severity = Column(String, index=True)
    description = Column(Text)
    events_correlated = Column(Integer)
    acknowledged = Column(Integer, default=0) # 0 for false, 1 for true

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

import os
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Index, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("SQLALCHEMY_DATABASE_URL")
if not DATABASE_URL:
    db_path = os.getenv("DB_PATH", "./siem.db")
    DATABASE_URL = f"sqlite:///{db_path}"

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def utc_now():
    return datetime.now(timezone.utc)


class LogEventDB(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now, index=True)
    host = Column(String, index=True)
    severity = Column(String, index=True)
    category = Column(String, index=True)
    message = Column(Text)
    raw = Column(Text)

    __table_args__ = (
        Index("ix_log_events_host_timestamp", "host", "timestamp"),
        Index("ix_log_events_category_timestamp", "category", "timestamp"),
    )


class AlertDB(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now, index=True)
    rule_name = Column(String, index=True)
    severity = Column(String, index=True)
    description = Column(Text)
    events_correlated = Column(Integer)
    acknowledged = Column(Integer, default=0)  # 0 for false, 1 for true
    mitre_technique = Column(String, nullable=True, index=True)
    mitre_tactic = Column(String, nullable=True, index=True)
    status = Column(String, default="new", index=True)  # new, in_progress, resolved, false_positive
    assigned_to = Column(String, nullable=True)
    resolution_notes = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_alerts_rule_timestamp", "rule_name", "timestamp"),
    )


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

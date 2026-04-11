import re
import json
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from .database import LogEventDB
from .schemas import LogEventCreate
from .rules_engine import RulesEngine
import logging

logger = logging.getLogger(__name__)

# Initialize Rules Engine
rules_engine = RulesEngine()

def parse_syslog(line: str) -> Optional[LogEventCreate]:
    # e.g., Oct 11 12:00:00 hostname process: message
    pattern = r"([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+)\s+(\S+)\s+(.*?):\s+(.*)"
    match = re.search(pattern, line)
    if match:
        timestamp_str, host, process, message = match.groups()
        # Guess severity
        severity = "info"
        if "error" in message.lower() or "fatal" in message.lower():
            severity = "high"
        elif "warning" in message.lower():
            severity = "medium"
            
        return LogEventCreate(
            host=host,
            severity=severity,
            category="system",
            message=f"{process}: {message}",
            raw=line
        )
    # Fallback
    return LogEventCreate(
        host="unknown", severity="info", category="system", message=line, raw=line
    )

def parse_auth_log(line: str) -> Optional[LogEventCreate]:
    # Looks like syslog but for auth
    event = parse_syslog(line)
    if event:
        event.category = "auth"
        if "failed" in event.message.lower() or "invalid" in event.message.lower() or "error" in event.message.lower():
            event.severity = "high"
    return event

def parse_nginx_access(line: str) -> Optional[LogEventCreate]:
    # e.g., 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    pattern = r"(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+\"([^\"]+)\"\s+(\d+)\s+\d+"
    match = re.search(pattern, line)
    if match:
        host, timestamp_str, request, status = match.groups()
        
        severity = "info"
        if status.startswith("4"):
            severity = "medium"
        elif status.startswith("5"):
            severity = "high"

        return LogEventCreate(
            host=host,
            severity=severity,
            category="web",
            message=f"{request} - Status {status}",
            raw=line
        )
    return LogEventCreate(
        host="unknown", severity="info", category="web", message=line, raw=line
    )

def parse_windows_event_json(json_str: str) -> Optional[LogEventCreate]:
    try:
        data = json.loads(json_str)
        # Assuming simple flat JSON with some standard fields
        host = data.get("Computer", "unknown")
        message = data.get("Message", str(data))
        event_id = data.get("EventID", 0)
        
        severity_val = data.get("Level", 4) # 1=Critical, 2=Error, 3=Warning, 4=Info
        severity = "info"
        if severity_val in [1, 2]:
            severity = "high"
        elif severity_val == 3:
            severity = "medium"

        return LogEventCreate(
            host=host,
            severity=severity,
            category="windows",
            message=f"EventID {event_id}: {message}",
            raw=json_str
        )
    except Exception:
        return LogEventCreate(
            host="unknown", severity="info", category="windows", message=json_str, raw=json_str
        )


def process_log_entry(event_data: LogEventCreate, db: Session) -> LogEventDB:
    # Save to DB
    db_event = LogEventDB(
        timestamp=event_data.timestamp or datetime.utcnow(),
        host=event_data.host,
        severity=event_data.severity,
        category=event_data.category,
        message=event_data.message,
        raw=event_data.raw or ""
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # Evaluate rules
    try:
        rules_engine.evaluate_event(db_event, db)
    except Exception as e:
        logger.error(f"Error evaluating rules for event {db_event.id}: {e}")

    return db_event

def parse_and_ingest_file(file_path: str, db: Session, log_type: str):
    """
    Reads a local file line by line and ingests it.
    """
    count = 0
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                event_data = None
                if log_type == "syslog":
                    event_data = parse_syslog(line)
                elif log_type == "auth":
                    event_data = parse_auth_log(line)
                elif log_type == "nginx":
                    event_data = parse_nginx_access(line)
                elif log_type == "windows_json":
                    event_data = parse_windows_event_json(line)
                else:
                    event_data = LogEventCreate(
                        host="unknown", severity="info", category="unknown", message=line, raw=line
                    )
                
                if event_data:
                    process_log_entry(event_data, db)
                    count += 1
        return count
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return 0

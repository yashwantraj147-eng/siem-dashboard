from datetime import datetime, timezone
import json
import logging
import re
from typing import List, Optional
from sqlalchemy.orm import Session
from .database import LogEventDB
from .rules_engine import RulesEngine
from .schemas import LogEventCreate

logger = logging.getLogger(__name__)

# Initialize Rules Engine singleton
rules_engine = RulesEngine()


def _parse_syslog_timestamp(ts_str: str) -> Optional[datetime]:
    try:
        clean_ts = " ".join(ts_str.split())
        current_year = datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{current_year} {clean_ts}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _parse_nginx_timestamp(ts_str: str) -> Optional[datetime]:
    try:
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    except Exception:
        try:
            dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _parse_iso_timestamp(ts_str: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def parse_syslog(line: str) -> Optional[LogEventCreate]:
    pattern = r"([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*?):\s+(.*)"
    match = re.search(pattern, line)
    if match:
        timestamp_str, host, process, message = match.groups()
        parsed_ts = _parse_syslog_timestamp(timestamp_str)
        severity = "info"
        lower_msg = message.lower()
        if "error" in lower_msg or "fatal" in lower_msg:
            severity = "high"
        elif "warning" in lower_msg:
            severity = "medium"

        return LogEventCreate(
            timestamp=parsed_ts,
            host=host,
            severity=severity,
            category="system",
            message=f"{process}: {message}",
            raw=line,
        )

    return LogEventCreate(
        host="unknown",
        severity="info",
        category="system",
        message=line,
        raw=line,
    )


def parse_auth_log(line: str) -> Optional[LogEventCreate]:
    event = parse_syslog(line)
    if event:
        event.category = "auth"
        lower_msg = event.message.lower()
        if any(term in lower_msg for term in ["failed", "invalid", "error", "unauthorized"]):
            event.severity = "high"
    return event


def parse_nginx_access(line: str) -> Optional[LogEventCreate]:
    # e.g., 127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /test HTTP/1.1" 200 2326
    pattern = r"(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+\"([^\"]+)\"\s+(\d+)\s+\d+"
    match = re.search(pattern, line)
    if match:
        host, timestamp_str, request, status = match.groups()
        parsed_ts = _parse_nginx_timestamp(timestamp_str)
        severity = "info"
        if status.startswith("4"):
            severity = "medium"
        elif status.startswith("5"):
            severity = "high"

        return LogEventCreate(
            timestamp=parsed_ts,
            host=host,
            severity=severity,
            category="web",
            message=f"{request} - Status {status}",
            raw=line,
        )

    return LogEventCreate(
        host="unknown",
        severity="info",
        category="web",
        message=line,
        raw=line,
    )


def parse_windows_event_json(json_str: str) -> Optional[LogEventCreate]:
    try:
        data = json.loads(json_str)
        host = data.get("Computer") or data.get("Host") or data.get("host") or "unknown"
        message = data.get("Message") or data.get("message") or str(data)
        event_id = data.get("EventID") or data.get("event_id") or 0

        # Try parsing timestamp from common keys
        parsed_ts = None
        for key in ["TimeCreated", "timestamp", "Timestamp", "Date", "TimeGenerated"]:
            if key in data and isinstance(data[key], str):
                parsed_ts = _parse_iso_timestamp(data[key])
                if parsed_ts:
                    break

        severity_val = data.get("Level", 4)  # 1=Critical, 2=Error, 3=Warning, 4=Info
        severity = "info"
        if severity_val in [1, 2]:
            severity = "high"
        elif severity_val == 3:
            severity = "medium"

        return LogEventCreate(
            timestamp=parsed_ts,
            host=host,
            severity=severity,
            category="windows",
            message=f"EventID {event_id}: {message}",
            raw=json_str,
        )
    except Exception:
        return LogEventCreate(
            host="unknown",
            severity="info",
            category="windows",
            message=json_str,
            raw=json_str,
        )


def parse_log_line(line: str, log_type: str) -> Optional[LogEventCreate]:
    if log_type == "syslog":
        return parse_syslog(line)
    elif log_type == "auth":
        return parse_auth_log(line)
    elif log_type == "nginx":
        return parse_nginx_access(line)
    elif log_type == "windows_json":
        return parse_windows_event_json(line)
    else:
        return LogEventCreate(
            host="unknown",
            severity="info",
            category="unknown",
            message=line,
            raw=line,
        )


def process_log_entries(events_data: List[LogEventCreate], db: Session) -> List[LogEventDB]:
    """
    Ingest a batch of events within a single database transaction,
    then trigger rule evaluation.
    """
    if not events_data:
        return []

    now = datetime.now(timezone.utc)
    db_events = [
        LogEventDB(
            timestamp=item.timestamp or now,
            host=item.host,
            severity=item.severity,
            category=item.category,
            message=item.message,
            raw=item.raw or "",
        )
        for item in events_data
    ]

    db.add_all(db_events)
    db.commit()

    for event in db_events:
        db.refresh(event)

    for event in db_events:
        try:
            rules_engine.evaluate_event(event, db)
        except Exception as e:
            logger.error(f"Error evaluating rules for event {event.id}: {e}")

    return db_events


def process_log_entry(event_data: LogEventCreate, db: Session) -> LogEventDB:
    results = process_log_entries([event_data], db)
    return results[0]


def parse_and_ingest_file(file_path: str, db: Session, log_type: str, batch_size: int = 500) -> int:
    """
    Reads a local file line by line and ingests records in high-performance batches.
    """
    count = 0
    batch: List[LogEventCreate] = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                event = parse_log_line(line, log_type)
                if event:
                    batch.append(event)
                    if len(batch) >= batch_size:
                        process_log_entries(batch, db)
                        count += len(batch)
                        batch = []

            if batch:
                process_log_entries(batch, db)
                count += len(batch)

        return count
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return count

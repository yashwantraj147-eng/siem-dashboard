import asyncio
import csv
import io
import json
import os
import shutil
import tempfile
from typing import List, Optional, Set
from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Form, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from . import database, schemas, ingestion
from .database import LogEventDB, AlertDB

# Initialize Database
database.init_db()

app = FastAPI(
    title="SIEM Dashboard API",
    version="2.0.0",
    description="High-performance Security Information and Event Management platform API"
)

# CORS Configuration
cors_origins_env = os.getenv("CORS_ORIGINS", "*")
allowed_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
allow_credentials = False if "*" in allowed_origins else True

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50")) * 1024 * 1024
API_KEY = os.getenv("SIEM_API_KEY", "").strip()


# REAL-TIME SSE BROADCASTER
class SSEBroadcaster:
    def __init__(self):
        self.listeners: Set[asyncio.Queue] = set()

    async def subscribe(self) -> asyncio.Queue:
        queue = asyncio.Queue(maxsize=100)
        self.listeners.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        self.listeners.discard(queue)

    def broadcast_sync(self, event_type: str, data: dict):
        message = json.dumps({"type": event_type, "payload": data})
        for queue in list(self.listeners):
            try:
                queue.put_nowait(message)
            except (asyncio.QueueFull, Exception):
                pass


broadcaster = SSEBroadcaster()


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Optional API Key authentication for forwarders and data collection agents."""
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing X-API-Key header")
    return True


# SYSTEM HEALTH & REAL-TIME STREAMING
@app.get("/api/health")
def health_check(db: Session = Depends(database.get_db)):
    """Health check endpoint for container orchestrators and load balancers."""
    try:
        db.execute(func.now() if database.engine.dialect.name == "postgresql" else func.datetime('now'))
        return {
            "status": "healthy",
            "database": "connected",
            "rules_loaded": len(ingestion.rules_engine.rules),
            "sse_subscribers": len(broadcaster.listeners)
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database connectivity failed: {e}")


@app.get("/api/stream")
async def live_event_stream(request: Request):
    """Server-Sent Events (SSE) endpoint pushing sub-second alerts and event signals to SOC dashboards."""
    queue = await broadcaster.subscribe()

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            broadcaster.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


# INGESTION ENDPOINTS
@app.post("/api/ingest", response_model=schemas.LogEventResponse)
def ingest_event(
    event: schemas.LogEventCreate, 
    db: Session = Depends(database.get_db),
    _auth=Depends(verify_api_key)
):
    """Ingest a single structured log event."""
    result = ingestion.process_log_entry(event, db)
    broadcaster.broadcast_sync("event_ingested", {"id": result.id, "host": result.host, "severity": result.severity})
    return result


@app.post("/api/ingest/batch", response_model=List[schemas.LogEventResponse])
def ingest_batch(
    events: List[schemas.LogEventCreate], 
    db: Session = Depends(database.get_db),
    _auth=Depends(verify_api_key)
):
    """Ingest multiple structured log events in a single batch transaction."""
    results = ingestion.process_log_entries(events, db)
    broadcaster.broadcast_sync("batch_ingested", {"count": len(results)})
    return results


@app.post("/api/ingest/file")
async def ingest_file(
    log_type: str = Form(...), 
    file: UploadFile = File(...), 
    db: Session = Depends(database.get_db),
    _auth=Depends(verify_api_key)
):
    """Upload a file to ingest logs in high-performance batches."""
    fd, temp_path = tempfile.mkstemp()
    bytes_read = 0
    try:
        with os.fdopen(fd, "wb") as f:
            while chunk := await file.read(1024 * 1024):  # 1MB buffer
                bytes_read += len(chunk)
                if bytes_read > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413, 
                        detail=f"File exceeds maximum allowed size of {MAX_UPLOAD_SIZE // (1024 * 1024)}MB"
                    )
                f.write(chunk)

        count = ingestion.parse_and_ingest_file(temp_path, db, log_type)
        broadcaster.broadcast_sync("file_ingested", {"filename": file.filename, "count": count})
        return {
            "message": f"Successfully ingested {count} events from {file.filename}",
            "count": count
        }
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# QUERY & SEARCH ENDPOINTS
@app.get("/api/events", response_model=List[schemas.LogEventResponse])
def get_events(
    skip: int = Query(0, ge=0), 
    limit: int = Query(50, ge=1, le=500), 
    severity: Optional[str] = None,
    category: Optional[str] = None,
    keyword: Optional[str] = None,
    host: Optional[str] = None,
    db: Session = Depends(database.get_db)
):
    """Fetch structured log events with optional multi-field filters."""
    query = db.query(LogEventDB)
    if severity:
        query = query.filter(LogEventDB.severity == severity.lower())
    if category:
        query = query.filter(LogEventDB.category == category.lower())
    if host:
        query = query.filter(LogEventDB.host == host)
    if keyword:
        kw = f"%{keyword}%"
        query = query.filter(LogEventDB.message.ilike(kw) | LogEventDB.raw.ilike(kw))
    
    return query.order_by(desc(LogEventDB.timestamp)).offset(skip).limit(limit).all()


@app.get("/api/alerts", response_model=List[schemas.AlertResponse])
def get_alerts(
    skip: int = Query(0, ge=0), 
    limit: int = Query(50, ge=1, le=200), 
    db: Session = Depends(database.get_db)
):
    """Fetch triggered detection alerts."""
    return db.query(AlertDB).order_by(desc(AlertDB.timestamp)).offset(skip).limit(limit).all()


@app.put("/api/alerts/{alert_id}/acknowledge", response_model=schemas.AlertResponse)
def acknowledge_alert(alert_id: int, db: Session = Depends(database.get_db)):
    """Acknowledge or dismiss an alert."""
    alert = db.query(AlertDB).filter(AlertDB.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = 1
    alert.status = "in_progress"
    db.commit()
    db.refresh(alert)
    return alert


@app.put("/api/alerts/{alert_id}/triage", response_model=schemas.AlertResponse)
def triage_alert(
    alert_id: int, 
    triage_data: schemas.AlertTriage, 
    db: Session = Depends(database.get_db)
):
    """Update alert triage status, assignment, and resolution notes."""
    alert = db.query(AlertDB).filter(AlertDB.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = triage_data.status
    if triage_data.status in ["resolved", "false_positive", "in_progress"]:
        alert.acknowledged = 1
    elif triage_data.status == "new":
        alert.acknowledged = 0

    if triage_data.assigned_to is not None:
        alert.assigned_to = triage_data.assigned_to
    if triage_data.resolution_notes is not None:
        alert.resolution_notes = triage_data.resolution_notes

    db.commit()
    db.refresh(alert)
    return alert


# FORENSIC EXPORT ENDPOINTS (CSV)
@app.get("/api/events/export")
def export_events_csv(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    host: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = Query(5000, ge=1, le=10000),
    db: Session = Depends(database.get_db)
):
    """Export queried log events in CSV format for compliance reporting."""
    query = db.query(LogEventDB)
    if severity:
        query = query.filter(LogEventDB.severity == severity.lower())
    if category:
        query = query.filter(LogEventDB.category == category.lower())
    if host:
        query = query.filter(LogEventDB.host == host)
    if keyword:
        kw = f"%{keyword}%"
        query = query.filter(LogEventDB.message.ilike(kw) | LogEventDB.raw.ilike(kw))

    events = query.order_by(desc(LogEventDB.timestamp)).limit(limit).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Event_ID", "Timestamp_UTC", "Host", "Severity", "Category", "Message"])
    for e in events:
        writer.writerow([e.id, e.timestamp.isoformat(), e.host, e.severity, e.category, e.message])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=siem_events.csv"}
    )


@app.get("/api/alerts/export")
def export_alerts_csv(
    limit: int = Query(2000, ge=1, le=5000),
    db: Session = Depends(database.get_db)
):
    """Export security alerts in CSV format for incident response audits."""
    alerts = db.query(AlertDB).order_by(desc(AlertDB.timestamp)).limit(limit).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Alert_ID", "Timestamp_UTC", "Rule_Name", "Severity", 
        "MITRE_Technique", "MITRE_Tactic", "Status", "Correlated_Events", 
        "Acknowledged", "Assigned_To", "Description"
    ])
    for a in alerts:
        writer.writerow([
            a.id, a.timestamp.isoformat(), a.rule_name, a.severity,
            a.mitre_technique or "", a.mitre_tactic or "", a.status or "new",
            a.events_correlated, a.acknowledged, a.assigned_to or "", a.description
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=siem_alerts.csv"}
    )


# ANALYTICS & METRICS
@app.get("/api/stats/top-ips")
def get_top_ips(limit: int = Query(10, ge=1, le=50), db: Session = Depends(database.get_db)):
    """Get top source hosts by event count."""
    results = (
        db.query(LogEventDB.host, func.count(LogEventDB.id).label('count'))
        .group_by(LogEventDB.host)
        .order_by(desc('count'))
        .limit(limit)
        .all()
    )
    return [{"host": r[0] if r[0] else "unknown", "count": r[1]} for r in results]


@app.get("/api/stats/categories")
def get_categories(db: Session = Depends(database.get_db)):
    """Get event count breakdown by category."""
    results = (
        db.query(LogEventDB.category, func.count(LogEventDB.id).label('count'))
        .group_by(LogEventDB.category)
        .all()
    )
    return [{"category": r[0] if r[0] else "unknown", "count": r[1]} for r in results]


@app.get("/api/stats/timeline")
def get_timeline(db: Session = Depends(database.get_db)):
    """Get events per hour for timeline analytics (cross-database portable)."""
    if database.engine.dialect.name == "postgresql":
        time_col = func.to_char(LogEventDB.timestamp, 'YYYY-MM-DD HH24:00:00').label('hour')
    else:
        time_col = func.strftime('%Y-%m-%d %H:00:00', LogEventDB.timestamp).label('hour')

    results = (
        db.query(time_col, func.count(LogEventDB.id).label('count'))
        .group_by('hour')
        .order_by('hour')
        .limit(24)
        .all()
    )
    return [{"time": r[0] or "N/A", "count": r[1]} for r in results]


@app.get("/api/stats/mitre")
def get_mitre_stats(db: Session = Depends(database.get_db)):
    """Get alert counts grouped by MITRE ATT&CK tactic and technique."""
    results = (
        db.query(
            AlertDB.mitre_tactic,
            AlertDB.mitre_technique,
            func.count(AlertDB.id).label('count')
        )
        .filter(AlertDB.mitre_tactic.isnot(None))
        .group_by(AlertDB.mitre_tactic, AlertDB.mitre_technique)
        .order_by(desc('count'))
        .all()
    )
    return [{"tactic": r[0] or "Unknown", "technique": r[1] or "Unknown", "count": r[2]} for r in results]


# STATIC ASSET & SPA SERVING
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API route not found")
    
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse(status_code=404, content={"message": "Frontend index.html not found"})

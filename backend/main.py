from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List, Optional
import os
import shutil
import tempfile

from . import database, schemas, ingestion
from .database import LogEventDB, AlertDB

# Initialize Database
database.init_db()

app = FastAPI(title="SIEM Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API ENDPOINTS

@app.post("/api/ingest", response_model=schemas.LogEventResponse)
def ingest_event(event: schemas.LogEventCreate, db: Session = Depends(database.get_db)):
    """Ingest a single structured log event."""
    return ingestion.process_log_entry(event, db)

@app.post("/api/ingest/file")
async def ingest_file(
    log_type: str = Form(...), 
    file: UploadFile = File(...), 
    db: Session = Depends(database.get_db)
):
    """Upload a file to ingest logs from it."""
    # Save file temporally
    fd, temp_path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # Ingest it synchronous for simplicity and immediate feedback
    count = ingestion.parse_and_ingest_file(temp_path, db, log_type)
    
    # Cleanup temp file
    os.remove(temp_path)
    
    return {"message": f"Successfully ingested {count} events from {file.filename}"}

@app.get("/api/events", response_model=List[schemas.LogEventResponse])
def get_events(
    skip: int = 0, 
    limit: int = 50, 
    severity: Optional[str] = None,
    category: Optional[str] = None,
    keyword: Optional[str] = None,
    host: Optional[str] = None,
    db: Session = Depends(database.get_db)
):
    """Fetch structured log events with optional filters."""
    query = db.query(LogEventDB)
    if severity:
        query = query.filter(LogEventDB.severity == severity)
    if category:
        query = query.filter(LogEventDB.category == category)
    if host:
        query = query.filter(LogEventDB.host == host)
    if keyword:
        query = query.filter(LogEventDB.message.contains(keyword) | LogEventDB.raw.contains(keyword))
    
    return query.order_by(desc(LogEventDB.timestamp)).offset(skip).limit(limit).all()

@app.get("/api/alerts", response_model=List[schemas.AlertResponse])
def get_alerts(skip: int = 0, limit: int = 50, db: Session = Depends(database.get_db)):
    """Fetch active alerts."""
    return db.query(AlertDB).order_by(desc(AlertDB.timestamp)).offset(skip).limit(limit).all()

@app.put("/api/alerts/{alert_id}/acknowledge", response_model=schemas.AlertResponse)
def acknowledge_alert(alert_id: int, db: Session = Depends(database.get_db)):
    """Acknowledge/dismiss an alert."""
    alert = db.query(AlertDB).filter(AlertDB.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = 1
    db.commit()
    db.refresh(alert)
    return alert

# Analytics Endpoints
@app.get("/api/stats/top-ips")
def get_top_ips(limit: int = 10, db: Session = Depends(database.get_db)):
    """Get top 10 source IPs for bar chart."""
    results = db.query(LogEventDB.host, func.count(LogEventDB.id).label('count')).group_by(LogEventDB.host).order_by(desc('count')).limit(limit).all()
    return [{"host": r[0] if r[0] else "unknown", "count": r[1]} for r in results]

@app.get("/api/stats/categories")
def get_categories(db: Session = Depends(database.get_db)):
    """Get event categories breakdown for pie chart."""
    results = db.query(LogEventDB.category, func.count(LogEventDB.id).label('count')).group_by(LogEventDB.category).all()
    return [{"category": r[0] if r[0] else "unknown", "count": r[1]} for r in results]

@app.get("/api/stats/timeline")
def get_timeline(db: Session = Depends(database.get_db)):
    """Get events per hour for the last 24h line chart."""
    # Simple timeline: group by hour using sqlite strftime
    results = db.query(
        func.strftime('%Y-%m-%d %H:00:00', LogEventDB.timestamp).label('hour'),
        func.count(LogEventDB.id).label('count')
    ).group_by('hour').order_by('hour').limit(24).all()
    
    return [{"time": r[0], "count": r[1]} for r in results]

# Serve Frontend - Assuming frontend is at ../frontend relative to backend
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not Found")
    
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse(status_code=404, content={"message": "Frontend not found. Make sure index.html exists in frontend/"})

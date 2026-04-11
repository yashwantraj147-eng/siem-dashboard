from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class LogEventCreate(BaseModel):
    timestamp: Optional[datetime] = None
    host: str
    severity: str
    category: str
    message: str
    raw: Optional[str] = None

class LogEventResponse(BaseModel):
    id: int
    timestamp: datetime
    host: str
    severity: str
    category: str
    message: str
    raw: str

    class Config:
        from_attributes = True

class AlertResponse(BaseModel):
    id: int
    timestamp: datetime
    rule_name: str
    severity: str
    description: str
    events_correlated: int
    acknowledged: int

    class Config:
        from_attributes = True

class AlertAcknowledge(BaseModel):
    acknowledged: int

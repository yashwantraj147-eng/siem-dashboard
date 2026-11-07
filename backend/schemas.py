from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class LogEventCreate(BaseModel):
    timestamp: Optional[datetime] = None
    host: str = Field(default="unknown")
    severity: str = Field(default="info")
    category: str = Field(default="system")
    message: str
    raw: Optional[str] = None


class LogEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    host: str
    severity: str
    category: str
    message: str
    raw: str


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    rule_name: str
    severity: str
    description: str
    events_correlated: int
    acknowledged: int
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    status: str = "new"
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


class AlertAcknowledge(BaseModel):
    acknowledged: int = 1


class AlertTriage(BaseModel):
    status: str = Field(..., description="Triage status: new, in_progress, resolved, or false_positive")
    assigned_to: Optional[str] = Field(None, description="Analyst name or ID")
    resolution_notes: Optional[str] = Field(None, description="Investigation findings and notes")

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LogEventCreate(BaseModel):
    timestamp: datetime | None = None
    host: str = Field(default="unknown")
    severity: str = Field(default="info")
    category: str = Field(default="system")
    message: str
    raw: str | None = None


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
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    status: str = "new"
    assigned_to: str | None = None
    resolution_notes: str | None = None


class AlertAcknowledge(BaseModel):
    acknowledged: int = 1


class AlertTriage(BaseModel):
    status: str = Field(..., description="Triage status: new, in_progress, resolved, or false_positive")
    assigned_to: str | None = Field(None, description="Analyst name or ID")
    resolution_notes: str | None = Field(None, description="Investigation findings and notes")

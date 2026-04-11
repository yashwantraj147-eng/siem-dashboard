import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_read_main():
    response = client.get("/")
    # FastApi will return 200 FileResponse if index.html is present, otherwise 404
    assert response.status_code in [200, 404]

def test_ingest_event():
    event_data = {
        "host": "test-host",
        "severity": "info",
        "category": "system",
        "message": "Test event message",
        "raw": "Test event message raw"
    }
    response = client.post("/api/ingest", json=event_data)
    assert response.status_code == 200
    assert response.json()["host"] == "test-host"

def test_get_events():
    response = client.get("/api/events")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_alerts():
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

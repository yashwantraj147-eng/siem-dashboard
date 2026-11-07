<div align="center">
  <img src="https://img.shields.io/badge/Status-Production--Ready-success.svg" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/FastAPI-0.104%2B-009688.svg?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/Tailwind_CSS-38B2AC?logo=tailwind-css&logoColor=white" alt="Tailwind">
  
  <h1>🛡️ SIEM Dashboard Engine</h1>
  <p><i>An enterprise-grade, high-throughput Security Information and Event Management (SIEM) Platform.</i></p>
</div>

---

## 📖 Overview

The **SIEM Dashboard** is a high-performance, resilient full-stack application engineered to ingest, normalize, correlate, and analyze network and security telemetry in real time.

It translates heterogeneous log formats into a unified event schema, evaluates stateful correlation rules over sliding time windows, triggers non-blocking alert webhooks, and visualizes security operations telemetry in an interactive, sanitized dashboard.

---

## ✨ Features & Architecture Highlights

- **⚡ High-Throughput Batch Ingestion**: Ingests structured logs individually or in high-performance batches (500 records/transaction), preventing disk I/O lockups and timeouts.
- **🔍 Log Normalization with Timestamp Preservation**: Accurately parses RFC syslog, SSH `auth.log`, Nginx/Apache access logs, and Windows Event JSONL while preserving true log event timestamps.
- **⚔️ Sliding-Window Correlation Engine**: Evaluates YAML-defined detection rules against specific criteria (category, matching field, value) per host without false-positive cross-contamination.
- **🚨 Non-Blocking Webhook Alerting**: Dispatches outbound alerts asynchronously via background threads to Slack, Discord, or SOAR webhooks without slowing down ingestion.
- **🛡️ Enterprise Security**:
  - Built-in DOM escaping and sanitization against Stored XSS attacks.
  - Multi-part file upload streaming with configurable file size limits (50MB default).
  - Optional `X-API-Key` authentication for forwarders and data collection agents.
  - Cross-database compatible (SQLite or PostgreSQL / TimescaleDB).
- **🐳 Containerized & Cloud Native**: Ships with `Dockerfile`, `docker-compose.yml`, and `render.yaml`.
- **🧪 Automated CI/CD Testing**: Isolated in-memory SQLite test suite running on GitHub Actions.

---

## 🛠️ Technology Stack

| Component | Technology | Description |
|-----------|------------|-------------|
| **Backend API** | FastAPI + Uvicorn | High-performance async Python backend with health checks & batch APIs. |
| **Database** | SQLite / PostgreSQL + SQLAlchemy | Persistent ORM storage with composite indexes for sliding-window queries. |
| **Alerting** | HTTPX / Webhooks | Non-blocking background alert dispatcher for ChatOps & SOAR. |
| **Frontend** | Vanilla JS + HTML5 + Tailwind | Real-time dark-themed SOC single-page application with DOM XSS defenses. |
| **Analytics** | Chart.js | Visualizes event volume timelines, top source hosts, and category breakdowns. |

---

## 🚀 Quick Start Setup

### Option A: Local Python Environment

```bash
# 1. Clone the repository 
git clone https://github.com/yashwantraj147-eng/siem-dashboard.git
cd siem-dashboard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the FastAPI backend
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Navigate to `http://localhost:8000/` in your browser.

### Option B: Docker Compose

```bash
# Start the full stack container
docker compose up -d --build

# View container logs
docker compose logs -f
```

---

## ⚙️ Environment Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `./siem.db` | Local SQLite database file path. |
| `DATABASE_URL` | *(None)* | Optional PostgreSQL connection string (e.g. `postgresql://user:pass@host:5432/siem`). |
| `WEBHOOK_URL` | `""` | Outbound Slack/Discord webhook URL for real-time alert notifications. |
| `SIEM_API_KEY` | `""` | Secret API key required in `X-API-Key` header for ingestion endpoints (optional). |
| `MAX_UPLOAD_SIZE_MB`| `50` | Maximum file size allowed for log uploads in megabytes. |
| `CORS_ORIGINS` | `*` | Comma-separated list of allowed CORS origins. |

---

## 🧪 Testing the Ingestion Pipeline

The project includes `sample_logs/` designed specifically to test detection rules:

From the dashboard, upload the sample logs in the **Ingest Logs** panel:
- **`auth.log`** ➡️ Select **Auth Log** *(Triggers: Brute Force Attempt alert)*
- **`nginx_access.log`** ➡️ Select **Nginx / Apache** *(Triggers: Directory Traversal alert)*
- **`windows_events.json`** ➡️ Select **Windows Event Log** *(Triggers: Security Log Clearing alert)*
- **`syslog.log`** ➡️ Select **Syslog** *(Triggers: High Severity System Event)*

### Running Automated Tests

```bash
pytest -v
```

All 8 comprehensive tests run against an isolated in-memory test database, guaranteeing zero side-effects on production data.

---

## 📁 Repository Structure

```text
📦 siem_dashboard
 ┣ 📂 backend/
 ┃ ┣ 📜 alerting.py       # Asynchronous webhook dispatcher
 ┃ ┣ 📜 database.py       # SQLAlchemy ORM, indexes & connection pooling
 ┃ ┣ 📜 ingestion.py      # High-performance parsers & batch ingest logic
 ┃ ┣ 📜 main.py           # FastAPI entrypoint, health checks & routes
 ┃ ┣ 📜 rules_engine.py   # Sliding-window correlation & rule evaluation
 ┃ ┗ 📜 schemas.py        # Pydantic v2 schemas and validation models
 ┣ 📂 frontend/
 ┃ ┗ 📜 index.html        # Sanitized dark-themed SOC single-page app
 ┣ 📂 rules/
 ┃ ┗ 📜 default_rules.yaml# YAML detection rules & thresholds
 ┣ 📂 sample_logs/        # Pre-populated test logs formatted for ingestion
 ┣ 📂 tests/
 ┃ ┣ 📜 conftest.py       # Isolated in-memory DB fixtures
 ┃ ┗ 📜 test_api.py       # Full unit & integration test suite
 ┣ 📜 .github/workflows/ci.yml # Automated CI pipeline
 ┣ 📜 Dockerfile          # Multi-stage production container image
 ┣ 📜 docker-compose.yml  # Docker Compose orchestration
 ┣ 📜 pyproject.toml      # Pytest & project configuration
 ┣ 📜 render.yaml         # Cloud deployment blueprint
 ┗ 📜 requirements.txt    # Production dependencies
```

---

<div align="center">
  <i>Engineered for robust cyber-threat visibility and scalable security operations.</i>
</div>

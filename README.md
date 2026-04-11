<div align="center">
  <img src="https://img.shields.io/badge/Status-Active-success.svg" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/FastAPI-0.104.1-009688.svg?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Tailwind_CSS-38B2AC?logo=tailwind-css&logoColor=white" alt="Tailwind">
  
  <h1>🛡️ SIEM Dashboard Engine</h1>
  <p><i>A full-stack Security Information and Event Management (SIEM) Platform.</i></p>
</div>

---

## 📖 Overview

The **SIEM Dashboard** is a lightweight, customizable, robust full-stack application built to ingest, aggregate, and analyze network and security logs in real-time. Unifying logs from multiple sources, it categorizes events and runs custom correlation rules to detect persistent threats.

Whether it's parsing `syslog` output, analyzing Nginx activity, or trapping brute force attempts on `auth.log`, this engine normalizes unstructured data into actionable intelligence.

## ✨ Features

- **🚀 Live Dashboard**: A dynamic Single-Page Application featuring Chart.js analytics seamlessly updating in real time.
- **🔍 Log Normalization Engine**: Translates various heterogeneous formats (Syslog, Auth, Nginx HTTP, Windows JSONL) to a unified event schema.
- **⚔️ Rule-based Detection**: A YAML-synthesized Correlation Engine that triggers alerts based on count-thresholds in specified time windows.
- **🚨 Automated Alerting**: Provides local alert acknowledgments and outbound webhook connections for ChatOps integrations (Slack, Discord).
- **☁️ Production Ready**: Ships with `render.yaml` ensuring instant persistent cloud deployments.

---

## 🛠️ Technology Stack

| Component | Technology | Description |
|-----------|------------|-------------|
| **Backend API** | FastAPI | High-performance async Python backend routing API calls. |
| **Database** | SQLite + SQLAlchemy | Persistent ORM-based local event storage structure. |
| **Frontend** | Vanilla JS + HTML | A lightweight dark-themed SPA leveraging Tailwind CSS (CDN).|
| **Analytics** | Chart.js | Renders Top IPs, Categories, and Timeline events. |

---

## 🚀 Quick Start Setup

To run this application locally, ensure you have Python 3.10+ installed.

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

---

## 🧪 Testing the Ingestion Pipeline

The project includes `sample_logs/` designed specifically to trigger the pre-written detection rules. 

From the frontend dashboard, drag and drop the provided logs into the **Ingest Logs** panel using the correct Log Type dropdown:
- Upload `syslog.log` ➡️ **Syslog**
- Upload `auth.log` ➡️ **Auth Log** *(Triggers: Brute Force Attempt alerts)*
- Upload `nginx_access.log` ➡️ **Nginx Access Log** *(Triggers: Directory Traversal alerts)*
- Upload `windows_events.json` ➡️ **Windows Events** *(Triggers: Security Log Clearing alert)*

---

## 📁 Repository Structure

```text
📦 siem_dashboard
 ┣ 📂 backend/         # FastAPI entry and core logic (Alerting, Rules, DB, schemas)
 ┣ 📂 frontend/        # View presentation layer (Tailwind & SPA Logic)
 ┣ 📂 rules/           # YAML file definitions for event correlation rules
 ┣ 📂 sample_logs/     # Pre-populated test logs formatted for ingestion
 ┣ 📂 tests/           # Pytest suite
 ┣ 📜 render.yaml      # Blueprint infrastructure for Render deployments
 ┗ 📜 requirements.txt # Python dependencies
```

---

<div align="center">
  <i>Engineered for robust cyber-threat visibility.</i>
</div>

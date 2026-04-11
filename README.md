# Complete SIEM Dashboard

A fully functional Security Information and Event Management (SIEM) dashboard built from scratch using FastAPI, SQLite, and Vanilla JS with Tailwind CSS.

## Features
- **Frontend Dashboard:** Real-time event feed, charts (Chart.js), and active alert monitoring (Vanilla JS + Tailwind CDN). View `index.html` via the backend server at `http://localhost:8000/`.
- **Log Ingestion Engine:** Parses syslog, auth.log, Nginx access logs, and Windows Event JSONL files.
- **Normalization:** Maps heterogeneous logs to a unified schema.
- **Detection Rules Engine:** YAML-based correlation rules evaluate incoming logs based on counts in time windows and custom filters to generate alerts.
- **Alerting Panel:** Built-in alerts dashboard with webhook integration for Slack/Discord. 
- **Analytics API:** Endpoints to aggregate log statistics (Top IPs, Events per hour, Categories).

## Setup Instructions

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the server:**
   ```bash
   uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Access the SIEM:**
   Open a web browser and navigate to `http://localhost:8000/`.

## Usage & Ingestion

From the dashboard, use the **Ingest Logs** panel to upload the provided test files located in `sample_logs/`.

1. Upload `syslog.log` as log type `Syslog`.
2. Upload `auth.log` as log type `Auth Log`.
3. Upload `nginx_access.log` as log type `Nginx Access Log`.
4. Upload `windows_events.json` as log type `Windows Events`.

You should see the dashboard charts populate and new alerts trigger regarding Brute Force attempts and Malicious file downloads!

## Testing

Run tests using pytest:

```bash
pytest tests/
```

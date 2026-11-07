import logging
import os
import threading
from typing import Optional
import httpx

logger = logging.getLogger(__name__)


def get_webhook_url() -> str:
    return os.getenv("WEBHOOK_URL", "").strip()


def _dispatch_webhook_sync(url: str, payload: dict):
    try:
        with httpx.Client(timeout=4.0) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            logger.info(f"Webhook alert dispatched successfully (status {response.status_code})")
    except Exception as e:
        logger.error(f"Failed to dispatch webhook alert: {e}")


def send_alert_webhook(rule_name: str, severity: str, description: str, host: Optional[str] = None):
    """
    Send an alert to a configured webhook URL (Slack, Discord, Teams, etc.).
    Dispatches in a background thread so log ingestion is never blocked.
    """
    webhook_url = get_webhook_url()
    if not webhook_url:
        logger.debug("Webhook alerting is disabled. Set WEBHOOK_URL environment variable to enable.")
        return

    host_info = f"\n*Host*: {host}" if host else ""
    payload = {
        "text": f"🚨 *SIEM ALERT* 🚨\n*Rule*: {rule_name}\n*Severity*: {severity.upper()}{host_info}\n*Description*: {description}"
    }

    thread = threading.Thread(
        target=_dispatch_webhook_sync,
        args=(webhook_url, payload),
        daemon=True,
    )
    thread.start()

import requests
import logging

logger = logging.getLogger(__name__)

# Configure Webhook URL for Slack or Discord. 
# Empty string means disabled.
WEBHOOK_URL = "" 

def send_alert_webhook(rule_name: str, severity: str, description: str):
    """
    Send an alert to a configured webhook URL (e.g., Slack, Discord).
    """
    if not WEBHOOK_URL:
        logger.info("Webhook alerting is disabled. Set WEBHOOK_URL to enable.")
        return

    # Using Slack webhook payload format as a generic standard
    payload = {
        "text": f"🚨 *SIEM ALERT* 🚨\n*Rule*: {rule_name}\n*Severity*: {severity}\n*Description*: {description}"
    }
    
    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        response.raise_for_status()
        logger.info(f"Successfully sent webhook alert for rule: {rule_name}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send webhook alert: {e}")

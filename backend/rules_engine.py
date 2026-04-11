import yaml
import logging
import os
from typing import List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from .database import LogEventDB, AlertDB
from .alerting import send_alert_webhook

logger = logging.getLogger(__name__)

class RulesEngine:
    def __init__(self, rules_file_path: str = "rules/default_rules.yaml"):
        # Make the path relative to the project root if the current working directory isn't exactly where expected
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.rules_file_path = os.path.join(base_dir, rules_file_path)
        self.rules = self.load_rules()
        logger.info(f"Loaded {len(self.rules)} rules from {self.rules_file_path}")

    def load_rules(self) -> List[Dict[str, Any]]:
        try:
            with open(self.rules_file_path, "r") as f:
                content = yaml.safe_load(f)
                return content.get("rules", [])
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return []

    def evaluate_event(self, event: LogEventDB, db: Session):
        """
        Evaluate a single event against all rules.
        """
        if not self.rules:
            # Try reloading rules if none are loaded (could have been missing at startup)
            self.rules = self.load_rules()
            
        for rule in self.rules:
            if self._match_condition(event, rule.get("condition", {})):
                self._process_rule_match(event, rule, db)

    def _match_condition(self, event: LogEventDB, condition: Dict[str, Any]) -> bool:
        """
        Check if an event matches a simple condition.
        """
        # Optional category filter
        if "category" in condition and event.category != condition["category"]:
            return False

        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")

        if not field or not operator or not value:
            return False

        event_value = getattr(event, field, None)
        if event_value is None:
            return False

        if operator == "equals":
            return str(event_value).lower() == str(value).lower()
        elif operator == "contains":
            return str(value).lower() in str(event_value).lower()
        
        return False

    def _process_rule_match(self, event: LogEventDB, rule: Dict[str, Any], db: Session):
        threshold = rule.get("threshold", 1)
        time_window = rule.get("time_window", 0)
        
        # Simple single-event rule
        if threshold <= 1:
            self._trigger_alert(rule, 1, db)
            return

        # Correlation rule
        if time_window > 0:
            past_time = datetime.utcnow() - timedelta(seconds=time_window)
            
            # Count similar events from the same host in the time window
            count = db.query(LogEventDB).filter(
                LogEventDB.host == event.host,
                LogEventDB.timestamp >= past_time
            ).count()

            # If we hit the threshold, trigger alert
            if count >= threshold:
                self._trigger_alert(rule, count, db)

    def _trigger_alert(self, rule: Dict[str, Any], count: int, db: Session):
        # Prevent spamming the same alert for the same time window by simple dedup.
        recent_alert = db.query(AlertDB).filter(
            AlertDB.rule_name == rule["name"],
            AlertDB.timestamp >= datetime.utcnow() - timedelta(minutes=1)
        ).first()

        if recent_alert:
            return # Skip if we already alerted recently

        alert = AlertDB(
            rule_name=rule["name"],
            severity=rule["severity"],
            description=rule["description"],
            events_correlated=count,
            acknowledged=0
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        
        logger.info(f"Generated alert: {alert.rule_name} (Severity: {alert.severity})")
        
        # Send webhook
        send_alert_webhook(alert.rule_name, alert.severity, alert.description)

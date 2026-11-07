import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session
import yaml
from .alerting import send_alert_webhook
from .database import AlertDB, LogEventDB

logger = logging.getLogger(__name__)


class RulesEngine:
    def __init__(self, rules_file_path: str = "rules/default_rules.yaml"):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.rules_file_path = os.path.join(base_dir, rules_file_path)
        self.rules = self.load_rules()
        logger.info(f"Loaded {len(self.rules)} rules from {self.rules_file_path}")

    def load_rules(self) -> List[Dict[str, Any]]:
        try:
            with open(self.rules_file_path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
                return content.get("rules", []) if content else []
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return []

    def evaluate_event(self, event: LogEventDB, db: Session):
        """
        Evaluate a single event against all configured detection rules.
        """
        if not self.rules:
            self.rules = self.load_rules()

        for rule in self.rules:
            if self._match_condition(event, rule.get("condition", {})):
                self._process_rule_match(event, rule, db)

    def _match_condition(self, event: LogEventDB, condition: Dict[str, Any]) -> bool:
        """
        Check if an event matches a rule condition.
        """
        if "category" in condition and event.category != condition["category"]:
            return False

        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")

        if not field or not operator or value is None:
            return False

        event_value = getattr(event, field, None)
        if event_value is None:
            return False

        if operator == "equals":
            return str(event_value).lower() == str(value).lower()
        elif operator == "contains":
            return str(value).lower() in str(event_value).lower()

        return False

    def _apply_condition_filter(self, query, condition: Dict[str, Any]):
        """
        Apply condition filters to a SQLAlchemy query so correlation only counts matching events.
        """
        if "category" in condition:
            query = query.filter(LogEventDB.category == condition["category"])

        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")

        if field and operator and value is not None and hasattr(LogEventDB, field):
            col = getattr(LogEventDB, field)
            if operator == "equals":
                query = query.filter(func.lower(col) == str(value).lower())
            elif operator == "contains":
                query = query.filter(col.ilike(f"%{value}%"))

        return query

    def _process_rule_match(self, event: LogEventDB, rule: Dict[str, Any], db: Session):
        threshold = rule.get("threshold", 1)
        time_window = rule.get("time_window", 0)

        # Single-event threshold
        if threshold <= 1:
            self._trigger_alert(rule, 1, event, db)
            return

        # Correlation rule with time-window aggregation
        if time_window > 0:
            event_time = event.timestamp or datetime.now(timezone.utc)
            past_time = event_time - timedelta(seconds=time_window)

            query = db.query(LogEventDB).filter(
                LogEventDB.host == event.host,
                LogEventDB.timestamp >= past_time,
                LogEventDB.timestamp <= event_time,
            )

            # Apply rule condition filters to query
            query = self._apply_condition_filter(query, rule.get("condition", {}))
            count = query.count()

            if count >= threshold:
                self._trigger_alert(rule, count, event, db)

    def _trigger_alert(self, rule: Dict[str, Any], count: int, event: Optional[LogEventDB], db: Session):
        now = datetime.now(timezone.utc)
        host_str = event.host if event else "unknown"
        alert_desc = f"{rule['description']} (Host: {host_str})"

        # Deduplicate per (rule_name, host) in 1-minute window to avoid alert storms
        recent_alert = db.query(AlertDB).filter(
            AlertDB.rule_name == rule["name"],
            AlertDB.description.contains(host_str),
            AlertDB.timestamp >= now - timedelta(minutes=1),
        ).first()

        if recent_alert:
            return

        alert = AlertDB(
            rule_name=rule["name"],
            severity=rule["severity"],
            description=alert_desc,
            events_correlated=count,
            acknowledged=0,
            timestamp=now,
            mitre_technique=rule.get("mitre_technique"),
            mitre_tactic=rule.get("mitre_tactic"),
            status="new"
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        logger.info(f"Generated alert: {alert.rule_name} (Severity: {alert.severity}) for host: {host_str}")
        send_alert_webhook(alert.rule_name, alert.severity, alert.description, host=host_str)

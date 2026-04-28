"""Sigma rule engine — matches OCSF events against Sigma rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from shrike.detect.alert import CorrelationAlert
from shrike.detect.sigma.rule_loader import SigmaRuleLoader
from shrike.detect.sigma.ocsf_mapper import OCSFFieldMapper
from shrike.evaluate.types import get_nested


class SigmaRuleEngine:
    """Matches OCSF events against loaded Sigma rules.

    Usage:
        engine = SigmaRuleEngine(rules_dir="/etc/sigma/rules")
        alerts = engine.match(ocsf_event)
    """

    def __init__(self, rules_dir: str | Path | None = None):
        """Initialize Sigma rule engine.

        Args:
            rules_dir: Directory containing Sigma YAML rule files.
        """
        self._loader = SigmaRuleLoader()
        self._mapper = OCSFFieldMapper()
        self.rules: list[dict[str, Any]] = []

        if rules_dir:
            self.load_rules(rules_dir)

    def get_stats(self) -> dict[str, Any]:
        """"Return Sigma rule engine statistics."""
        return {
            "rules_loaded": len(self.rules),
            "last_match_count": 0,
        }

    def load_rules(self, rules_dir: str | Path) -> int:
        """Load Sigma rules from directory.

        Args:
            rules_dir: Directory containing Sigma YAML files.

        Returns:
            Number of rules loaded.
        """
        loaded = self._loader.load_from_directory(rules_dir)
        self.rules.extend(loaded)
        return len(loaded)

    def match(self, event: dict[str, Any]) -> list[CorrelationAlert]:
        """Match an OCSF event against all loaded rules.

        Args:
            event: OCSF-normalized event dict.

        Returns:
            List of CorrelationAlerts for matching rules.
        """
        alerts: list[CorrelationAlert] = []

        for rule in self.rules:
            if self._rule_matches(rule, event):
                alert = self._create_alert(rule, event)
                alerts.append(alert)

        return alerts

    def _rule_matches(self, rule: dict[str, Any], event: dict[str, Any]) -> bool:
        """Check if a rule matches an event.

        Args:
            rule: Parsed Sigma rule.
            event: OCSF event.

        Returns:
            True if rule matches event.
        """
        # Check logsource compatibility first
        if not self._check_logsource(rule, event):
            return False

        # Check detection conditions
        detection = rule.get("detection", {})
        selections = detection.get("selection", {})

        # All selections must match (AND logic)
        for sel_name, sel_criteria in selections.items():
            if not self._check_selection(sel_criteria, event):
                return False

        return True

    def _check_logsource(self, rule: dict[str, Any], event: dict[str, Any]) -> bool:
        """Check if event matches rule's logsource specification.

        Args:
            rule: Parsed Sigma rule.
            event: OCSF event.

        Returns:
            True if logsource matches.
        """
        logsource = rule.get("logsource", {})
        category = logsource.get("category")
        service = logsource.get("service")

        # Get OCSF class_uid from event
        event_class_uid = event.get("class_uid")

        # Check category mapping
        if category:
            expected_class = self._mapper.get_class_uid_for_logsource(category, service)
            if expected_class and event_class_uid != expected_class:
                return False

        return True

    def _check_selection(self, criteria: Any, event: dict[str, Any]) -> bool:
        """Check if selection criteria matches event.

        Args:
            criteria: Sigma selection criteria (dict or list).
            event: OCSF event.

        Returns:
            True if criteria matches.
        """
        if isinstance(criteria, dict):
            # Field-based matching
            for field, value in criteria.items():
                if isinstance(value, list):
                    # OR logic for list values
                    if not self._check_field_values(field, value, event):
                        return False
                else:
                    # Single value matching
                    if not self._check_field_value(field, value, event):
                        return False
            return True
        elif isinstance(criteria, list):
            # List of field conditions (AND logic)
            return all(self._check_selection(c, event) for c in criteria)
        else:
            # Unknown criteria format
            return True

    def _check_field_values(
        self, sigma_field: str, values: list[Any], event: dict[str, Any]
    ) -> bool:
        """Check if field matches any of the values (OR logic).

        Args:
            sigma_field: Sigma field name.
            values: List of acceptable values.
            event: OCSF event.

        Returns:
            True if any value matches.
        """
        ocsf_path = self._mapper.map_field(sigma_field)
        if not ocsf_path:
            return False

        event_value = get_nested(event, ocsf_path)
        if event_value is None:
            return False

        for value in values:
            if self._values_match(event_value, value):
                return True

        return False

    def _check_field_value(
        self, sigma_field: str, expected_value: Any, event: dict[str, Any]
    ) -> bool:
        """Check if field matches expected value.

        Args:
            sigma_field: Sigma field name.
            expected_value: Expected value (may contain wildcards).
            event: OCSF event.

        Returns:
            True if value matches.
        """
        ocsf_path = self._mapper.map_field(sigma_field)
        if not ocsf_path:
            return False

        event_value = get_nested(event, ocsf_path)
        if event_value is None:
            return False

        return self._values_match(event_value, expected_value)

    def _values_match(self, actual: Any, expected: Any) -> bool:
        """Check if actual value matches expected (with wildcard support).

        Sigma wildcards:
        - '*' matches any sequence of characters
        - '?' matches any single character

        Args:
            actual: Actual value from event.
            expected: Expected value (may contain wildcards).

        Returns:
            True if values match.
        """
        actual_str = str(actual).lower()
        expected_str = str(expected)

        # Case-insensitive exact match
        if "*" not in expected_str and "?" not in expected_str:
            return actual_str == expected_str.lower()

        # Wildcard matching - convert Sigma wildcard to regex
        pattern = self._wildcard_to_regex(expected_str)
        return bool(re.match(pattern, actual_str, re.IGNORECASE))

    def _wildcard_to_regex(self, pattern: str) -> str:
        """Convert Sigma wildcard pattern to regex.

        Args:
            pattern: Pattern with * and ? wildcards.

        Returns:
            Regex pattern string.
        """
        # Escape regex special chars except * and ?
        result = ""
        for char in pattern:
            if char == "*":
                result += ".*"
            elif char == "?":
                result += "."
            elif char in r"\.^$+{}[]|()":
                result += "\\" + char
            else:
                result += char

        return f"^{result}$"

    def _create_alert(self, rule: dict[str, Any], event: dict[str, Any]) -> CorrelationAlert:
        """Create a CorrelationAlert from a matching rule.

        Args:
            rule: Matched Sigma rule.
            event: Matching OCSF event.

        Returns:
            CorrelationAlert.
        """
        # Map severity
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        severity = severity_map.get(rule.get("level", "medium"), "medium")

        # Extract observables from event
        observables = self._extract_observables(event)

        return CorrelationAlert(
            alert_id=f"sigma-{rule.get('id', 'unknown')}-{id(event)}",
            timestamp=event.get("time", ""),
            correlation_type="sigma",
            severity=severity,
            title=rule.get("title", "Unknown"),
            description=rule.get("description", ""),
            matched_rules=[rule.get("title", "")],
            observables=observables,
            event_count=1,
            mitre_techniques=rule.get("mitre_techniques", []),
            mitre_tactics=rule.get("mitre_tactics", []),
            event_ids=[event.get("event_id", "")],
        )

    def _extract_observables(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract observables from an OCSF event.

        Args:
            event: OCSF event.

        Returns:
            List of observable dicts.
        """
        observables = []

        # Extract from observables field
        for obs in event.get("observables", []):
            observables.append(obs)

        # Extract key fields
        if "src_endpoint" in event and "ip" in event["src_endpoint"]:
            observables.append({
                "name": "src_endpoint.ip",
                "type": "IP Address",
                "value": event["src_endpoint"]["ip"],
            })

        if "user" in event and "name" in event["user"]:
            observables.append({
                "name": "user.name",
                "type": "User Name",
                "value": event["user"]["name"],
            })

        return observables

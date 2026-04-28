"""Schema-aware value coercion for OCSF fields.

Replaces the blind _coerce_value() with type-aware coercion that knows
whether a field should be an IP, port, timestamp, integer, or string.

Usage:
    from shrike.evaluate.coercion import OCSFCoercer

    coercer = OCSFCoercer()
    value = coercer.coerce("src_endpoint.port", "22/tcp")  # → 22
    value = coercer.coerce("file.hashes.value", "1234567890")  # → "1234567890" (stays string)
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any


# OCSF field path → expected type.
# Derived from OCSF field naming conventions and schema semantics.
# The schema files have type=string for everything, so we maintain
# a curated map based on OCSF documentation.
FIELD_TYPE_MAP: dict[str, str] = {
    # IP addresses
    "src_endpoint.ip": "ip",
    "dst_endpoint.ip": "ip",
    "device.ip": "ip",

    # Ports
    "src_endpoint.port": "port",
    "dst_endpoint.port": "port",

    # Integers (PIDs, counts, IDs)
    "process.pid": "integer",
    "process.parent_process.pid": "integer",
    "process.tid": "integer",
    "count": "integer",
    "metadata.count": "integer",

    # Timestamps
    "time": "timestamp",
    "start_time": "timestamp",
    "end_time": "timestamp",
    "metadata.logged_time": "timestamp",

    # Enums — severity
    "severity_id": "severity_enum",

    # Enums — activity
    "activity_id": "activity_enum",

    # Traffic bytes/packets
    "traffic.bytes": "integer",
    "traffic.bytes_in": "integer",
    "traffic.bytes_out": "integer",
    "traffic.packets": "integer",
    "traffic.packets_in": "integer",
    "traffic.packets_out": "integer",

    # MAC addresses
    "device.mac": "mac",
    "src_endpoint.mac": "mac",

    # Booleans
    "is_mfa": "boolean",
    "is_remote": "boolean",

    # Field coverage / scores
    "field_coverage": "float",
}

# Suffix-based type inference for fields NOT in the explicit map.
# Checked in order — first match wins.
SUFFIX_TYPE_RULES: list[tuple[str, str]] = [
    (".ip", "ip"),
    (".port", "port"),
    (".pid", "integer"),
    (".tid", "integer"),
    (".mac", "mac"),
    ("_id", "integer"),  # severity_id, activity_id, class_uid, etc.
    ("_uid", "integer"),
    ("_count", "integer"),
]

# Severity name → ID mapping (OCSF standard)
SEVERITY_MAP: dict[str, int] = {
    "unknown": 0, "informational": 1, "info": 1, "low": 2,
    "medium": 3, "high": 4, "critical": 5, "fatal": 6, "other": 99,
}

# Valid activity IDs (OCSF allows 0-6, 99)
VALID_ACTIVITY_IDS = {0, 1, 2, 3, 4, 5, 6, 99}


class OCSFCoercer:
    """Schema-aware value coercion for OCSF fields."""

    def __init__(self) -> None:
        self._type_map = dict(FIELD_TYPE_MAP)

    def evaluate_batch(self, results: list[tuple[dict, dict]]) -> float:
        """"Score type coercion quality across a batch of results.

        Args:
            results: List of (actual, expected) dicts.

        Returns:
            Score 0-100 representing % of fields correctly coerced.
        """
        if not results:
            return 0.0
        correct = 0
        for actual, expected in results:
            for field, exp_val in expected.items():
                act_val = actual.get(field)
                if self.validate_type(field, act_val) and act_val == exp_val:
                    correct += 1
        return round(correct / len(results) * 100, 1)

    def get_type(self, field_path: str) -> str | None:
        """Get the expected type for a field path."""
        # Exact match first
        if field_path in self._type_map:
            return self._type_map[field_path]
        # Suffix-based inference
        for suffix, field_type in SUFFIX_TYPE_RULES:
            if field_path.endswith(suffix):
                return field_type
        return None

    def coerce(self, field_path: str, value: Any) -> Any:
        """Coerce a value to match the expected OCSF type for this field.

        Returns the coerced value, or the original if coercion fails.
        """
        field_type = self.get_type(field_path)
        if field_type is None:
            return self._coerce_generic(value)

        coercer = {
            "ip": self._coerce_ip,
            "port": self._coerce_port,
            "integer": self._coerce_integer,
            "float": self._coerce_float,
            "timestamp": self._coerce_timestamp,
            "mac": self._coerce_mac,
            "boolean": self._coerce_boolean,
            "severity_enum": self._coerce_severity,
            "activity_enum": self._coerce_activity,
        }.get(field_type)

        if coercer:
            result = coercer(value)
            return result if result is not None else value
        return value

    def validate_type(self, field_path: str, value: Any) -> bool:
        """Check if a value matches the expected type (without coercing)."""
        field_type = self.get_type(field_path)
        if field_type is None:
            return True  # No type constraint

        validator = {
            "ip": self._is_valid_ip,
            "port": self._is_valid_port,
            "integer": lambda v: isinstance(v, int),
            "float": lambda v: isinstance(v, (int, float)),
            "timestamp": self._is_valid_timestamp,
            "mac": self._is_valid_mac,
            "boolean": lambda v: isinstance(v, bool),
            "severity_enum": lambda v: isinstance(v, int) and 0 <= v <= 99,
            "activity_enum": lambda v: isinstance(v, int) and v in VALID_ACTIVITY_IDS,
        }.get(field_type)

        return validator(value) if validator else True

    # --- Coercion methods ---

    @staticmethod
    def _coerce_ip(value: Any) -> str | None:
        """Coerce to valid IP. Strips port suffixes."""
        val_str = str(value).strip("'\"")
        # Strip port suffix: "1.2.3.4:22" → "1.2.3.4"
        if ":" in val_str and val_str.count(":") == 1:
            host, _, port = val_str.rpartition(":")
            if port.isdigit():
                val_str = host
        # Strip bracket notation: "[::1]" → "::1"
        val_str = val_str.strip("[]")
        try:
            ipaddress.ip_address(val_str)
            return val_str
        except ValueError:
            return None

    @staticmethod
    def _coerce_port(value: Any) -> int | None:
        """Coerce to valid port (0-65535). Handles '22/tcp'."""
        if isinstance(value, int):
            return value if 0 <= value <= 65535 else None
        val_str = str(value).strip("'\"")
        # Handle "22/tcp", "443/https"
        m = re.match(r"(\d+)(?:/\w+)?$", val_str)
        if m:
            port = int(m.group(1))
            return port if 0 <= port <= 65535 else None
        return None

    @staticmethod
    def _coerce_integer(value: Any) -> int | None:
        """Coerce to integer. Strips non-digit prefixes/suffixes."""
        if isinstance(value, int):
            return value
        val_str = str(value).strip("'\"")
        # Try direct parse
        try:
            return int(val_str)
        except ValueError:
            pass
        # Extract first numeric sequence
        m = re.search(r"-?\d+", val_str)
        return int(m.group()) if m else None

    @staticmethod
    def _coerce_float(value: Any) -> float | None:
        """Coerce to float. Strips percentage signs."""
        if isinstance(value, (int, float)):
            return float(value)
        val_str = str(value).strip("'\"").rstrip("%")
        try:
            return float(val_str)
        except ValueError:
            return None

    @staticmethod
    def _coerce_timestamp(value: Any) -> Any:
        """Coerce to timestamp. Returns the value in its most useful form."""
        if isinstance(value, (int, float)):
            v = float(value)
            # Millisecond epoch → convert to seconds
            if 946684800000 < v < 4102444800000:
                return v / 1000.0
            # Second epoch — leave as-is
            if 946684800 < v < 4102444800:
                return v
            return value
        val_str = str(value).strip("'\"")
        # Try ISO8601
        try:
            datetime.fromisoformat(val_str.replace("Z", "+00:00"))
            return val_str
        except ValueError:
            pass
        # Try common syslog format "Mar 29 10:00:00" (with year added to avoid deprecation)
        try:
            # Add current year to avoid Python 3.15 deprecation warning about ambiguous dates
            current_year = datetime.now().year
            datetime.strptime(f"{val_str} {current_year}", "%b %d %H:%M:%S %Y")
            return val_str
        except ValueError:
            pass
        # Try epoch as string (seconds or milliseconds)
        try:
            epoch = float(val_str)
            if 946684800000 < epoch < 4102444800000:
                return epoch / 1000.0
            if 946684800 < epoch < 4102444800:
                return epoch
        except ValueError:
            pass
        return value  # Can't parse — return as-is

    @staticmethod
    def _coerce_mac(value: Any) -> str | None:
        """Coerce to normalized MAC address."""
        val_str = str(value).strip("'\"").lower()
        # Remove separators and reformat
        clean = re.sub(r"[:\-.]", "", val_str)
        if len(clean) == 12 and all(c in "0123456789abcdef" for c in clean):
            return ":".join(clean[i:i+2] for i in range(0, 12, 2))
        return None

    @staticmethod
    def _coerce_boolean(value: Any) -> bool | None:
        """Coerce to boolean."""
        if isinstance(value, bool):
            return value
        val_str = str(value).strip("'\"").lower()
        if val_str in ("true", "yes", "1", "success", "succeeded", "pass", "accept"):
            return True
        if val_str in ("false", "no", "0", "failure", "failed", "fail", "deny", "block"):
            return False
        return None

    @staticmethod
    def _coerce_severity(value: Any) -> int | None:
        """Coerce severity to OCSF severity_id enum."""
        if isinstance(value, int) and 0 <= value <= 99:
            return value
        val_str = str(value).strip("'\"").lower()
        # Try name lookup
        if val_str in SEVERITY_MAP:
            return SEVERITY_MAP[val_str]
        # Try numeric string
        try:
            v = int(val_str)
            return v if 0 <= v <= 99 else None
        except ValueError:
            return None

    @staticmethod
    def _coerce_activity(value: Any) -> int | None:
        """Coerce activity to OCSF activity_id enum."""
        if isinstance(value, int) and value in VALID_ACTIVITY_IDS:
            return value
        try:
            v = int(str(value).strip("'\""))
            return v if v in VALID_ACTIVITY_IDS else None
        except ValueError:
            return None

    @staticmethod
    def _coerce_generic(value: Any) -> Any:
        """Generic coercion for fields without a known type. Strip quotes."""
        if isinstance(value, str):
            return value.strip("'\"")
        return value

    # --- Validators (no coercion, just check) ---

    @staticmethod
    def _is_valid_ip(value: Any) -> bool:
        try:
            ipaddress.ip_address(str(value).strip("[]"))
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_port(value: Any) -> bool:
        return isinstance(value, int) and 0 <= value <= 65535

    @staticmethod
    def _is_valid_timestamp(value: Any) -> bool:
        if isinstance(value, (int, float)):
            v = float(value)
            # Epoch seconds (2000-2100)
            if 946684800 < v < 4102444800:
                return True
            # Epoch milliseconds (2000-2100)
            if 946684800000 < v < 4102444800000:
                return True
            return False
        val_str = str(value)
        # ISO8601
        try:
            datetime.fromisoformat(val_str.replace("Z", "+00:00"))
            return True
        except ValueError:
            pass
        # Syslog BSD (no year) - add current year to avoid Python 3.15 deprecation
        try:
            current_year = datetime.now().year
            datetime.strptime(f"{val_str} {current_year}", "%b %d %H:%M:%S %Y")
            return True
        except ValueError:
            pass
        # Slash format: 2026/03/30 01:53:25.597 +00:00
        try:
            # Strip timezone offset for parsing
            clean = re.sub(r'\s*[+-]\d{2}:\d{2}\s*$', '', val_str)
            datetime.strptime(clean, "%Y/%m/%d %H:%M:%S.%f")
            return True
        except ValueError:
            pass
        try:
            datetime.strptime(val_str, "%Y/%m/%d %H:%M:%S")
            return True
        except ValueError:
            pass
        # Time only (HH:MM:SS) — accept as partial timestamp
        if re.match(r'^\d{2}:\d{2}:\d{2}', val_str):
            return True
        # Comma-separated: "Mar 28, 2026 04:39:42.196"
        try:
            datetime.strptime(val_str.split('.')[0], "%b %d, %Y %H:%M:%S")
            return True
        except ValueError:
            pass
        # CLF/Apache: "15/Jan/2024:14:30:25 +0100"
        if re.match(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', val_str):
            return True
        # Asctime: "Mon Aug 28 08:04:30 2023"
        try:
            datetime.strptime(val_str, "%a %b %d %H:%M:%S %Y")
            return True
        except ValueError:
            pass
        # US date: "05/02/2025 11:31:06"
        try:
            datetime.strptime(val_str, "%m/%d/%Y %H:%M:%S")
            return True
        except ValueError:
            pass
        # Epoch as string (seconds or milliseconds)
        try:
            epoch = float(val_str)
            if 946684800 < epoch < 4102444800:
                return True
            if 946684800000 < epoch < 4102444800000:
                return True
        except ValueError:
            pass
        return False

    @staticmethod
    def _is_valid_mac(value: Any) -> bool:
        return bool(re.match(
            r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$", str(value)
        ))

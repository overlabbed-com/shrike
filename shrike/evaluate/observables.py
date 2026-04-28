"""OCSF Observables builder — populates the observables[] array.

Every OCSF event should have an observables[] array that catalogs all
observed entities (IPs, hostnames, users, processes, etc.) with their
type and role. This is how SIEMs correlate across events — "show me
every event involving 192.168.1.3."

Usage:
    from shrike.evaluate.observables import ObservablesBuilder

    builder = ObservablesBuilder()
    event = {"src_endpoint": {"ip": "1.2.3.4", "port": 22}, "user": "admin"}
    builder.inject(event)
    # event["observables"] = [
    #   {"name": "src_endpoint.ip", "type": "IP Address", "type_id": 2, "value": "1.2.3.4"},
    #   {"name": "src_endpoint.port", "type": "Port", "type_id": 11, "value": "22"},
    #   {"name": "user", "type": "User Name", "type_id": 4, "value": "admin"},
    # ]
"""

from __future__ import annotations

from typing import Any

from shrike.evaluate.types import walk_event


# OCSF Observable type IDs (from OCSF v1.3 dictionary)
# Explicit full-path mappings — highest priority
FIELD_OBSERVABLE_MAP: dict[str, tuple[int, str]] = {
    # IP Addresses (type_id=2)
    "src_endpoint.ip": (2, "IP Address"),
    "dst_endpoint.ip": (2, "IP Address"),
    "device.ip": (2, "IP Address"),

    # Hostnames (type_id=1)
    "device.hostname": (1, "Hostname"),
    "src_endpoint.hostname": (1, "Hostname"),
    "dst_endpoint.hostname": (1, "Hostname"),
    "query.hostname": (1, "Hostname"),
    "http_request.url.hostname": (1, "Hostname"),

    # Ports (type_id=11)
    "src_endpoint.port": (11, "Port"),
    "dst_endpoint.port": (11, "Port"),

    # User Names (type_id=4)
    "user": (4, "User Name"),
    "actor.user.name": (4, "User Name"),
    "actor.user.uid": (10, "Resource UID"),

    # Process (type_id=9, 15, 13)
    "process.name": (9, "Process Name"),
    "process.pid": (15, "Process ID"),
    "process.cmd_line": (13, "Command Line"),
    "process.file.path": (7, "File Name"),
    "process.parent_process.name": (9, "Process Name"),
    "process.parent_process.pid": (15, "Process ID"),

    # File (type_id=7, 8)
    "file.name": (7, "File Name"),
    "file.path": (7, "File Name"),
    "file.hashes.value": (8, "Hash"),

    # Network (type_id=6, 16)
    "http_request.url.path": (6, "URL String"),
    "http_request.user_agent": (16, "HTTP User-Agent"),

    # MAC (type_id=3)
    "device.mac": (3, "MAC Address"),
    "src_endpoint.mac": (3, "MAC Address"),

    # Email (type_id=5)
    "email.from": (5, "Email Address"),
    "email.to": (5, "Email Address"),

    # Session/Resource (type_id=10)
    "session.uid": (10, "Resource UID"),
    "finding_info.uid": (10, "Resource UID"),
    "metadata.uid": (10, "Resource UID"),
}

# Suffix-based fallback for fields not in the explicit map
SUFFIX_OBSERVABLE_MAP: list[tuple[str, int, str]] = [
    (".ip", 2, "IP Address"),
    (".hostname", 1, "Hostname"),
    (".port", 11, "Port"),
    (".mac", 3, "MAC Address"),
    (".name", 9, "Process Name"),  # Only under process objects
    (".pid", 15, "Process ID"),
    (".cmd_line", 13, "Command Line"),
    (".path", 7, "File Name"),
    (".user_agent", 16, "HTTP User-Agent"),
]

# Fields to exclude from observables (metadata, not observable entities)
EXCLUDE_FIELDS = frozenset({
    "class_uid", "class_name", "category_uid", "category_name",
    "activity_id", "activity_name", "severity_id", "severity",
    "type_uid", "type_name", "status_id", "status",
    "message", "raw_data", "time", "start_time", "end_time",
    "metadata.version", "metadata.product.name",
    "metadata.product.vendor_name", "metadata.event_code",
    "metadata.logged_time",
})

class ObservablesBuilder:
    """Build OCSF observables[] array from extracted event fields."""

    def build(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Walk event fields and build observables array.

        Returns list of observable dicts, each with:
          name: OCSF field path (e.g., "src_endpoint.ip")
          type: Human-readable type name (e.g., "IP Address")
          type_id: OCSF observable type ID (e.g., 2)
          value: The actual value
        """
        observables: list[dict[str, Any]] = []
        seen_values: set[str] = set()  # Dedupe by (type_id, value)

        for field_path, value in walk_event(event):
            if field_path in EXCLUDE_FIELDS:
                continue
            if value is None or str(value) in ("", "None", "null", "0", "unknown"):
                continue

            type_id, type_name = self._get_observable_type(field_path)
            if type_id is None:
                continue

            # Dedupe: same type + same value = one observable
            dedup_key = f"{type_id}:{value}"
            if dedup_key in seen_values:
                continue
            seen_values.add(dedup_key)

            observables.append({
                "name": field_path,
                "type": type_name,
                "type_id": type_id,
                "value": value,
            })

        return observables

    def inject(self, event: dict[str, Any]) -> dict[str, Any]:
        """Add observables[] to event in-place. Returns the modified event."""
        event["observables"] = self.build(event)
        return event

    def count_eligible(self, event: dict[str, Any]) -> int:
        """Count fields that COULD produce observables (regardless of whether they do)."""
        count = 0
        for field_path, value in walk_event(event):
            if field_path in EXCLUDE_FIELDS:
                continue
            if value is None or str(value) in ("", "None", "null", "0", "unknown"):
                continue
            type_id, _ = self._get_observable_type(field_path)
            if type_id is not None:
                count += 1
        return count

    def _get_observable_type(self, field_path: str) -> tuple[int | None, str]:
        """Get the observable type for a field path."""
        # Explicit map first
        if field_path in FIELD_OBSERVABLE_MAP:
            return FIELD_OBSERVABLE_MAP[field_path]

        # Suffix-based fallback
        for suffix, type_id, type_name in SUFFIX_OBSERVABLE_MAP:
            if field_path.endswith(suffix):
                return type_id, type_name

        return None, ""

    def evaluate_batch(self, results):
        if not results:
            return 0.0
        covered = 0
        for actual, expected in results:
            obs = self.build(actual)
            obs_fields = {o['name'] for o in obs}
            for field in expected:
                if field in obs_fields:
                    covered += 1
        return round(covered / len(results) * 100, 1)

    def evaluate_batch(self, results):
        if not results:
            return 0.0
        covered = 0
        for actual, expected in results:
            obs = self.build(actual)
            obs_fields = {o["name"] for o in obs}
            for field in expected:
                if field in obs_fields:
                    covered += 1
        return round(covered / len(results) * 100, 1)

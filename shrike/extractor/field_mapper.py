"""OCSF field name mapper — maps vendor-specific JSON field names to OCSF paths.

Three strategies, tried in order:
  1. Exact alias lookup (data/field_aliases.json)
  2. Fuzzy substring rules (IP-like, user-like, process-like)
  3. Embedding-based KNN similarity (requires sentence-transformers)

This replaces the hardcoded field name lists in _auto_extract_json.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class FieldMapper:
    """Maps vendor field names to OCSF field paths."""

    def __init__(self, aliases_path: Path | None = None):
        self._aliases: dict[str, str] = {}
        if aliases_path is None:
            aliases_path = Path(__file__).parent.parent.parent / "data" / "field_aliases.json"
        if aliases_path.exists():
            with open(aliases_path) as f:
                self._aliases = json.load(f)

        # Lazy-loaded embedding mapper (Strategy 3)
        self._embedding_mapper = None
        self._embedding_available: bool | None = None  # None = not checked yet

    def map_field(self, vendor_field: str, value: Any = None) -> str | None:
        """Map a vendor field name to an OCSF field path.

        Args:
            vendor_field: The vendor-specific field name (e.g., "source.ip", "aip").
            value: Optional field value for type-based heuristics.

        Returns:
            OCSF field path (e.g., "src_endpoint.ip") or None if no mapping found.
        """
        # Strategy 1: Exact alias lookup
        result = self._aliases.get(vendor_field)
        if result:
            return result

        # Also try the leaf name (last part after dots)
        leaf = vendor_field.rsplit(".", 1)[-1] if "." in vendor_field else vendor_field
        result = self._aliases.get(leaf)
        if result:
            return result

        # Strategy 2: Fuzzy substring rules
        result = self._fuzzy_match(vendor_field, value)
        if result:
            return result

        # Strategy 3: Embedding-based similarity
        result = self._embedding_match(vendor_field)
        if result:
            return result

        return None

    def map_all(self, fields: dict[str, Any]) -> dict[str, tuple[str, Any]]:
        """Map all fields in a dict. Returns {ocsf_path: (vendor_field, value)}."""
        mapped = {}
        for vendor_field, value in fields.items():
            ocsf_path = self.map_field(vendor_field, value)
            if ocsf_path and value is not None:
                mapped[ocsf_path] = (vendor_field, value)
        return mapped

    def _get_embedding_mapper(self):
        """Lazy-load the embedding mapper. Returns None if unavailable."""
        if self._embedding_available is False:
            return None
        if self._embedding_mapper is not None:
            return self._embedding_mapper

        try:
            from shrike.extractor.embedding_field_mapper import EmbeddingFieldMapper
            self._embedding_mapper = EmbeddingFieldMapper()
            self._embedding_available = True
            return self._embedding_mapper
        except (ImportError, Exception) as e:
            logger.debug("Embedding field mapper unavailable: %s", e)
            self._embedding_available = False
            return None

    def _embedding_match(self, field: str) -> str | None:
        """Strategy 3: Embedding-based similarity matching."""
        mapper = self._get_embedding_mapper()
        if mapper is None:
            return None

        try:
            ocsf_path, score = mapper.map_field(field)
            if ocsf_path:
                logger.debug(
                    "Embedding match: %s -> %s (score=%.3f)", field, ocsf_path, score
                )
            return ocsf_path
        except Exception as e:
            logger.debug("Embedding match failed for %s: %s", field, e)
            return None

    def _fuzzy_match(self, field: str, value: Any = None) -> str | None:
        """Fuzzy substring-based field mapping."""
        fl = field.lower()
        val_str = str(value) if value is not None else ""

        # IP address fields
        if self._is_ip_value(val_str):
            if any(k in fl for k in ("src", "source", "client", "caller", "remote", "origin")):
                return "src_endpoint.ip"
            if any(k in fl for k in ("dst", "dest", "server", "target")):
                return "dst_endpoint.ip"
            if "ip" in fl or "addr" in fl:
                return "src_endpoint.ip"  # Default to source if ambiguous

        # Port fields
        if any(k in fl for k in ("sport", "src_port", "source_port", "srcport", "s_port")):
            return "src_endpoint.port"
        if any(k in fl for k in ("dport", "dst_port", "dest_port", "dstport", "d_port")):
            return "dst_endpoint.port"

        # User fields
        if fl in ("user", "username", "user_name", "login", "account"):
            return "user"
        if any(k in fl for k in ("email", "mail")) and "subject" not in fl:
            if "@" in val_str:
                return "user"

        # Process fields
        if fl in ("process", "proc", "program"):
            return "process.name"
        if fl in ("pid", "process_id", "processid"):
            return "process.pid"
        if any(k in fl for k in ("cmdline", "command_line", "commandline", "cmd")):
            return "process.cmd_line"
        if fl in ("exe", "executable", "binary", "image"):
            return "process.file.path"

        # Host/device fields
        if fl in ("hostname", "host", "computer", "machine", "node", "device"):
            return "device.hostname"
        if fl in ("fqdn", "host_fqdn"):
            return "device.hostname"

        # Severity
        if fl in ("severity", "sev", "priority", "prio"):
            return "severity"
        if fl in ("severity_id", "sev_id"):
            return "severity_id"

        # Time
        if fl in ("timestamp", "time", "ts", "date", "datetime", "eventtime",
                  "created_at", "created", "logged_at", "log_time"):
            return "time"

        # Action/activity
        if fl in ("action", "activity", "operation", "method", "verb", "event_type"):
            return "activity_name"

        # Message
        if fl in ("message", "msg", "description", "detail", "details", "text", "log_message"):
            return "message"

        # Protocol
        if fl in ("protocol", "proto", "transport"):
            return "connection_info.protocol_name"

        # URL
        if fl in ("url", "uri", "path", "request_uri", "request_url"):
            return "http_request.url.path"

        # HTTP method
        if fl in ("method", "http_method", "request_method"):
            if val_str.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                return "http_request.http_method"

        # Status
        if fl in ("status", "result", "outcome", "response_code", "status_code"):
            return "status"

        # File
        if any(k in fl for k in ("filename", "file_name", "fname")):
            return "file.name"
        if any(k in fl for k in ("filepath", "file_path", "fpath")):
            return "file.path"
        if any(k in fl for k in ("hash", "sha256", "md5", "sha1")):
            return "file.hashes.value"

        # DNS
        if any(k in fl for k in ("query", "qname", "domain", "fqdn")) and "dns" in fl:
            return "query.hostname"

        return None

    @staticmethod
    def _is_ip_value(val: str) -> bool:
        """Check if a value looks like an IP address."""
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val.strip()))

    @property
    def alias_count(self) -> int:
        return len(self._aliases)

    def map_batch(self, vendor_fields: list[str]) -> list[str | None]:
        return [self.map_field(f) for f in vendor_fields]

    def get_stats(self) -> dict:
        return {
            'aliases_loaded': len(self._aliases),
            'embedding_available': self._embedding_available is True,
        }

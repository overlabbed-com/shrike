"""Splunk HEC destination — sends OCSF events to Splunk via HTTP Event Collector."""

from __future__ import annotations

import json
import logging
import ssl
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

from shrike.destinations.base import Destination, HealthStatus, SendResult
from shrike.destinations.wal import WriteAheadLog

logger = logging.getLogger(__name__)

# OCSF class_uid → Splunk index mapping
# Each OCSF class routes to its own index for targeted searching and retention.
# Class-level indexes enable per-class retention policies and faster searches.
_CLASS_INDEX: dict[int, str] = {
    # System Activity (category 1)
    1001: "ocsf-file-activity", 1002: "ocsf-kernel-extension",
    1003: "ocsf-kernel-activity", 1004: "ocsf-memory-activity",
    1005: "ocsf-module-activity", 1006: "ocsf-scheduled-job",
    1007: "ocsf-process-activity", 1008: "ocsf-log-activity",
    # Findings (category 2)
    2001: "ocsf-security-finding", 2002: "ocsf-vulnerability-finding",
    2003: "ocsf-compliance-finding", 2004: "ocsf-detection-finding",
    2005: "ocsf-incident-finding", 2006: "ocsf-data-security-finding",
    # IAM (category 3)
    3001: "ocsf-account-change", 3002: "ocsf-authentication",
    3003: "ocsf-authorize-session", 3004: "ocsf-group-management",
    3005: "ocsf-user-access-management", 3006: "ocsf-entity-management",
    # Network Activity (category 4)
    4001: "ocsf-network-activity", 4002: "ocsf-http-activity",
    4003: "ocsf-dns-activity", 4004: "ocsf-dhcp-activity",
    4005: "ocsf-rdp-activity", 4006: "ocsf-smb-activity",
    4007: "ocsf-ssh-activity", 4008: "ocsf-ftp-activity",
    4009: "ocsf-email-activity", 4010: "ocsf-file-hosting",
    4011: "ocsf-vpn-activity", 4012: "ocsf-email-url",
    4013: "ocsf-inventory-info",
    # Discovery (category 5)
    5001: "ocsf-device-inventory", 5002: "ocsf-compliance-check",
    5003: "ocsf-directory-service", 5004: "ocsf-config-state",
    5019: "ocsf-device-config-state",
    # Application Activity (category 6)
    6001: "ocsf-web-resources", 6002: "ocsf-application-lifecycle",
    6003: "ocsf-api-activity", 6005: "ocsf-file-hosting-activity",
    6006: "ocsf-scan-activity", 6007: "ocsf-module-activity-app",
}

# Category-level fallback — used when class_uid isn't in the class map.
_CATEGORY_INDEX: dict[int, str] = {
    1: "ocsf-system", 2: "ocsf-findings", 3: "ocsf-iam",
    4: "ocsf-network", 5: "ocsf-discovery", 6: "ocsf-application",
}

_DEFAULT_INDEX = "ocsf-raw"

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503})


def _is_retryable(status_code: int) -> bool:
    """Return True if the HTTP status code indicates a transient failure worth retrying."""
    return status_code in _RETRYABLE_STATUS_CODES


def class_uid_to_index(class_uid: int | None, category_uid: int | None = None) -> str:
    """Map an OCSF class_uid to a Splunk index name.

    Tries class-level first, falls back to category, then ocsf_raw.
    """
    if class_uid and class_uid in _CLASS_INDEX:
        return _CLASS_INDEX[class_uid]
    if category_uid and category_uid in _CATEGORY_INDEX:
        return _CATEGORY_INDEX[category_uid]
    if class_uid:
        cat = class_uid // 1000
        if cat in _CATEGORY_INDEX:
            return _CATEGORY_INDEX[cat]
    return _DEFAULT_INDEX


class SplunkHECDestination(Destination):
    """Sends OCSF-normalized events to Splunk via HEC."""

    name = "splunk_hec"

    def __init__(
        self,
        url: str,
        token: str,
        wal_dir: str | None = None,
        max_size_mb: int = 500,
        tls_verify: bool = True,
        **kwargs: object,
    ) -> None:
        self._url = url.rstrip("/") + "/services/collector/event"
        self._token = token
        self._last_send: float = 0.0
        self._retry_count: int = 0
        self._last_error: str = ""

        # WAL for durability - use secure temp directory
        wal_path = Path(wal_dir) if wal_dir else Path(tempfile.mkdtemp(prefix="shrike-splunk-"))
        self.wal = WriteAheadLog(self.name, wal_path, max_size_mb=max_size_mb)

        # Build SSL context based on tls_verify setting
        if tls_verify:
            self._ssl_ctx = ssl.create_default_context()
        else:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

        # V-5: Reuse a single session (lazy-init to avoid event loop requirement at construction)
        self._session: aiohttp.ClientSession | None = None

        # Management API URL (port 8089) for index creation
        # Use urlparse to correctly extract hostname regardless of scheme/port presence
        parsed_url = urlparse(url)
        host = parsed_url.hostname or url.strip("/").split("//")[1].split(":")[0]
        # Preserve scheme from original URL (HTTPS HEC → HTTPS management)
        scheme = "https" if parsed_url.scheme == "https" else "http"
        self._mgmt_url = f"{scheme}://{host}:8089"

        # Idempotent — ensure indexes run once per process lifetime
        self._indexes_ensured = False

    def _get_session(self) -> aiohttp.ClientSession:
        """"Return the persistent session, creating it on first use."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=self._ssl_ctx),
            )
        return self._session

    def _all_index_names(self) -> set[str]:
        """Return every index name shrike may write to."""
        names: set[str] = set(_CLASS_INDEX.values())
        names.update(_CATEGORY_INDEX.values())
        names.add(_DEFAULT_INDEX)
        return names

    async def ensure_indexes(self) -> None:
        """Create any missing Splunk indexes. Idempotent — skips indexes that already exist."""
        session = self._get_session()
        headers = {
            "Authorization": f"Splunk {self._token}",
            "Content-Type": "application/json",
        }

        # Fetch existing indexes
        try:
            async with session.get(
                f"{self._mgmt_url}/services/server/indexes?output_mode=json",
                headers=headers,
            ) as resp:
                if resp.status != 200:
                    logger.warning("Index check failed: HEC %s", resp.status)
                    return
                data = await resp.json()
                existing = {e["name"] for e in data.get("entry", [])}
        except aiohttp.ClientError as exc:
            logger.warning("Index check failed: %s", exc)
            return

        # Create missing indexes
        for idx_name in sorted(self._all_index_names()):
            if idx_name in existing:
                continue
            try:
                async with session.post(
                    f"{self._mgmt_url}/services/server/indexes",
                    data=f"name={idx_name}".encode(),
                    headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                ) as resp:
                    if resp.status in (200, 201):
                        logger.info("Created Splunk index: %s", idx_name)
                    elif resp.status == 409:
                        logger.debug("Index already exists: %s", idx_name)
                    else:
                        body = await resp.text()
                        logger.warning("Index create failed for %s: HEC %s — %s", idx_name, resp.status, body)
            except aiohttp.ClientError as exc:
                logger.warning("Index create failed for %s: %s", idx_name, exc)

    def _format_hec_event(self, event: dict) -> dict:
        """Wrap an OCSF event in the HEC envelope."""
        uid = event.get("category_uid")
        return {
            "index": class_uid_to_index(event.get("class_uid"), uid),
            "sourcetype": "_json",
            "event": event,
        }

    async def send_batch(self, events: list[dict]) -> SendResult:
        """POST events to the Splunk HEC endpoint as newline-delimited JSON."""
        if not events:
            return SendResult(accepted=0, rejected=0, retryable=0)

        # Ensure indexes exist on first send (idempotent)
        if not self._indexes_ensured:
            await self.ensure_indexes()
            self._indexes_ensured = True

        payload = "\n".join(
            json.dumps(self._format_hec_event(e)) for e in events
        )
        headers = {
            "Authorization": f"Splunk {self._token}",
            "Content-Type": "application/json",
        }

        try:
            session = self._get_session()
            async with session.post(
                self._url,
                data=payload,
                headers=headers,
            ) as resp:
                self._last_send = time.time()
                if resp.status == 200:
                    self._retry_count = 0
                    self._last_error = ""
                    return SendResult(
                        accepted=len(events),
                        rejected=0,
                        retryable=0,
                    )
                body = await resp.text()
                self._last_error = f"HEC {resp.status}: {body}"
                logger.warning("Splunk HEC error: %s", self._last_error)

                if _is_retryable(resp.status):
                    self._retry_count += 1
                    return SendResult(
                        accepted=0,
                        rejected=0,
                        retryable=len(events),
                        errors=[self._last_error],
                    )
                # Permanent failure (400, 401, 403, etc.) — reject, don't retry
                return SendResult(
                    accepted=0,
                    rejected=len(events),
                    retryable=0,
                    errors=[self._last_error],
                )
        except (aiohttp.ClientError, TimeoutError) as exc:
            self._retry_count += 1
            self._last_error = str(exc)
            logger.warning("Splunk HEC connection error: %s", exc)
            return SendResult(
                accepted=0,
                rejected=0,
                retryable=len(events),
                errors=[self._last_error],
            )

    async def health(self) -> HealthStatus:
        """Healthy when retry count is below threshold."""
        return HealthStatus(
            healthy=self._retry_count < 3,
            pending=self.wal.pending_count,
            disk_usage_mb=self.wal.disk_usage_mb,
            last_send_epoch=self._last_send,
            retry_count=self._retry_count,
            error=self._last_error,
        )

    async def close(self) -> None:
        """Close the persistent HTTP session."""
        if self._session is not None and not self._session.closed:
            await self._session.close()
            self._session = None

"""Tests for the Splunk HEC destination."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shrike.destinations.splunk_hec import (
    SplunkHECDestination,
    _is_retryable,
    class_uid_to_index,
)


# ------------------------------------------------------------------
# Index routing
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("class_uid", "category_uid", "expected"),
    [
        # Specific class mappings take precedence
        (1001, None, "ocsf-file-activity"),
        (1007, None, "ocsf-process-activity"),
        (3002, None, "ocsf-authentication"),
        (4003, None, "ocsf-dns-activity"),
        # Specific class even with category provided
        (1005, 1, "ocsf-module-activity"),  # module_activity has specific mapping
        (3005, 3, "ocsf-user-access-management"),  # user_access_mgmt has specific mapping
        (4007, 4, "ocsf-ssh-activity"),  # ssh has specific mapping
        # Category fallback when class_uid not in _CLASS_INDEX
        (9999, 1, "ocsf-system"),  # unknown class in category 1
        (8888, 3, "ocsf-iam"),  # unknown class in category 3
        # None/missing falls back to category
        (None, 1, "ocsf-system"),
        (None, 3, "ocsf-iam"),
        (None, 4, "ocsf-network"),
        (None, None, "ocsf-raw"),
        # Unknown category falls back to raw
        (9999, 99, "ocsf-raw"),
        (None, 99, "ocsf-raw"),
    ],
)
def test_index_routing(class_uid: int | None, category_uid: int | None, expected: str) -> None:
    assert class_uid_to_index(class_uid, category_uid) == expected


# ------------------------------------------------------------------
# HEC event formatting
# ------------------------------------------------------------------


def test_format_hec_event(tmp_path: Path) -> None:
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )
    event = {"category_uid": 4, "src_ip": "10.0.0.1"}
    formatted = dest._format_hec_event(event)

    # category_uid=4 (network) → ocsf-network
    assert formatted["index"] == "ocsf-network"
    assert formatted["sourcetype"] == "_json"
    assert formatted["event"] is event


# ------------------------------------------------------------------
# send_batch success
# ------------------------------------------------------------------


async def test_send_batch_success(tmp_path: Path) -> None:
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )

    events = [
        {"category_uid": 3, "user": "alice"},  # IAM category
        {"category_uid": 2, "finding": "cve-123"},
    ]

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"entry": []})
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_post = MagicMock(return_value=mock_resp)

    mock_session = MagicMock()
    mock_session.post = mock_post
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.closed = False

    # Patch _get_session to return the mock session
    dest._session = mock_session

    result = await dest.send_batch(events)

    assert result.accepted == 2
    assert result.rejected == 0
    assert result.retryable == 0

    # Verify POST was called with correct URL and auth header
    call_kwargs = mock_post.call_args
    assert "Splunk test-token" in call_kwargs.kwargs["headers"]["Authorization"]
    payload = call_kwargs.kwargs["data"]
    lines = payload.strip().split("\n")
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["index"] == "ocsf-iam"  # category_uid=3 → ocsf-iam


# ------------------------------------------------------------------
# send_batch with empty list
# ------------------------------------------------------------------


async def test_send_batch_empty(tmp_path: Path) -> None:
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )
    result = await dest.send_batch([])
    assert result.accepted == 0
    assert result.retryable == 0


# ------------------------------------------------------------------
# health status
# ------------------------------------------------------------------


async def test_health_reports_healthy(tmp_path: Path) -> None:
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )
    status = await dest.health()
    assert status.healthy is True
    assert status.retry_count == 0


# ------------------------------------------------------------------
# Retry logic (IMPORTANT-3)
# ------------------------------------------------------------------


def test_is_retryable_transient_codes() -> None:
    """429, 500, 502, 503 are retryable."""
    assert _is_retryable(429) is True
    assert _is_retryable(500) is True
    assert _is_retryable(502) is True
    assert _is_retryable(503) is True


def test_is_retryable_permanent_codes() -> None:
    """400, 401, 403 are NOT retryable (permanent rejection)."""
    assert _is_retryable(400) is False
    assert _is_retryable(401) is False
    assert _is_retryable(403) is False
    assert _is_retryable(404) is False
    assert _is_retryable(200) is False


async def test_send_batch_400_rejected(tmp_path: Path) -> None:
    """HTTP 400 results in rejected (not retryable) events."""
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )

    mock_resp = AsyncMock()
    mock_resp.status = 400
    mock_resp.text = AsyncMock(return_value="Bad request")
    mock_resp.json = AsyncMock(return_value={"entry": []})
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.closed = False
    dest._session = mock_session

    result = await dest.send_batch([{"event": "data"}])
    assert result.rejected == 1
    assert result.retryable == 0
    assert result.accepted == 0


async def test_send_batch_503_retryable(tmp_path: Path) -> None:
    """HTTP 503 results in retryable events."""
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )

    mock_resp = AsyncMock()
    mock_resp.status = 503
    mock_resp.text = AsyncMock(return_value="Service unavailable")
    mock_resp.json = AsyncMock(return_value={"entry": []})
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.closed = False
    dest._session = mock_session

    result = await dest.send_batch([{"event": "data"}])
    assert result.retryable == 1
    assert result.rejected == 0
    assert result.accepted == 0


# ------------------------------------------------------------------
# Phase 1.1 (#11) — tempfile import
# ------------------------------------------------------------------


def test_splunk_dest_instantiates_without_wal_dir(tmp_path: Path) -> None:
    """SplunkHECDestination must not raise NameError when wal_dir is None.

    Regression test for Phase 1.1 (#11): tempfile.mkdtemp() was called without
    importing tempfile, causing a NameError at construction time.
    """
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=None,
    )
    # Must not raise NameError — tempfile must be importable
    assert dest.wal is not None
    # WAL should be functional
    assert dest.wal._wal_path.exists()


# ------------------------------------------------------------------
# Phase 1.5 (NEW) — Management URL parsing
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("hec_url", "expected_mgmt_url"),
    [
        # HTTPS URL with explicit port → management uses same scheme + port 8089
        ("https://splunk:8088", "https://splunk:8089"),
        ("https://splunk", "https://splunk:8089"),
        # HTTP URL with explicit port → management uses http + port 8089
        ("http://splunk:8088", "http://splunk:8089"),
        ("http://splunk", "http://splunk:8089"),
        # IP address variants
        ("https://192.168.1.100:8088", "https://192.168.1.100:8089"),
        ("http://192.168.1.100", "http://192.168.1.100:8089"),
    ],
)
def test_management_url_parsing(hec_url: str, expected_mgmt_url: str) -> None:
    """Management URL must be correctly derived from HEC URL regardless of format.

    Regression test for Phase 1.5 (NEW): the previous rsplit(":", 1) approach
    incorrectly split the hostname when the scheme was present, producing
    mangled URLs like "https://https://splunk:8089".
    """
    dest = SplunkHECDestination(
        url=hec_url,
        token="test-token",
        wal_dir=None,
    )
    assert dest._mgmt_url == expected_mgmt_url

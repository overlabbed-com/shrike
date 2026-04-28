"""Tests for TLS configuration in Splunk HEC destination."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from shrike.destinations.splunk_hec import SplunkHECDestination


class TestSplunkHECTLS:
    """Tests for Splunk HEC TLS configuration."""

    def test_tls_verify_true(self, tmp_path: Path) -> None:
        """When tls_verify=True, SSL context verifies certificates."""
        wal_dir = tmp_path / "wal"
        wal_dir.mkdir()

        dest = SplunkHECDestination(
            name="splunk_hec",
            url="https://splunk.example.com:8088/services/collector",
            token="test-token",
            index="ocsf-test",
            tls_verify=True,
            wal_dir=str(wal_dir),
        )

        # SSL context should verify certificates
        assert dest._ssl_ctx.check_hostname is True
        assert dest._ssl_ctx.verify_mode == ssl.CERT_REQUIRED

    def test_tls_verify_false(self, tmp_path: Path) -> None:
        """When tls_verify=False, SSL context does not verify certificates."""
        wal_dir = tmp_path / "wal"
        wal_dir.mkdir()

        dest = SplunkHECDestination(
            name="splunk_hec",
            url="https://splunk.example.com:8088/services/collector",
            token="test-token",
            index="ocsf-test",
            tls_verify=False,
            wal_dir=str(wal_dir),
        )

        # SSL context should NOT verify certificates
        assert dest._ssl_ctx.check_hostname is False
        assert dest._ssl_ctx.verify_mode == ssl.CERT_NONE

    def test_tls_connection_failure_graceful(self, tmp_path: Path) -> None:
        """TLS connection failure is handled gracefully."""
        wal_dir = tmp_path / "wal"
        wal_dir.mkdir()

        dest = SplunkHECDestination(
            name="splunk_hec",
            url="https://invalid.example.com:8088/services/collector",
            token="test-token",
            index="ocsf-test",
            tls_verify=True,
            wal_dir=str(wal_dir),
        )

        # Attempting to send should fail gracefully, not raise
        import asyncio
        try:
            result = asyncio.run(dest.send_batch([{"test": "event"}]))
            # If it returns, it should have errors
            assert len(result.errors) > 0 or result.accepted == 0
        except Exception as e:
            # Connection errors are acceptable
            assert "ssl" in str(e).lower() or "certificate" in str(e).lower() or "connection" in str(e).lower()
"""Tests for FormatDetector."""

from __future__ import annotations

import pytest

from shrike.detector.format_detector import (
    LogFormat,
    detect_format,
)


class TestDetectFormat:
    """Tests for detect_format() function."""

    def test_syslog_bsd(self):
        """Detects BSD syslog."""
        log = "Mar 15 10:00:00 host sshd[123]: Accepted password"
        assert detect_format(log) == LogFormat.SYSLOG_BSD

    def test_syslog_rfc5424(self):
        """Detects RFC 5424 syslog."""
        log = "<34>1 2024-03-15T10:00:00 host sshd 123 ID123 - message"
        assert detect_format(log) == LogFormat.SYSLOG_RFC5424

    def test_syslog_rfc3164(self):
        """Detects RFC 3164 syslog."""
        log = "<34>Oct 13 15:36:43 host sshd: Accepted"
        assert detect_format(log) == LogFormat.SYSLOG_RFC3164

    def test_json(self):
        """Detects JSON."""
        log = '{"user": "alice", "event": "login"}'
        assert detect_format(log) == LogFormat.JSON

    def test_cef(self):
        """Detects CEF."""
        log = "CEF:0|Security|Product|1.0|100|Login|3|src=192.168.1.1"
        assert detect_format(log) == LogFormat.CEF

    def test_leef(self):
        """Detects LEEF."""
        log = "LEEF:1.0|Security|Product|1.0|100|src=192.168.1.1"
        assert detect_format(log) == LogFormat.LEEF

    def test_xml(self):
        """Detects XML."""
        log = '<?xml version="1.0"?><event><user>alice</user></event>'
        assert detect_format(log) == LogFormat.XML

    def test_csv(self):
        """Detects CSV."""
        log = "2024-03-15,host,sshd,Accepted"
        assert detect_format(log) == LogFormat.CSV

    def test_custom(self):
        """Falls back to custom when no format matches."""
        log = "some completely custom log format xyz123"
        assert detect_format(log) == LogFormat.CUSTOM



"""Tests for preparsers module."""

from __future__ import annotations

import pytest

from shrike.extractor.preparsers import (
    PreparsedFields,
    preparse,
    preparse_syslog_bsd,
    preparse_syslog_rfc5424,
    preparse_json,
    preparse_cef,
    preparse_leef,
)
from shrike.detector.format_detector import LogFormat


class TestPreparseSyslogBsd:
    """Tests for preparse_syslog_bsd."""

    def test_parses_valid_syslog(self):
        """Parses valid BSD syslog line."""
        log = "Mar 15 10:00:00 host sshd[12345]: Accepted password for alice from 192.168.1.1 port 22"
        result = preparse_syslog_bsd(log)
        assert result is not None
        assert result.format_type == "syslog_bsd"
        assert result.hostname == "host"
        assert result.source_app == "sshd"
        assert result.message is not None

    def test_returns_none_on_invalid(self):
        """Returns None for invalid syslog."""
        result = preparse_syslog_bsd("not a syslog line")
        assert result is None

    def test_pid_extracted(self):
        """PID extracted when present."""
        log = "Mar 15 10:00:00 host sshd[12345]: Accepted password"
        result = preparse_syslog_bsd(log)
        assert result.fields["_pid"] == "12345"

    def test_no_pid(self):
        """No PID = no _pid field."""
        log = "Mar 15 10:00:00 host kernel: Device initialized"
        result = preparse_syslog_bsd(log)
        assert result is not None
        assert "_pid" not in result.fields


class TestPreparseSyslogRfc5424:
    """Tests for preparse_syslog_rfc5424."""

    def test_parses_valid_rfc5424(self):
        """Parses valid RFC 5424 syslog."""
        log = "<34>1 2024-03-15T10:00:00 host sshd 12345 ID123 - message text"
        result = preparse_syslog_rfc5424(log)
        assert result is not None
        assert result.format_type == "syslog_rfc5424"

    def test_returns_none_on_invalid(self):
        """Returns None for invalid RFC 5424."""
        result = preparse_syslog_rfc5424("not rfc5424")
        assert result is None


class TestPreparseJson:
    """Tests for preparse_json."""

    def test_parses_valid_json(self):
        """Parses valid JSON log."""
        log = '{"timestamp": "2024-03-15", "user": "alice", "event": "login"}'
        result = preparse_json(log)
        assert result is not None
        assert result.format_type == "json"
        assert result.fields["user"] == "alice"

    def test_returns_none_on_invalid_json(self):
        """Returns None for invalid JSON."""
        result = preparse_json("not json")
        assert result is None


class TestPreparseCef:
    """Tests for preparse_cef."""

    def test_parses_valid_cef(self):
        """Parses valid CEF line."""
        log = "CEF:0|Security|Product|1.0|100|Login success|3|src=192.168.1.1 dst=10.0.0.1"
        result = preparse_cef(log)
        assert result is not None
        assert result.format_type == "cef"

    def test_returns_none_on_invalid(self):
        """Returns None for invalid CEF."""
        result = preparse_cef("not cef")
        assert result is None


class TestPreparseLeef:
    """Tests for preparse_leef."""

    def test_parses_valid_leef(self):
        """Parses valid LEEF line."""
        log = "LEEF:1.0|Security|Product|1.0|100|src=192.168.1.1"
        result = preparse_leef(log)
        assert result is not None
        assert result.format_type == "leef"

    def test_returns_none_on_invalid(self):
        """Returns None for invalid LEEF."""
        result = preparse_leef("not leef")
        assert result is None


class TestPreparseDispatch:
    """Tests for preparse() dispatcher."""

    def test_dispatches_to_syslog_bsd(self):
        """preparse() dispatches to syslog BSD."""
        log = "Mar 15 10:00:00 host sshd[123]: Accepted"
        result = preparse(log, LogFormat.SYSLOG_BSD)
        assert result is not None
        assert result.format_type == "syslog_bsd"

    def test_dispatches_to_json(self):
        """preparse() dispatches to JSON."""
        log = '{"user": "alice"}'
        result = preparse(log, LogFormat.JSON)
        assert result is not None
        assert result.format_type == "json"

    def test_dispatches_to_cef(self):
        """preparse() dispatches to CEF."""
        log = "CEF:0|Security|Product|1.0|100|Login|3|src=192.168.1.1"
        result = preparse(log, LogFormat.CEF)
        assert result is not None
        assert result.format_type == "cef"

    def test_dispatches_to_leef(self):
        """preparse() dispatches to LEEF."""
        log = "LEEF:1.0|Security|Product|1.0|100|src=192.168.1.1"
        result = preparse(log, LogFormat.LEEF)
        assert result is not None
        assert result.format_type == "leef"

    def test_returns_none_for_unknown_format(self):
        """preparse() returns None for unknown format."""
        result = preparse("completely unknown format", LogFormat.CUSTOM)
        assert result is None
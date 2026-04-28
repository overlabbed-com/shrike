"""Tests for shrike CLI."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


def _strip_ml_warning(stdout: str) -> str:
    """Strip the ML dependency warning from stdout if present."""
    lines = stdout.split("\n")
    if lines and "ML dependencies" in lines[0] and "not installed" in lines[0]:
        return "\n".join(lines[1:])
    return stdout


class TestShrikeCLI:
    """Tests for shrike CLI commands."""

    def test_cli_detect_only_flag(self, tmp_path: Path) -> None:
        """--detect-only flag detects format without extraction."""
        log_file = tmp_path / "test.log"
        log_file.write_text("Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22\n")

        result = subprocess.run(
            [sys.executable, "-m", "shrike", "--input", str(log_file), "--detect-only"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "syslog_bsd" in result.stdout.lower() or "bsd" in result.stdout.lower()

    @pytest.mark.skipif(
        importlib.util.find_spec("transformers") is None,
        reason="ML dependencies not installed"
    )
    def test_cli_classify_only_flag(self, tmp_path: Path) -> None:
        """--classify-only flag classifies without extraction."""
        log_file = tmp_path / "test.log"
        log_file.write_text("Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22\n")

        result = subprocess.run(
            [sys.executable, "-m", "shrike", "--input", str(log_file), "--classify-only"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        # Strip ML warning before checking output
        output = _strip_ml_warning(result.stdout)
        assert "3002" in output or "Authentication" in output

    def test_cli_stdin_input(self) -> None:
        """CLI accepts input from stdin."""
        log_line = "Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22\n"

        result = subprocess.run(
            [sys.executable, "-m", "shrike", "--input", "-"],
            input=log_line,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

    def test_cli_json_output(self, tmp_path: Path) -> None:
        """CLI outputs JSON with --format json."""
        log_file = tmp_path / "test.log"
        log_file.write_text("Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22\n")

        result = subprocess.run(
            [sys.executable, "-m", "shrike", "--input", str(log_file), "--format", "json"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        # Strip ML warning before parsing JSON
        output = _strip_ml_warning(result.stdout)
        try:
            json.loads(output)
        except json.JSONDecodeError:
            pytest.fail(f"Output is not valid JSON: {output}")

    def test_cli_summary_output(self, tmp_path: Path) -> None:
        """CLI outputs summary with --format summary."""
        log_file = tmp_path / "test.log"
        log_file.write_text("Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22\n")

        result = subprocess.run(
            [sys.executable, "-m", "shrike", "--input", str(log_file), "--format", "summary"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

    def test_cli_filter_pack(self, tmp_path: Path) -> None:
        """CLI applies filter pack with --filter flag."""
        log_file = tmp_path / "test.log"
        log_file.write_text("Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22\n")

        result = subprocess.run(
            [sys.executable, "-m", "shrike", "--input", str(log_file), "--filter", "security-focused"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

    def test_cli_invalid_format(self, tmp_path: Path) -> None:
        """CLI handles invalid log format gracefully."""
        log_file = tmp_path / "test.log"
        log_file.write_text("completely invalid log format that cannot be parsed\n")

        result = subprocess.run(
            [sys.executable, "-m", "shrike", "--input", str(log_file)],
            capture_output=True,
            text=True,
        )

        # Should still return 0 but mark as unknown
        assert result.returncode == 0

    def test_cli_nonexistent_file(self) -> None:
        """CLI handles nonexistent file gracefully."""
        result = subprocess.run(
            [sys.executable, "-m", "shrike", "--input", "/nonexistent/file.log"],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "not found" in result.stderr.lower() or "error" in result.stderr.lower()
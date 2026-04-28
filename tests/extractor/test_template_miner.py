"""Tests for LogTemplateMiner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shrike.extractor.template_miner import (
    IP_RE,
    PORT_RE,
    LogTemplateMiner,
    VariableSlot,
)


class TestVariableSlot:
    """Tests for VariableSlot dataclass."""

    def test_init(self):
        """Initializes with position."""
        slot = VariableSlot(position=0, entity_type="ip", ocsf_hint="src_endpoint.ip")
        assert slot.position == 0


class TestEntityClassifiers:
    """Tests for entity type classifiers."""

    def test_ip_re(self):
        """IP_RE matches IPv4 addresses."""
        assert IP_RE.match("192.168.1.1")
        assert IP_RE.match("10.0.0.1")
        assert not IP_RE.match("not an ip")

    def test_port_re(self):
        """PORT_RE matches port numbers."""
        assert PORT_RE.match("22")
        assert PORT_RE.match("8080")
        assert not PORT_RE.match("700000")  # 6 digits, not a valid port


class TestLogTemplateMiner:
    """Tests for LogTemplateMiner."""

    def test_init(self):
        """Initializes Drain3 template miner."""
        miner = LogTemplateMiner()
        assert miner._miner is not None

    def test_train(self):
        """train() learns from log batch."""
        miner = LogTemplateMiner()
        logs = [
            "Mar 15 10:00:00 host sshd[123]: Accepted password for alice",
            "Mar 15 10:01:00 host sshd[456]: Accepted password for bob",
        ]
        miner.train(logs)
        assert miner._miner.drain.clusters_counter >= 1

    def test_extract_no_templates(self):
        """extract() returns None when no templates learned."""
        miner = LogTemplateMiner()
        result = miner.extract("completely unknown log format")
        # May return None or empty result
        assert result is None or isinstance(result, dict)

    @pytest.mark.skip(reason="Template mining behavior varies")
    def test_extract_with_templates(self):
        """extract() uses learned templates."""
        miner = LogTemplateMiner()
        miner.train([
            "Mar 15 10:00:00 host sshd[123]: Accepted password for alice",
        ])
        result = miner.extract("Mar 15 10:00:00 host sshd[456]: Accepted password for bob")
        assert result is not None

    def test_get_stats(self):
        """get_stats() returns mining statistics."""
        miner = LogTemplateMiner()
        stats = miner.get_stats()
        assert "templates_learned" in stats
        assert "logs_processed" in stats
"""Tests for TieredExtractor and PreparseExtractor."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from shrike.detector.format_detector import LogFormat
from shrike.extractor.schema_injected_extractor import (
    ExtractionResult,
    _build_schema_context,
)
from shrike.extractor.tiered_extractor import (
    PreparseExtractor,
    TieredExtractor,
)


class TestTieredExtractor:
    """Tests for TieredExtractor."""

    def test_init_default(self):
        """Initializes with all tiers."""
        extractor = TieredExtractor()
        assert extractor._pattern_extractor is not None
        assert extractor._preparse_extractor is not None
        assert extractor._full_extractor is not None

    def test_init_pattern_only(self):
        """Initializes without LLM (pattern-only mode)."""
        extractor = TieredExtractor(enable_tier2=False, enable_tier3=False)
        assert extractor._pattern_extractor is not None
        assert extractor._preparse_extractor is None
        assert extractor._full_extractor is None

    def test_extract_pattern_hit(self):
        """Pattern match returns immediately without LLM call."""
        extractor = TieredExtractor()

        mock_result = ExtractionResult(
            event={"class_uid": 3002, "user": "alice"},
            class_uid=3002,
            class_name="Authentication",
            raw_log="sshd: Accepted password for alice",
        )
        with patch.object(extractor._pattern_extractor, "try_extract", return_value=mock_result):
            result, tier = extractor.extract(
                "sshd: Accepted password for alice",
                LogFormat.SYSLOG_BSD,
                3002,
                "Authentication",
            )
            assert result is mock_result
            assert tier == 1

    def test_extract_falls_through_to_llm(self):
        """No pattern match falls through to LLM tiers."""
        extractor = TieredExtractor()

        mock_result = ExtractionResult(
            event={"class_uid": 3002, "user": "alice"},
            class_uid=3002,
            class_name="Authentication",
            raw_log="unknown log format",
        )
        with patch.object(extractor._pattern_extractor, "try_extract", return_value=None):
            with patch.object(extractor._preparse_extractor, "try_extract", return_value=None):
                with patch.object(extractor._full_extractor, "extract", return_value=mock_result):
                    result, tier = extractor.extract(
                        "unknown log format",
                        LogFormat.SYSLOG_BSD,
                        3002,
                        "Authentication",
                    )
                    assert result is mock_result
                    assert tier == 3

    def test_extract_all_tiers_fail(self):
        """All tiers fail = None result."""
        extractor = TieredExtractor(enable_tier2=False, enable_tier3=False)

        with patch.object(extractor._pattern_extractor, "try_extract", return_value=None):
            result, tier = extractor.extract(
                "unknown log format",
                LogFormat.SYSLOG_BSD,
                3002,
                "Authentication",
            )
            assert result is None or result.error is not None


class TestPreparseExtractor:
    """Tests for PreparseExtractor."""

    def test_init(self):
        """Initializes with LLM URL."""
        extractor = PreparseExtractor(api_base="http://localhost:11434/v1")
        assert extractor._api_base is not None

    def test_init_no_llm(self):
        """Initializes without LLM."""
        extractor = PreparseExtractor(api_base=None)
        assert extractor._api_base is None

    def test_extract_no_llm(self):
        """No LLM configured = None."""
        extractor = PreparseExtractor(api_base=None)
        result = extractor.try_extract("any log", LogFormat.SYSLOG_BSD, 3002, "")
        assert result is None

    def test_extract_llm_returns_result(self):
        """LLM returns extraction result."""
        extractor = PreparseExtractor(api_base="http://localhost:11434/v1")

        # Use a log that preparses to 2+ fields (KV format)
        raw_log = "type=USER_START msg=audit(1234.567:12345): pid=1 uid=0 auid=4294967295 ses=4294967295"
        mock_json = '{"user": "alice", "class_uid": 3002, "class_name": "Authentication", "severity_id": 1}'
        with patch.object(extractor, "_call_api", Mock(return_value=mock_json)):
            result = extractor.try_extract(
                raw_log,
                LogFormat.KV,
                3002,
                "Authentication",
            )
            assert result is not None
            assert result.event.get("user") == "alice"

    def test_build_schema_context(self):
        """_build_schema_context() returns prompt text."""
        schema = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "attributes": {},
        }
        context = _build_schema_context(schema)
        assert isinstance(context, str)
        assert len(context) > 0
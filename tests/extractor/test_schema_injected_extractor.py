"""Tests for SchemaInjectedExtractor and ExtractionResult."""

from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch

import pytest

from shrike.extractor.schema_injected_extractor import (
    ExtractionResult,
    SchemaInjectedExtractor,
    _build_schema_context,
    _extract_json,
)


class TestExtractionResult:
    """Tests for ExtractionResult dataclass."""

    def test_init(self):
        """Initializes with required fields."""
        result = ExtractionResult(
            event={"class_uid": 3002},
            class_uid=3002,
            class_name="Authentication",
            raw_log="test",
        )
        assert result.event["class_uid"] == 3002
        assert result.class_uid == 3002

    def test_init_with_optional_fields(self):
        """Initializes with optional fields."""
        result = ExtractionResult(
            event={"class_uid": 3002},
            class_uid=3002,
            class_name="Authentication",
            raw_log="test",
            extraction_time_ms=500.0,
            retries=1,
            error=None,
        )
        assert result.extraction_time_ms == 500.0
        assert result.retries == 1

    def test_confidence_dict(self):
        """confidence is a dict mapping field → derivation method."""
        result = ExtractionResult(
            event={"class_uid": 3002, "user": "alice"},
            class_uid=3002,
            class_name="Authentication",
            raw_log="test",
            confidence={"user": "pattern", "src_endpoint.ip": "alias"},
        )
        assert result.confidence["user"] == "pattern"
        assert result.confidence["src_endpoint.ip"] == "alias"


class TestSchemaInjectedExtractor:
    """Tests for SchemaInjectedExtractor."""

    def test_init_no_llm(self):
        """Initializes without LLM (disabled)."""
        extractor = SchemaInjectedExtractor(api_base=None)
        assert extractor._api_base is None

    def test_extract_no_llm(self):
        """No LLM = None."""
        extractor = SchemaInjectedExtractor(api_base=None)
        result = extractor.extract("any log", 3002, "")
        assert result.error is not None

    def test_extract_with_mock_llm(self):
        """"LLM returns extraction result."""
        extractor = SchemaInjectedExtractor(api_base="http://localhost:11434/v1")

        # _call_api returns a JSON string that _extract_json parses
        mock_json_response = '{"user": "alice", "class_uid": 3002, "class_name": "Authentication", "severity_id": 1}'
        with patch.object(extractor, "_call_api", Mock(return_value=mock_json_response)):
            result = extractor.extract("sshd: Accepted password for alice", 3002, "")
            assert result.event.get("user") == "alice"
            assert result.class_uid == 3002


class TestBuildSchemaContext:
    """Tests for _build_schema_context."""

    def test_returns_string(self):
        """Returns a string schema description."""
        schema = {"class_uid": 3002, "class_name": "Authentication"}
        context = _build_schema_context(schema)
        assert isinstance(context, str)
        assert len(context) > 0


class TestExtractJson:
    """Tests for _extract_json helper."""

    def test_extracts_json_from_response(self):
        """Extracts JSON object from LLM response text."""
        response = 'Here is the extraction:\n{"class_uid": 3002, "user": "alice"}\nDone.'
        result = _extract_json(response)
        assert result == {"class_uid": 3002, "user": "alice"}

    def test_handles_markdown_code_block(self):
        """Handles markdown code block wrapper."""
        response = '```json\n{"class_uid": 3002}\n```'
        result = _extract_json(response)
        assert result == {"class_uid": 3002}

    def test_returns_none_on_invalid_json(self):
        """Returns None on invalid JSON."""
        response = "This is not JSON at all"
        result = _extract_json(response)
        assert result is None
"""Tests for EmbeddingFieldMapper."""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

from shrike.extractor.embedding_field_mapper import (
    EmbeddingFieldMapper,
    _normalize_field_name,
)

_sentence_transformers_available = importlib.util.find_spec('sentence_transformers') is not None

pytestmark = pytest.mark.skipif(
    not _sentence_transformers_available,
    reason='sentence_transformers not installed',
)


class TestNormalizeFieldName:
    """Tests for _normalize_field_name helper."""

    def test_dots_replaced(self):
        """Dots replaced with spaces."""
        assert _normalize_field_name("src_endpoint.ip") == "src endpoint ip"

    def test_underscores_replaced(self):
        """Underscores replaced with spaces."""
        assert _normalize_field_name("source_address") == "source address"

    def test_camel_case_split(self):
        """CamelCase split into separate words."""
        assert _normalize_field_name("sourceAddress") == "source address"
        assert _normalize_field_name("callerIpAddress") == "caller ip address"

    def test_mixed(self):
        """Mixed separators handled."""
        result = _normalize_field_name("src_endpoint.ip_address")
        assert "." not in result
        assert "_" not in result


class TestEmbeddingFieldMapper:
    """Tests for EmbeddingFieldMapper."""

    def test_init_no_model(self):
        """Initializes without model (embedding disabled)."""
        mapper = EmbeddingFieldMapper(index_path=None)
        assert mapper._model is None

    def test_map_field_no_model(self):
        """No model = None."""
        mapper = EmbeddingFieldMapper(index_path=None)
        result = mapper.map_field("sourceAddress")
        assert result is None

    def test_get_stats(self):
        """get_stats() returns statistics."""
        mapper = EmbeddingFieldMapper(index_path=None)
        stats = mapper.get_stats()
        assert "model_loaded" in stats
        assert "embedding_count" in stats
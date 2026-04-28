"""Tests for NERExtractor."""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

from shrike.extractor.ner_extractor import NERExtractor, ENTITY_OCSF_MAP

_transformers_available = importlib.util.find_spec('transformers') is not None

pytestmark = pytest.mark.skipif(
    not _transformers_available,
    reason='transformers not installed',
)


class TestNERExtractor:
    """Tests for NERExtractor."""

    def test_init_without_model(self):
        """Initializes without model (pattern-only mode)."""
        extractor = NERExtractor(model_path=None)
        assert extractor._model is None
        assert extractor._tokenizer is None

    def test_entity_ocsf_map_complete(self):
        """ENTITY_OCSF_MAP has all expected entity types."""
        assert "IP" in ENTITY_OCSF_MAP
        assert "PORT" in ENTITY_OCSF_MAP
        assert "USER" in ENTITY_OCSF_MAP
        assert "HOSTNAME" in ENTITY_OCSF_MAP
        assert "PROCESS" in ENTITY_OCSF_MAP

    def test_entity_ocsf_map_values_are_ocsf_fields(self):
        """ENTITY_OCSF_MAP values are valid OCSF field paths."""
        for entity_type, field_path in ENTITY_OCSF_MAP.items():
            assert isinstance(field_path, str)
            assert "." in field_path or field_path in ("user", "status", "time", "activity_name")

    @patch("shrike.extractor.ner_extractor.ENTITY_OCSF_MAP", {"USER": "user", "IP": "src_endpoint.ip"})
    def test_extract_returns_dict(self):
        """extract() returns a dict with entity → OCSF field mappings."""
        extractor = NERExtractor(model_path=None)
        # When no model, returns empty
        result = extractor.extract("test log line")
        assert isinstance(result, dict)

    def test_extract_batch(self):
        """extract_batch() processes multiple logs."""
        extractor = NERExtractor(model_path=None)
        logs = ["line 1", "line 2", "line 3"]
        results = extractor.extract_batch(logs)
        assert len(results) == 3

    def test_get_stats(self):
        """get_stats() returns NER statistics."""
        extractor = NERExtractor(model_path=None)
        stats = extractor.get_stats()
        assert "model_loaded" in stats
        assert "inference_count" in stats
        assert "avg_latency_ms" in stats
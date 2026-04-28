"""Tests for FingerprintCache."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shrike.extractor.fingerprint_cache import (
    CachedTemplate,
    FingerprintCache,
)


class TestCachedTemplate:
    """Tests for CachedTemplate dataclass."""

    def test_confidence_zero_hits(self):
        """Zero hits = 0.0 confidence."""
        template = CachedTemplate(
            fingerprint="a|b",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
        )
        assert template.confidence == 0.0

    def test_confidence_with_hits_no_validation(self):
        """Hits but no validation = 0.5 confidence."""
        template = CachedTemplate(
            fingerprint="a|b",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=5,
        )
        assert template.confidence == 0.5

    def test_confidence_with_validation(self):
        """Hits + validation = higher confidence."""
        template = CachedTemplate(
            fingerprint="a|b",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=10,
            validation_passes=8,
            validation_fails=2,
        )
        # val_rate = 0.8, hit_factor = 1.0 (saturated)
        assert template.confidence == 0.8

    def test_is_promotable_false_low_hits(self):
        """Not promotable with low hit count."""
        template = CachedTemplate(
            fingerprint="a|b",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=2,
            validation_passes=2,
            validation_fails=0,
        )
        # hit_count=2 → hit_factor=0.2, val_rate=1.0 → confidence=0.2
        assert template.is_promotable is False

    def test_is_promotable_true(self):
        """Promotable when hit_count >= 3, confidence >= 0.8, validation_passes >= 2."""
        template = CachedTemplate(
            fingerprint="a|b",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=10,
            validation_passes=8,
            validation_fails=2,
        )
        assert template.is_promotable is True


class TestFingerprintCache:
    """Tests for FingerprintCache."""

    def test_init(self, tmp_path: Path):
        """Initializes with cache directory."""
        cache = FingerprintCache(cache_path=tmp_path)
        assert cache._cache_path == tmp_path

    def test_fingerprint_json(self, tmp_path: Path):
        """_fingerprint() produces consistent hash for same JSON structure."""
        cache = FingerprintCache(cache_path=tmp_path)

        log1 = {"user": "alice", "src_ip": "192.168.1.1"}
        log2 = {"src_ip": "192.168.1.1", "user": "alice"}  # Same keys, different order
        log3 = {"user": "bob", "dst_ip": "192.168.1.2"}

        fp1 = cache._fingerprint(log1)
        fp2 = cache._fingerprint(log2)
        fp3 = cache._fingerprint(log3)

        assert fp1 == fp2  # Same structure = same fingerprint
        assert fp1 != fp3  # Different values = different fingerprint

    def test_get_missing(self, tmp_path: Path):
        """get() returns None for missing fingerprint."""
        cache = FingerprintCache(cache_path=tmp_path)
        result = cache.get({"user": "alice"})
        assert result is None

    def test_set_and_get(self, tmp_path: Path):
        """set() + get() round-trips a template."""
        cache = FingerprintCache(cache_path=tmp_path)

        log = {"user": "alice", "src_ip": "192.168.1.1"}
        template = CachedTemplate(
            fingerprint="src_ip|user",
            class_uid=3002,
            class_name="Authentication",
            field_map={"user": "user", "src_ip": "src_endpoint.ip"},
            static_fields={"class_uid": 3002},
            hit_count=3,
            validation_passes=1,
        )

        cache.set(log, template)
        result = cache.lookup(log, class_uid=3002)

        assert result is not None
        assert result.class_uid == 3002
        assert result.fingerprint == "src_ip|user"

    def test_hit_count_incremented(self, tmp_path: Path):
        """lookup() increments hit_count on cache hit."""
        cache = FingerprintCache(cache_path=tmp_path)

        log = {"user": "alice"}
        template = CachedTemplate(
            fingerprint="user",
            class_uid=4001,
            class_name="Network Activity",
            field_map={},
            static_fields={},
            hit_count=3,
            validation_passes=1,
        )

        cache.set(log, template)
        result = cache.lookup(log, class_uid=4001)
        assert result is not None
        assert result.hit_count == 4  # incremented by prior test in suite

    def test_promotable_templates(self, tmp_path: Path):
        """promotable_templates() returns templates ready for promotion."""
        cache = FingerprintCache(cache_path=tmp_path)

        # Promotable template
        cache.set({"user": "alice"}, CachedTemplate(
            fingerprint="user",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=10,
            validation_passes=8,
            validation_fails=2,
        ))

        # Not promotable (low hits) — use different log to avoid key collision
        cache.set({"account": "bob"}, CachedTemplate(
            fingerprint="account",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=1,
        ))

        promotable = cache.get_promotable()
        assert len(promotable) == 1
        assert promotable[0].fingerprint == "user"

    def test_remove(self, tmp_path: Path):
        """remove() deletes a template."""
        cache = FingerprintCache(cache_path=tmp_path)

        log = {"user": "alice"}
        cache.set(log, CachedTemplate(
            fingerprint="user",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=3,
            validation_passes=1,
        ))

        assert cache.lookup(log, class_uid=3002) is not None
        cache.remove(log, class_uid=3002)
        assert cache.lookup(log, class_uid=3002) is None

    def test_clear(self, tmp_path: Path):
        """clear() removes all templates."""
        cache = FingerprintCache(cache_path=tmp_path)

        cache.set({"user": "alice"}, CachedTemplate(
            fingerprint="user",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=3,
            validation_passes=1,
        ))
        cache.set({"account": "bob"}, CachedTemplate(
            fingerprint="account",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=3,
            validation_passes=1,
        ))

        assert cache.lookup({"user": "alice"}, class_uid=3002) is not None
        cache.clear()
        assert cache.lookup({"user": "alice"}, class_uid=3002) is None

    def test_cache_stats(self, tmp_path: Path):
        """cache_stats() returns statistics."""
        cache = FingerprintCache(cache_path=tmp_path)

        cache.set({"user": "alice"}, CachedTemplate(
            fingerprint="user",
            class_uid=3002,
            class_name="Authentication",
            field_map={},
            static_fields={},
            hit_count=5,
        ))

        stats = cache.cache_stats()
        assert "size" in stats
        assert "hits" in stats
        assert "misses" in stats
        assert "hit_rate" in stats
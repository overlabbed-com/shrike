"""Tests for FilterEngine."""

from __future__ import annotations

from pathlib import Path

import pytest

from shrike.filter.filter_engine import FilterEngine, FilterPack, FilterResult


class TestFilterPack:
    """Tests for FilterPack."""

    def test_from_yaml(self, tmp_path: Path):
        """Loads filter pack from YAML."""
        yaml_content = """
name: test-pack
description: Test filter pack
rules:
  - keep: {classes: [3002]}
  - drop: {all: true}
"""
        path = tmp_path / "test.yaml"
        path.write_text(yaml_content)

        pack = FilterPack.from_yaml(path)
        assert pack.name == "test-pack"
        assert pack.description == "Test filter pack"
        assert len(pack.rules) == 2


class TestFilterEngine:
    """Tests for FilterEngine."""

    def test_init(self):
        """Initializes with filter packs directory."""
        engine = FilterEngine()
        assert engine._packs == {}

    def test_load_pack(self, tmp_path: Path):
        """Loads a filter pack."""
        yaml_content = """
name: test
rules:
  - keep: {classes: [3002]}
"""
        path = tmp_path / "test.yaml"
        path.write_text(yaml_content)

        engine = FilterEngine(packs_dir=tmp_path)
        assert "test" in engine._packs

    def test_evaluate_keep_class(self, tmp_path: Path):
        """Keeps events matching class filter."""
        yaml_content = """
name: security-focused
rules:
  - keep: {classes: [3002]}
  - drop: {all: true}
"""
        path = tmp_path / "security-focused.yaml"
        path.write_text(yaml_content)

        engine = FilterEngine(packs_dir=tmp_path)
        engine.set_active("security-focused")
        result = engine.evaluate(3002)
        assert result.action == "keep"

    def test_evaluate_drop_class(self, tmp_path: Path):
        """Drops events not matching class filter."""
        yaml_content = """
name: security-focused
rules:
  - keep: {classes: [3002]}
  - drop: {all: true}
"""
        path = tmp_path / "security-focused.yaml"
        path.write_text(yaml_content)

        engine = FilterEngine(packs_dir=tmp_path)
        engine.set_active("security-focused")
        result = engine.evaluate(0)
        assert result.action == "drop"

    def test_evaluate_no_pack(self):
        """No pack = default keep."""
        engine = FilterEngine()
        result = engine.evaluate(3002)
        assert result.action == "keep"

    def test_list_packs(self, tmp_path: Path):
        """Lists available filter packs."""
        yaml_content = """
name: test-pack
rules:
  - keep: {all: true}
"""
        path = tmp_path / "test-pack.yaml"
        path.write_text(yaml_content)

        engine = FilterEngine(packs_dir=tmp_path)
        packs = engine.available_packs
        assert isinstance(packs, list)
        assert "test-pack" in packs

    def test_get_stats(self):
        """get_stats() returns statistics."""
        engine = FilterEngine()
        engine.evaluate(3002)
        engine.evaluate(3003)
        stats = engine.get_stats()
        assert "packs_loaded" in stats
        assert "evaluations" in stats
        assert stats["evaluations"] == 2
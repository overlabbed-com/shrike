"""Tests for the 8 evaluation dimensions and measure_all() orchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from shrike.evaluate.dimensions import (
    measure_all,
    measure_breadth,
    measure_accuracy,
    measure_schema_compliance,
    measure_relationship_integrity,
    measure_ground_truth_quality,
    measure_cache_quality,
    measure_type_fidelity,
    measure_observables,
)
from shrike.evaluate.types import DimensionScore


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_result(
    fields: dict,
    class_uid: int = 3002,
    confidence_method: str = "pattern",
):
    """Create a mock (ExtractionResult, gt_record) tuple."""
    from shrike.extractor.schema_injected_extractor import ExtractionResult
    # Support both flat keys (src_endpoint.ip=val) and nested dicts
    event = {"class_uid": class_uid}
    confidence = {}
    for k, v in fields.items():
        if "." in k:
            # Flat key like src_endpoint.ip → nested dict
            parts = k.split(".", 1)
            if parts[0] not in event:
                event[parts[0]] = {}
            event[parts[0]][parts[1]] = v
            confidence[k] = confidence_method
        else:
            event[k] = v
            confidence[k] = confidence_method
    result = ExtractionResult(
        event=event,
        class_uid=class_uid,
        class_name="Authentication",
        raw_log="test log",
        confidence=confidence,
    )
    gt = {"class_uid": class_uid, "raw_log": "test log"}
    return (result, gt)


# ------------------------------------------------------------------
# Dimension 1: Breadth
# ------------------------------------------------------------------


def test_measure_breadth_excellent() -> None:
    """5+ pattern/alias fields = excellent."""
    results = [
        _make_result({"user": "admin", "src_ip": "1.2.3.4", "port": 22, "dst_ip": "5.6.7.8", "result": "success"}),
    ]
    score = measure_breadth(results)
    assert score.name == "breadth"
    assert score.score == 100.0
    assert score.metadata["excellent"] == 1


def test_measure_breadth_partial() -> None:
    """1-2 fields = partial (below useful threshold)."""
    results = [
        _make_result({"user": "admin", "result": "success"}),
    ]
    score = measure_breadth(results)
    assert score.score == 0.0
    assert score.metadata["partial"] == 1


def test_measure_breadth_unmatched() -> None:
    """None result = unmatched."""
    results = [(None, {"class_uid": 3002, "raw_log": "test"})]
    score = measure_breadth(results)
    assert score.metadata["unmatched"] == 1


def test_measure_breadth_empty_list() -> None:
    """Empty results = 0 score."""
    score = measure_breadth([])
    assert score.score == 0.0
    assert score.total == 0


# ------------------------------------------------------------------
# Dimension 2: Accuracy
# ------------------------------------------------------------------


def test_measure_accuracy_all_correct(tmp_path) -> None:
    """All fields match golden = 100 score."""
    from shrike.extractor.pattern_extractor import PatternExtractor
    extractor = PatternExtractor()

    golden_logs = [
        {
            "raw_log": "sshd[123]: Accepted password for admin from 1.2.3.4",
            "class_uid": 3002,
            "expected": {},
        },
    ]

    score = measure_accuracy(extractor, golden_logs)
    assert score.name == "accuracy"
    # Score is 0 if no expected fields matched (all golden have empty expected)
    assert score.total == 0


def test_measure_accuracy_with_expected_fields(tmp_path) -> None:
    """Accuracy checks expected field values against extracted values."""
    from shrike.extractor.pattern_extractor import PatternExtractor
    extractor = PatternExtractor()

    # A log where we can verify specific field extraction
    golden_logs = [
        {
            "raw_log": "sshd[123]: Accepted password for admin from 1.2.3.4 port 22",
            "class_uid": 3002,
            "expected": {"actor.user.name": "admin"},
        },
    ]

    score = measure_accuracy(extractor, golden_logs)
    assert score.name == "accuracy"
    assert "golden_logs_tested" in score.metadata


# ------------------------------------------------------------------
# Dimension 3: Schema Compliance
# ------------------------------------------------------------------


def test_measure_schema_compliance_valid() -> None:
    """Valid OCSF event = 100 score."""
    from shrike.validator.ocsf_validator import OCSFValidator
    validator = OCSFValidator()

    result, gt = _make_result({"class_uid": 3002, "activity_id": 1, "status": "Success"})
    score = measure_schema_compliance([(result, gt)], validator)
    assert score.name == "schema_compliance"


def test_measure_schema_compliance_skips_none() -> None:
    """None results are skipped (not counted as failures)."""
    from shrike.validator.ocsf_validator import OCSFValidator
    validator = OCSFValidator()
    results = [(None, {"class_uid": 3002})]
    score = measure_schema_compliance(results, validator)
    assert score.total == 0


# ------------------------------------------------------------------
# Dimension 4: Relationship Integrity
# ------------------------------------------------------------------


def test_measure_relationship_integrity_paired() -> None:
    """Both endpoint fields present = paired."""
    results = [
        _make_result({
            "src_endpoint.ip": "1.2.3.4",
            "src_endpoint.port": 22,
            "dst_endpoint.ip": "5.6.7.8",
            "dst_endpoint.port": 443,
        }),
    ]
    score = measure_relationship_integrity(results)
    assert score.name == "relationship_integrity"
    assert score.metadata["paired"] == 2  # src and dst pairs


def test_measure_relationship_integrity_missed() -> None:
    """One field present, partner extractable but missing = extraction miss."""
    # A raw_log that contains the port number but it wasn't extracted
    result, gt = _make_result({
        "src_endpoint.ip": "1.2.3.4",
        "raw_log": "sshd[123]: Accepted password for admin from 1.2.3.4 port 22",
    })
    gt["raw_log"] = "sshd[123]: Accepted password for admin from 1.2.3.4 port 22"
    results = [(result, gt)]
    score = measure_relationship_integrity(results)
    assert score.name == "relationship_integrity"
    # src_endpoint.ip present, src_endpoint.port extractable from raw_log but not extracted → missed


def test_measure_relationship_integrity_sparse() -> None:
    """Partner not in raw_log = structural sparsity (neutral)."""
    result, gt = _make_result({"src_endpoint.ip": "1.2.3.4"})
    gt["raw_log"] = "sshd[123]: Accepted password for admin from 1.2.3.4"
    results = [(result, gt)]
    score = measure_relationship_integrity(results)
    assert score.name == "relationship_integrity"
    assert score.metadata["source_sparse"] == 1


# ------------------------------------------------------------------
# Dimension 5: Ground Truth Quality
# ------------------------------------------------------------------


def test_measure_ground_truth_quality_no_mislabels(tmp_path) -> None:
    """No suspected mislabels = 100 score."""
    from shrike.extractor.pattern_extractor import PatternExtractor
    extractor = PatternExtractor()

    ground_truth = [
        {"raw_log": "sshd[123]: Accepted password for admin from 1.2.3.4", "class_uid": 3002},
    ]

    score = measure_ground_truth_quality(ground_truth, extractor, sample_size=1)
    assert score.name == "ground_truth_quality"
    assert score.metadata["sample_size"] == 1


def test_measure_ground_truth_quality_empty() -> None:
    """Empty ground truth = 100 score (no evidence of problems)."""
    from shrike.extractor.pattern_extractor import PatternExtractor
    extractor = PatternExtractor()
    score = measure_ground_truth_quality([], extractor)
    assert score.score == 100.0


# ------------------------------------------------------------------
# Dimension 6: Cache Quality
# ------------------------------------------------------------------


def test_measure_cache_quality_no_stats() -> None:
    """No cache_stats = 100 score with skipped reason."""
    score = measure_cache_quality(cache_stats=None)
    assert score.name == "cache_quality"
    assert score.score == 100.0
    assert score.metadata["skipped"] is True


def test_measure_cache_quality_with_stats() -> None:
    """Cache stats produce a composite score."""
    cache_stats = {
        "hit_rate": 0.8,
        "size": 20,
        "hits": 80,
        "misses": 20,
        "promotable_count": 10,
    }
    score = measure_cache_quality(cache_stats=cache_stats)
    assert score.name == "cache_quality"
    assert score.score > 0
    assert score.metadata["hit_rate"] == 0.8
    assert score.metadata["size"] == 20


def test_measure_cache_quality_components() -> None:
    """Cache quality score has hit_rate, utilization, and promotable components."""
    cache_stats = {
        "hit_rate": 0.5,
        "size": 5,
        "hits": 50,
        "misses": 50,
        "promotable_count": 2,
    }
    score = measure_cache_quality(cache_stats=cache_stats)
    assert "hit_rate_score" in score.metadata
    assert "utilization_score" in score.metadata
    assert "promotable_score" in score.metadata


# ------------------------------------------------------------------
# Dimension 7: Type Fidelity
# ------------------------------------------------------------------


def test_measure_type_fidelity_all_valid() -> None:
    """All typed fields pass validation = 100 score."""
    results = [
        _make_result({
            "src_endpoint.ip": "1.2.3.4",
            "src_endpoint.port": 22,
            "time": 1700000000,
        }),
    ]
    score = measure_type_fidelity(results)
    assert score.name == "type_fidelity"
    assert score.total > 0


def test_measure_type_fidelity_empty() -> None:
    """No typed fields = 100 score (nothing to fail)."""
    score = measure_type_fidelity([])
    assert score.score == 100.0


# ------------------------------------------------------------------
# Dimension 8: Observables
# ------------------------------------------------------------------


def test_measure_observables_some_built() -> None:
    """Observables builder produces some observables."""
    results = [
        _make_result({
            "src_endpoint.ip": "1.2.3.4",
            "dst_endpoint.ip": "5.6.7.8",
        }),
    ]
    score = measure_observables(results)
    assert score.name == "observables"
    assert score.total > 0


def test_measure_observables_none_extracted() -> None:
    """No results = 0 score."""
    score = measure_observables([])
    assert score.score == 0.0


# ------------------------------------------------------------------
# measure_all() orchestrator
# ------------------------------------------------------------------


def test_measure_all_returns_all_dimensions(tmp_path) -> None:
    """measure_all() returns scores for all 8 dimensions."""
    from shrike.extractor.pattern_extractor import PatternExtractor
    from shrike.validator.ocsf_validator import OCSFValidator

    extractor = PatternExtractor()
    validator = OCSFValidator()

    results = [
        _make_result({
            "src_endpoint.ip": "1.2.3.4",
            "src_endpoint.port": 22,
            "user": "admin",
            "result": "success",
        }),
    ]
    golden_logs = []
    canary_logs = []
    ground_truth = []

    dimensions = measure_all(
        results=results,
        golden_logs=golden_logs,
        canary_logs=canary_logs,
        ground_truth=ground_truth,
        extractor=extractor,
        validator=validator,
    )

    expected_dims = {
        "breadth",
        "accuracy",
        "schema_compliance",
        "relationship_integrity",
        "ground_truth_quality",
        "cache_quality",
        "type_fidelity",
        "observables",
        "attack_coverage",
    }
    if canary_logs:
        expected_dims.add("canary_accuracy")

    assert set(dimensions.keys()) == expected_dims
    for name, dim in dimensions.items():
        assert isinstance(dim, DimensionScore)
        assert dim.name == name
        assert 0.0 <= dim.score <= 100.0


def test_measure_all_with_none_results(tmp_path) -> None:
    """measure_all() handles None results gracefully."""
    from shrike.extractor.pattern_extractor import PatternExtractor
    from shrike.validator.ocsf_validator import OCSFValidator

    extractor = PatternExtractor()
    validator = OCSFValidator()

    results = [(None, {"class_uid": 3002, "raw_log": "test"})]
    dimensions = measure_all(
        results=results,
        golden_logs=[],
        canary_logs=[],
        ground_truth=[],
        extractor=extractor,
        validator=validator,
    )

    assert "breadth" in dimensions
    assert dimensions["breadth"].metadata["unmatched"] == 1


def test_measure_all_cache_quality_with_tiered_mode(tmp_path) -> None:
    """Cache quality dimension reflects tiered mode when cache_stats provided."""
    from shrike.extractor.pattern_extractor import PatternExtractor
    from shrike.validator.ocsf_validator import OCSFValidator

    extractor = PatternExtractor()
    validator = OCSFValidator()

    cache_stats = {
        "hit_rate": 0.9,
        "size": 50,
        "hits": 900,
        "misses": 100,
        "promotable_count": 25,
    }

    dimensions = measure_all(
        results=[],
        golden_logs=[],
        canary_logs=[],
        ground_truth=[],
        extractor=extractor,
        validator=validator,
        tiered=True,
        cache_stats=cache_stats,
    )

    assert dimensions["cache_quality"].metadata["hit_rate"] == 0.9
    assert dimensions["cache_quality"].score > 50.0
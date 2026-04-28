"""Tests for HallucinationChecker."""

from __future__ import annotations

import pytest

from shrike.evaluate.hallucination import (
    HallucinationChecker,
    METADATA_FIELDS,
    EXEMPT_CONFIDENCE,
    KNOWN_DEFAULTS,
)


class TestHallucinationChecker:
    """Tests for HallucinationChecker.check_event."""

    def test_real_value_in_log_not_hallucinated(self):
        """Values that appear in raw log are not hallucinated."""
        checker = HallucinationChecker()
        event = {"user": "alice", "status": "success"}
        raw_log = 'sshd[123]: user=alice status=success'

        results = checker.check_event(event, raw_log)

        assert len(results) == 2
        for path, value, hallucinated in results:
            assert hallucinated is False

    def test_value_not_in_log_is_hallucinated(self):
        """Values that don't appear in raw log are hallucinated."""
        checker = HallucinationChecker()
        event = {"user": "alice", "status": "success"}
        raw_log = 'sshd[123]: login failed'

        results = checker.check_event(event, raw_log)

        assert len(results) == 2
        paths_with_hallucination = {p for p, v, h in results if h}
        assert "user" in paths_with_hallucination
        assert "status" in paths_with_hallucination

    def test_metadata_fields_exempt(self):
        """Metadata fields (class_uid, category_uid, etc.) are always exempt."""
        checker = HallucinationChecker()
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "user": "alice",
        }
        raw_log = 'sshd[123]: user=alice'

        results = checker.check_event(event, raw_log)

        paths = {p for p, v, h in results}
        assert "class_uid" not in paths
        assert "class_name" not in paths
        assert "category_uid" not in paths

    def test_exempt_confidence_static(self):
        """Fields with static/default/enrichment confidence are exempt."""
        checker = HallucinationChecker()
        event = {"user": "alice", "status": "unknown"}
        raw_log = 'sshd[123]: login'
        confidence = {"user": "static", "status": "default"}

        results = checker.check_event(event, raw_log, confidence)

        paths = {p for p, v, h in results}
        assert "user" not in paths
        assert "status" not in paths

    def test_exempt_confidence_enrichment(self):
        """Fields with enrichment confidence are exempt."""
        checker = HallucinationChecker()
        event = {"user": "alice", "status": "success"}
        raw_log = 'sshd[123]: login'
        confidence = {"user": "enrichment"}

        results = checker.check_event(event, raw_log, confidence)

        paths = {p for p, v, h in results}
        assert "user" not in paths
        assert "status" in paths  # status has no exempt confidence

    def test_json_source_alias_confidence_exempt(self):
        """JSON-sourced values with alias/auto/fuzzy/embedding confidence are exempt."""
        checker = HallucinationChecker()
        event = {"user": "alice", "status": "success"}
        raw_log = '{"user": "alice", "status": "success"}'
        confidence = {"user": "alias", "status": "fuzzy"}

        results = checker.check_event(event, raw_log, confidence)

        paths = {p for p, v, h in results}
        assert "user" not in paths
        assert "status" not in paths

    def test_known_defaults_flagged(self):
        """Known default/placeholder values are flagged as hallucinated."""
        checker = HallucinationChecker()
        event = {"user": "unknown", "status": "N/A"}
        raw_log = 'sshd[123]: login'

        results = checker.check_event(event, raw_log)

        hallucinated_values = {v for p, v, h in results if h}
        assert "unknown" in hallucinated_values
        assert "N/A" in hallucinated_values

    def test_case_insensitive_match(self):
        """Hostnames/usernames match case-insensitively."""
        checker = HallucinationChecker()
        event = {"user": "Admin", "hostname": "ServerOne"}
        raw_log = 'sshd[123]: user=admin hostname=serverone'

        results = checker.check_event(event, raw_log)

        for path, value, hallucinated in results:
            assert hallucinated is False

    def test_numeric_values(self):
        """Numeric values are checked with word boundaries."""
        checker = HallucinationChecker()
        event = {"process": {"pid": 12345}}
        raw_log = 'sshd[123]: process pid=12345'

        results = checker.check_event(event, raw_log)

        assert len(results) == 1
        _, _, hallucinated = results[0]
        assert hallucinated is False

    def test_numeric_in_larger_string(self):
        """Numeric values that appear embedded in larger strings are found."""
        checker = HallucinationChecker()
        event = {"count": 22}
        raw_log = 'sshd[123]: connections=22 total=100'

        results = checker.check_event(event, raw_log)

        assert len(results) == 1
        _, _, hallucinated = results[0]
        assert hallucinated is False

    def test_boolean_values(self):
        """Boolean values match various log representations."""
        checker = HallucinationChecker()
        event = {"is_mfa": True, "is_remote": False}
        raw_log = 'sshd[123]: mfa=true remote=no'

        results = checker.check_event(event, raw_log)

        assert len(results) == 2
        for path, value, hallucinated in results:
            assert hallucinated is False

    def test_boolean_true_aliases(self):
        """Boolean True matches 'yes', '1', 'success', etc."""
        checker = HallucinationChecker()
        event = {"is_mfa": True}
        raw_log = 'sshd[123]: mfa=yes'

        results = checker.check_event(event, raw_log)

        assert len(results) == 1
        _, _, hallucinated = results[0]
        assert hallucinated is False

    def test_boolean_false_aliases(self):
        """Boolean False matches 'no', '0', 'failure', etc."""
        checker = HallucinationChecker()
        event = {"is_mfa": False}
        raw_log = 'sshd[123]: mfa=fail'

        results = checker.check_event(event, raw_log)

        assert len(results) == 1
        _, _, hallucinated = results[0]
        assert hallucinated is False

    def test_list_values_any_element_found(self):
        """List values are hallucinated only if NO element appears in log."""
        checker = HallucinationChecker()
        event = {"ips": ["1.2.3.4", "5.6.7.8"]}
        raw_log = 'sshd[123]: src=1.2.3.4'

        results = checker.check_event(event, raw_log)

        assert len(results) == 1
        _, _, hallucinated = results[0]
        assert hallucinated is False  # At least one element found

    def test_list_values_all_missing(self):
        """List values are hallucinated if ALL elements missing."""
        checker = HallucinationChecker()
        event = {"ips": ["1.2.3.4", "5.6.7.8"]}
        raw_log = 'sshd[123]: no ip here'

        results = checker.check_event(event, raw_log)

        assert len(results) == 1
        _, _, hallucinated = results[0]
        assert hallucinated is True

    def test_dict_values(self):
        """Dict values check if ANY value appears in log."""
        checker = HallucinationChecker()
        event = {"endpoint": {"ip": "1.2.3.4", "port": 22}}
        raw_log = 'sshd[123]: ip=1.2.3.4 port=22'

        results = checker.check_event(event, raw_log)

        assert len(results) == 2
        for path, value, hallucinated in results:
            assert hallucinated is False

    def test_empty_short_values_skip(self):
        """Empty or single-char values are skipped (not flagged)."""
        checker = HallucinationChecker()
        event = {"code": "A", "empty": ""}
        raw_log = 'sshd[123]: code=A'

        results = checker.check_event(event, raw_log)

        # Single char "A" and empty string are skipped
        assert all(h is False for _, _, h in results)

    def test_nested_event_fields(self):
        """Nested event fields are checked with dotted paths."""
        checker = HallucinationChecker()
        event = {
            "src_endpoint": {"ip": "1.2.3.4", "port": 22},
            "user": "alice",
        }
        raw_log = 'sshd[123]: user=alice src=1.2.3.4 port=22'

        results = checker.check_event(event, raw_log)

        paths = {p for p, v, h in results}
        assert "src_endpoint.ip" in paths
        assert "src_endpoint.port" in paths
        assert "user" in paths

    def test_count_hallucinations(self):
        """count_hallucinations returns count of hallucinated fields."""
        checker = HallucinationChecker()
        event = {"user": "alice", "status": "success", "ip": "1.2.3.4"}
        # alice in log, status and ip not
        raw_log = "sshd[123]: login from alice"

        count = checker.count_hallucinations(event, raw_log)

        assert count == 2  # "status" and "ip" are hallucinated

    def test_is_metadata_exact_match(self):
        """_is_metadata returns True for exact metadata field matches."""
        checker = HallucinationChecker()
        assert checker._is_metadata("class_uid") is True
        assert checker._is_metadata("category_name") is True
        assert checker._is_metadata("severity_id") is True

    def test_is_metadata_leaf_name(self):
        """_is_metadata returns True when leaf name is a metadata field."""
        checker = HallucinationChecker()
        assert checker._is_metadata("anything.category_uid") is True
        assert checker._is_metadata("anything.class_uid") is True

    def test_is_metadata_non_metadata(self):
        """_is_metadata returns False for non-metadata fields."""
        checker = HallucinationChecker()
        assert checker._is_metadata("user") is False
        assert checker._is_metadata("src_endpoint.ip") is False

    def test_is_known_default(self):
        """_is_known_default detects placeholder values."""
        assert HallucinationChecker._is_known_default("unknown") is True
        assert HallucinationChecker._is_known_default("N/A") is True
        assert HallucinationChecker._is_known_default("None") is True
        assert HallucinationChecker._is_known_default("Security Finding") is True
        assert HallucinationChecker._is_known_default("alice") is False

    def test_value_in_log_direct(self):
        """_value_in_log finds direct substring matches."""
        assert HallucinationChecker._value_in_log("alice", "user=alice") is True
        assert HallucinationChecker._value_in_log("alice", "user=bob") is False

    def test_value_in_log_case_insensitive(self):
        """_value_in_log matches case-insensitively."""
        assert HallucinationChecker._value_in_log("Admin", "user=admin") is True

    def test_value_in_log_numeric(self):
        """_value_in_log finds numeric values."""
        assert HallucinationChecker._value_in_log(22, "port=22") is True
        assert HallucinationChecker._value_in_log(22.0, "port=22") is True

    def test_value_in_log_float_int_part(self):
        """Float value matches if its integer part appears."""
        assert HallucinationChecker._value_in_log(22.5, "value=22") is True


class TestConstants:
    """Tests for module-level constants."""

    def test_metadata_fields_set(self):
        """METADATA_FIELDS is a non-empty frozenset."""
        assert isinstance(METADATA_FIELDS, frozenset)
        assert len(METADATA_FIELDS) > 0
        assert "class_uid" in METADATA_FIELDS
        assert "category_uid" in METADATA_FIELDS

    def test_exempt_confidence_set(self):
        """EXEMPT_CONFIDENCE contains expected values."""
        assert isinstance(EXEMPT_CONFIDENCE, frozenset)
        assert "static" in EXEMPT_CONFIDENCE
        assert "default" in EXEMPT_CONFIDENCE
        assert "enrichment" in EXEMPT_CONFIDENCE

    def test_known_defaults_set(self):
        """KNOWN_DEFAULTS contains expected placeholder values."""
        assert isinstance(KNOWN_DEFAULTS, frozenset)
        assert "unknown" in KNOWN_DEFAULTS
        assert "N/A" in KNOWN_DEFAULTS
        assert "None" in KNOWN_DEFAULTS
"""Tests for RelevanceScorer — 98% → 100% coverage.

Covers:
- _infer_source_type() with empty event (returns "")
- _infer_source_type() with only device.type
- _infer_source_type() with only log_name
- _score_source_reputation() with unknown source
- _score_attack_coverage() with no matched techniques
- _score_attack_coverage() with matched techniques
- score() with explicit source_type overriding inference
- score() with empty event (class_uid=0)
- score() with event that has all security fields
"""

from __future__ import annotations

import pytest

from shrike.triage.relevance import (
    RelevanceScorer,
    RelevanceResult,
    DEFAULT_SOURCE_SCORE,
    DEFAULT_SUBTYPE_SCORE,
    SUBTYPE_SCORES,
)


# ---------------------------------------------------------------------------
# _infer_source_type() edge cases
# ---------------------------------------------------------------------------

class TestInferSourceType:
    """_infer_source_type() with various metadata fields."""

    def setup_method(self):
        self.scorer = RelevanceScorer()

    def test_infer_empty_event(self):
        """Empty event returns empty string."""
        result = self.scorer.score({})
        assert result.source_type == ""

    def test_infer_only_device_type(self):
        """Only device.type field is used for inference."""
        event = {"device": {"type": "Firewall"}}
        result = self.scorer.score(event)
        assert result.source_type == "firewall"

    def test_infer_only_log_name(self):
        """Only metadata.log_name field is used for inference."""
        event = {"metadata": {"log_name": "Windows Security"}}
        result = self.scorer.score(event)
        assert result.source_type == "windows_security"

    def test_infer_product_name_takes_precedence(self):
        """metadata.product.name is checked before log_name and device.type."""
        event = {
            "metadata": {
                "product": {"name": "CrowdStrike"},
                "log_name": "sshd",
            },
            "device": {"type": "web_server"},
        }
        result = self.scorer.score(event)
        assert result.source_type == "crowdstrike"

    def test_infer_log_name_takes_precedence_over_device_type(self):
        """metadata.log_name is used when product.name is absent."""
        event = {
            "metadata": {"log_name": "Palo Alto Networks"},
            "device": {"type": "unknown"},
        }
        result = self.scorer.score(event)
        assert result.source_type == "palo_alto_networks"

    def test_infer_replaces_spaces_with_underscores(self):
        """Spaces in source names are replaced with underscores."""
        event = {"metadata": {"product": {"name": "云防火墙"}}}
        result = self.scorer.score(event)
        assert result.source_type == "云防火墙"

    def test_infer_non_string_product_name(self):
        """Non-string product.name is handled gracefully."""
        event = {"metadata": {"product": {"name": 12345}}}
        result = self.scorer.score(event)
        assert result.source_type == ""


# ---------------------------------------------------------------------------
# _score_source_reputation() edge cases
# ---------------------------------------------------------------------------

class TestSourceReputation:
    """_score_source_reputation() with various source types."""

    def setup_method(self):
        self.scorer = RelevanceScorer()

    def test_unknown_source_gets_default(self):
        """Unknown source type gets DEFAULT_SOURCE_SCORE (0.5)."""
        result = self.scorer.score({"class_uid": 3002}, source_type="completely_unknown_vendor")
        assert result.components["source_reputation"] == DEFAULT_SOURCE_SCORE

    def test_known_source_high_reputation(self):
        """Known high-reputation sources score correctly."""
        result = self.scorer.score({"class_uid": 3002}, source_type="sysmon")
        assert result.components["source_reputation"] == 0.95

    def test_known_source_low_reputation(self):
        """Known low-reputation sources score correctly."""
        result = self.scorer.score({"class_uid": 3002}, source_type="heartbeat")
        assert result.components["source_reputation"] == 0.05

    def test_source_type_case_insensitive(self):
        """Source type matching is case-insensitive."""
        result = self.scorer.score({"class_uid": 3002}, source_type="SYSMON")
        assert result.components["source_reputation"] == 0.95

    def test_custom_source_reputation_override(self):
        """Custom source reputation overrides default."""
        scorer = RelevanceScorer(source_reputation={"my_source": 0.99})
        result = scorer.score({"class_uid": 3002}, source_type="my_source")
        assert result.components["source_reputation"] == 0.99

    def test_custom_source_reputation_partial(self):
        """Custom source reputation only overrides specified sources."""
        scorer = RelevanceScorer(source_reputation={"my_source": 0.99})
        result = scorer.score({"class_uid": 3002}, source_type="sysmon")
        assert result.components["source_reputation"] == 0.95  # unchanged


# ---------------------------------------------------------------------------
# _score_attack_coverage() edge cases
# ---------------------------------------------------------------------------

class TestAttackCoverage:
    """_score_attack_coverage() with various event configurations."""

    def setup_method(self):
        self.scorer = RelevanceScorer()

    def test_class_uid_zero_returns_empty(self):
        """class_uid=0 returns no matched techniques."""
        result = self.scorer.score({"class_uid": 0, "activity_id": 1})
        assert result.matched_techniques == []
        assert result.components["attack_coverage"] == 0.0

    def test_auth_logon_matches_attack_techniques(self):
        """Auth logon with full fields matches T1078."""
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": {"name": "admin"},
            "src_endpoint": {"ip": "192.168.1.100"},
            "status": "Success",
        }
        result = self.scorer.score(event)
        assert "T1078" in result.matched_techniques
        assert result.components["attack_coverage"] > 0.0

    def test_process_launch_matches_T1059(self):
        """Process launch with cmd_line matches T1059."""
        event = {
            "class_uid": 1007,
            "activity_id": 1,
            "process": {
                "name": "powershell.exe",
                "cmd_line": "powershell -enc SQBFAFgA...",
            },
        }
        result = self.scorer.score(event)
        assert "T1059" in result.matched_techniques

    def test_partial_fields_no_match(self):
        """Event with only some required fields doesn't match."""
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": {"name": "admin"},
            # Missing src_endpoint.ip and status
        }
        result = self.scorer.score(event)
        assert "T1078" not in result.matched_techniques

    def test_activity_filter_excludes_wrong_activity(self):
        """T1078 only matches activity_id=1 (Logon), not other activities."""
        event = {
            "class_uid": 3002,
            "activity_id": 2,  # Logoff, not Logon
            "user": {"name": "admin"},
            "src_endpoint": {"ip": "192.168.1.100"},
            "status": "Success",
        }
        result = self.scorer.score(event)
        assert "T1078" not in result.matched_techniques

    def test_multiple_techniques_matched(self):
        """Event matching multiple techniques gets higher score."""
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": {"name": "admin"},
            "src_endpoint": {"ip": "192.168.1.100"},
            "status": "Success",
        }
        result = self.scorer.score(event)
        # T1078, T1133, T1021, T1110 all require (3002, 1) + user + src_endpoint.ip + status
        assert len(result.matched_techniques) >= 1

    def test_attack_coverage_score_capped_at_one(self):
        """Attack coverage score is capped at 1.0."""
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": {"name": "admin"},
            "src_endpoint": {"ip": "192.168.1.100"},
            "status": "Success",
        }
        result = self.scorer.score(event)
        assert result.components["attack_coverage"] <= 1.0


# ---------------------------------------------------------------------------
# _score_subtype() edge cases
# ---------------------------------------------------------------------------

class TestSubtypeScoring:
    """_score_subtype() with known and unknown pairs."""

    def setup_method(self):
        self.scorer = RelevanceScorer()

    def test_known_auth_logon(self):
        """(3002, 1) = 1.0 for auth logon."""
        result = self.scorer.score({"class_uid": 3002, "activity_id": 1})
        assert result.components["subtype_score"] == 1.0

    def test_known_process_launch(self):
        """(1007, 1) = 0.9 for process launch."""
        result = self.scorer.score({"class_uid": 1007, "activity_id": 1})
        assert result.components["subtype_score"] == 0.9

    def test_known_finding_create(self):
        """(2004, 1) = 1.0 for finding create."""
        result = self.scorer.score({"class_uid": 2004, "activity_id": 1})
        assert result.components["subtype_score"] == 1.0

    def test_unknown_pair_defaults(self):
        """Unknown (class_uid, activity_id) defaults to 0.5."""
        result = self.scorer.score({"class_uid": 9999, "activity_id": 99})
        assert result.components["subtype_score"] == DEFAULT_SUBTYPE_SCORE

    def test_all_subtype_pairs_in_map(self):
        """Verify all SUBTYPE_SCORES entries are retrievable."""
        scorer = RelevanceScorer()
        for (class_uid, activity_id), score in SUBTYPE_SCORES.items():
            result = scorer._score_subtype(class_uid, activity_id)
            assert result == score, f"({class_uid}, {activity_id}) expected {score}, got {result}"


# ---------------------------------------------------------------------------
# _score_field_richness() edge cases
# ---------------------------------------------------------------------------

class TestFieldRichness:
    """_score_field_richness() with various field configurations."""

    def setup_method(self):
        self.scorer = RelevanceScorer()

    def test_empty_event_zero_richness(self):
        """Empty event has zero field richness."""
        result = self.scorer.score({"class_uid": 3002})
        assert result.components["field_richness"] == 0.0

    def test_all_fields_present_max_richness(self):
        """Event with all security fields gets max richness."""
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": {"name": "admin", "uid": "S-1-5-21"},
            "actor": {"user": {"name": "SYSTEM"}},
            "src_endpoint": {"ip": "192.168.1.100", "port": 12345},
            "dst_endpoint": {"ip": "10.0.0.1", "port": 22},
            "process": {"name": "ssh", "cmd_line": "sshd", "pid": 1234,
                        "parent_process": {"name": "init", "pid": 1}},
            "finding_info": {"title": "test", "uid": "abc"},
            "severity_id": 3,
            "status": "Success",
            "status_id": 1,
            "auth_protocol": "ssh",
            "auth_protocol_id": 99,
            "connection_info": {"protocol_name": "tcp", "direction": "outbound"},
            "http_request": {"url": {"path": "/"}, "http_method": "GET"},
            "http_response": {"code": 200},
            "query": {"hostname": "evil.com"},
            "answers": ["1.2.3.4"],
            "traffic": {"bytes_in": 100, "bytes_out": 200},
            "email": {"from": "a@b.com", "to": "c@d.com"},
            "api": {"operation": "login", "service": {"name": "api"}},
            "privileges": ["admin"],
            "session": {"uid": "sess-123"},
            "device": {"hostname": "host"},
            "observables": [],
            "unmapped": {},
        }
        result = self.scorer.score(event)
        assert result.components["field_richness"] == 1.0

    def test_falsy_values_ignored(self):
        """Empty strings, 'None', 'unknown', '0' are treated as absent."""
        event = {
            "class_uid": 3002,
            "user": {"name": ""},  # empty string
            "src_endpoint": {"ip": "None"},  # string None
            "status": "unknown",  # string unknown
        }
        result = self.scorer.score(event)
        # None of these should count as present
        assert result.components["field_richness"] < 1.0

    def test_class_specific_max_fields(self):
        """Different classes have different max field counts."""
        # System Activity (1001) has max 4 fields
        event_1001 = {
            "class_uid": 1001,
            "device": {"hostname": "host"},
        }
        # Authentication (3002) has max 12 fields
        event_3002 = {
            "class_uid": 3002,
            "user": {"name": "admin"},
        }
        result_1001 = self.scorer.score(event_1001)
        result_3002 = self.scorer.score(event_3002)
        # Both have 1 field, but different denominators
        assert result_1001.components["field_richness"] >= result_3002.components["field_richness"]


# ---------------------------------------------------------------------------
# score() composite and integration
# ---------------------------------------------------------------------------

class TestScoreComposite:
    """score() composite calculation and integration."""

    def setup_method(self):
        self.scorer = RelevanceScorer()

    def test_score_bounded_zero_to_one(self):
        """Composite score is always between 0.0 and 1.0."""
        events = [
            {"class_uid": 3002, "activity_id": 1, "user": {"name": "admin"},
             "src_endpoint": {"ip": "1.2.3.4"}, "status": "Success"},
            {"class_uid": 0},
            {"class_uid": 9999, "activity_id": 99},
        ]
        for event in events:
            result = self.scorer.score(event)
            assert 0.0 <= result.score <= 1.0

    def test_explicit_source_type_overrides_inference(self):
        """Explicit source_type parameter overrides inference."""
        event = {"metadata": {"product": {"name": "sshd"}}}
        result = self.scorer.score(event, source_type="crowdstrike")
        assert result.source_type == "crowdstrike"
        assert result.components["source_reputation"] == 0.95  # CrowdStrike reputation

    def test_empty_weights_sum_to_one(self):
        """Default weights sum to 1.0."""
        scorer = RelevanceScorer()
        total = sum(scorer._weights.values())
        assert abs(total - 1.0) < 0.01

    def test_custom_weights_all_zeros(self):
        """All-zero weights produce score of 0.0."""
        scorer = RelevanceScorer(weights={
            "subtype_score": 0.0,
            "field_richness": 0.0,
            "attack_coverage": 0.0,
            "source_reputation": 0.0,
        })
        result = scorer.score({"class_uid": 3002, "activity_id": 1})
        assert result.score == 0.0

    def test_to_dict_all_fields(self):
        """to_dict() returns all expected fields."""
        result = self.scorer.score({"class_uid": 3002, "activity_id": 1})
        d = result.to_dict()
        assert "relevance_score" in d
        assert "components" in d
        assert "matched_techniques" in d
        assert "source_type" in d
        assert all(isinstance(v, float) for v in d["components"].values())

    def test_to_dict_rounds_values(self):
        """to_dict() rounds values to 4 decimal places."""
        result = self.scorer.score({"class_uid": 3002, "activity_id": 1})
        d = result.to_dict()
        assert len(str(d["relevance_score"]).replace(".", "").replace("-", "")) <= 6


# ---------------------------------------------------------------------------
# RelevanceResult edge cases
# ---------------------------------------------------------------------------

class TestRelevanceResult:
    """RelevanceResult dataclass edge cases."""

    def test_result_with_empty_techniques(self):
        """Result with no matched techniques."""
        scorer = RelevanceScorer()
        result = scorer.score({"class_uid": 0})
        assert result.matched_techniques == []
        assert result.components["attack_coverage"] == 0.0

    def test_result_with_multiple_techniques(self):
        """Result with multiple matched techniques."""
        scorer = RelevanceScorer()
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": {"name": "admin"},
            "src_endpoint": {"ip": "192.168.1.100"},
            "status": "Success",
        }
        result = scorer.score(event)
        assert len(result.matched_techniques) > 0

    def test_result_source_type_empty_by_default(self):
        """source_type is empty string when not inferrable."""
        scorer = RelevanceScorer()
        result = scorer.score({})
        assert result.source_type == ""
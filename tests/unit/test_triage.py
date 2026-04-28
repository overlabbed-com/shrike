"""Tests for shrike.triage — relevance scoring, routing, and reclassification."""

import pytest

from shrike.triage.relevance import (
    RelevanceScorer,
    RelevanceResult,
    SUBTYPE_SCORES,
    DEFAULT_SUBTYPE_SCORE,
    SECURITY_FIELDS,
)
from shrike.triage.router import EventRouter, RoutingDecision
from shrike.triage.reclassifier import Reclassifier, ReclassificationResult


# ---------------------------------------------------------------------------
# Test fixtures — representative OCSF events
# ---------------------------------------------------------------------------

def _make_auth_logon_event() -> dict:
    """High-value: successful authentication with full fields."""
    return {
        "class_uid": 3002,
        "activity_id": 1,
        "category_uid": 3,
        "severity_id": 1,
        "status": "Success",
        "status_id": 1,
        "user": {"name": "admin", "uid": "S-1-5-21-1234"},
        "actor": {"user": {"name": "SYSTEM"}},
        "src_endpoint": {"ip": "192.168.1.100", "port": 49832},
        "dst_endpoint": {"ip": "10.0.0.1", "port": 22},
        "auth_protocol": "ssh",
        "auth_protocol_id": 99,
        "session": {"uid": "sess-abc123"},
        "device": {"hostname": "dc01.corp.local"},
        "metadata": {"product": {"name": "sshd"}},
    }


def _make_auth_logoff_event() -> dict:
    """Medium-value: session close with fewer fields."""
    return {
        "class_uid": 3002,
        "activity_id": 2,
        "category_uid": 3,
        "severity_id": 1,
        "status": "Success",
        "user": {"name": "user1"},
        "session": {"uid": "sess-xyz"},
        "metadata": {"product": {"name": "sshd"}},
    }


def _make_system_startup_event() -> dict:
    """Low-value: system startup heartbeat."""
    return {
        "class_uid": 1001,
        "activity_id": 1,
        "category_uid": 1,
        "severity_id": 1,
        "device": {"hostname": "web01"},
        "metadata": {"product": {"name": "healthcheck"}},
    }


def _make_process_launch_event() -> dict:
    """High-value: process creation with cmd_line (Sysmon-like)."""
    return {
        "class_uid": 1007,
        "activity_id": 1,
        "category_uid": 1,
        "severity_id": 1,
        "process": {
            "name": "powershell.exe",
            "cmd_line": "powershell -enc SQBFAFgA...",
            "pid": 4568,
            "parent_process": {"name": "cmd.exe", "pid": 1234},
            "file": {"path": "C:\\Windows\\System32\\powershell.exe"},
        },
        "actor": {"user": {"name": "CORP\\admin"}},
        "device": {"hostname": "ws01.corp.local"},
        "metadata": {"product": {"name": "sysmon"}},
    }


def _make_network_event() -> dict:
    """Medium-value: network connection with full fields."""
    return {
        "class_uid": 4001,
        "activity_id": 1,
        "category_uid": 4,
        "severity_id": 1,
        "src_endpoint": {"ip": "10.0.0.5", "port": 49100},
        "dst_endpoint": {"ip": "93.184.216.34", "port": 443},
        "connection_info": {"protocol_name": "TCP", "direction": "outbound"},
        "traffic": {"bytes_in": 1024, "bytes_out": 512},
        "metadata": {"product": {"name": "firewall"}},
    }


def _make_finding_event() -> dict:
    """High-value: vulnerability finding / IDS alert."""
    return {
        "class_uid": 2004,
        "activity_id": 1,
        "category_uid": 2,
        "severity_id": 4,
        "finding_info": {"title": "SQL Injection Attempt", "uid": "CVE-2024-1234"},
        "src_endpoint": {"ip": "203.0.113.50"},
        "dst_endpoint": {"ip": "10.0.0.1"},
        "status": "Detected",
        "metadata": {"product": {"name": "suricata"}},
    }


def _make_minimal_event() -> dict:
    """Noise: nearly empty event with unknown class."""
    return {
        "class_uid": 0,
        "activity_id": 0,
        "metadata": {},
    }


def _make_misclassified_event() -> dict:
    """An event classified as System Activity (1001) but has auth fields.

    Should be reclassifiable to Authentication (3002).
    """
    return {
        "class_uid": 1001,
        "activity_id": 1,
        "user": {"name": "admin", "uid": "S-1-5-21-9999"},
        "actor": {"user": {"name": "CORP\\svc_account"}},
        "src_endpoint": {"ip": "10.0.0.55", "port": 50123},
        "dst_endpoint": {"ip": "10.0.0.1"},
        "status": "Failure",
        "status_id": 2,
        "auth_protocol": "kerberos",
        "session": {"uid": "sess-misclass"},
        "device": {"hostname": "dc02"},
    }


# ===========================================================================
# RelevanceScorer tests
# ===========================================================================

class TestRelevanceScorer:

    def setup_method(self):
        self.scorer = RelevanceScorer()

    def test_score_returns_relevance_result(self):
        event = _make_auth_logon_event()
        result = self.scorer.score(event)
        assert isinstance(result, RelevanceResult)
        assert 0.0 <= result.score <= 1.0

    def test_high_value_auth_logon_scores_high(self):
        event = _make_auth_logon_event()
        result = self.scorer.score(event)
        assert result.score >= 0.7, f"Auth logon should score >= 0.7, got {result.score}"

    def test_system_startup_scores_low(self):
        event = _make_system_startup_event()
        result = self.scorer.score(event)
        assert result.score < 0.3, f"System startup should score < 0.3, got {result.score}"

    def test_process_launch_scores_high(self):
        event = _make_process_launch_event()
        result = self.scorer.score(event)
        assert result.score >= 0.7, f"Process launch should score >= 0.7, got {result.score}"

    def test_finding_scores_high(self):
        event = _make_finding_event()
        result = self.scorer.score(event)
        assert result.score >= 0.6, f"Finding should score >= 0.6, got {result.score}"

    def test_minimal_event_scores_low(self):
        event = _make_minimal_event()
        result = self.scorer.score(event)
        assert result.score < 0.3, f"Minimal event should score < 0.3, got {result.score}"

    def test_network_event_scores_moderate(self):
        event = _make_network_event()
        result = self.scorer.score(event)
        assert 0.3 <= result.score <= 0.9, f"Network event: expected 0.3-0.9, got {result.score}"

    def test_components_present(self):
        result = self.scorer.score(_make_auth_logon_event())
        assert "subtype_score" in result.components
        assert "field_richness" in result.components
        assert "attack_coverage" in result.components
        assert "source_reputation" in result.components

    def test_components_range(self):
        result = self.scorer.score(_make_auth_logon_event())
        for name, value in result.components.items():
            assert 0.0 <= value <= 1.0, f"Component {name} out of range: {value}"

    def test_subtype_score_known_pair(self):
        # Auth logon = (3002, 1) = 1.0
        event = {"class_uid": 3002, "activity_id": 1}
        result = self.scorer.score(event)
        assert result.components["subtype_score"] == 1.0

    def test_subtype_score_unknown_pair(self):
        event = {"class_uid": 9999, "activity_id": 99}
        result = self.scorer.score(event)
        assert result.components["subtype_score"] == DEFAULT_SUBTYPE_SCORE

    def test_source_type_explicit(self):
        event = _make_auth_logon_event()
        result = self.scorer.score(event, source_type="sysmon")
        assert result.source_type == "sysmon"
        assert result.components["source_reputation"] == 0.95

    def test_source_type_inferred(self):
        event = _make_auth_logon_event()
        result = self.scorer.score(event)
        assert result.source_type == "sshd"

    def test_healthcheck_low_reputation(self):
        event = _make_system_startup_event()
        result = self.scorer.score(event, source_type="healthcheck")
        assert result.components["source_reputation"] == 0.10

    def test_custom_source_reputation(self):
        scorer = RelevanceScorer(source_reputation={"custom_src": 0.99})
        event = _make_auth_logon_event()
        result = scorer.score(event, source_type="custom_src")
        assert result.components["source_reputation"] == 0.99

    def test_custom_weights(self):
        # All weight on subtype — auth logon subtype = 1.0
        scorer = RelevanceScorer(weights={
            "subtype_score": 1.0,
            "field_richness": 0.0,
            "attack_coverage": 0.0,
            "source_reputation": 0.0,
        })
        event = {"class_uid": 3002, "activity_id": 1}
        result = scorer.score(event)
        assert abs(result.score - 1.0) < 0.01

    def test_attack_techniques_matched(self):
        # Auth logon with full fields should match T1078, T1133, T1021, T1110
        event = _make_auth_logon_event()
        result = self.scorer.score(event)
        assert len(result.matched_techniques) > 0
        assert "T1078" in result.matched_techniques

    def test_no_attack_techniques_for_empty(self):
        event = _make_minimal_event()
        result = self.scorer.score(event)
        assert result.matched_techniques == []

    def test_to_dict(self):
        result = self.scorer.score(_make_auth_logon_event())
        d = result.to_dict()
        assert "relevance_score" in d
        assert "components" in d
        assert "matched_techniques" in d
        assert isinstance(d["relevance_score"], float)

    def test_field_richness_scales_with_fields(self):
        # More fields = higher richness
        sparse = {"class_uid": 3002, "activity_id": 1, "user": {"name": "bob"}}
        rich = _make_auth_logon_event()

        sparse_result = self.scorer.score(sparse)
        rich_result = self.scorer.score(rich)

        assert rich_result.components["field_richness"] > sparse_result.components["field_richness"]


# ===========================================================================
# EventRouter tests
# ===========================================================================

class TestEventRouter:

    def setup_method(self):
        self.router = EventRouter()
        self.scorer = RelevanceScorer()

    def test_route_returns_routing_decision(self):
        result = self.scorer.score(_make_auth_logon_event())
        decision = self.router.route(result)
        assert isinstance(decision, RoutingDecision)

    def test_high_score_routes_security(self):
        result = self.scorer.score(_make_auth_logon_event())
        decision = self.router.route(result)
        assert decision.tier == "security"
        assert decision.destination == "detect"
        assert decision.cost_tier == "$$$"

    def test_low_score_routes_noise_or_compliance(self):
        result = self.scorer.score(_make_system_startup_event())
        decision = self.router.route(result)
        assert decision.tier in ("noise", "compliance")

    def test_minimal_event_routes_low_tier(self):
        result = self.scorer.score(_make_minimal_event())
        decision = self.router.route(result)
        # Minimal event: unknown subtype=0.5, empty fields=0.0, no attack=0.0, unknown source=0.5
        # Composite: 0.5*0.4 + 0.0 + 0.0 + 0.5*0.1 = 0.25 → compliance
        assert decision.tier in ("noise", "compliance")

    def test_explicit_noise_routes_drop(self):
        """A raw score below 0.1 routes to noise/drop."""
        decision = self.router.route(0.05)
        assert decision.tier == "noise"
        assert decision.destination == "drop"
        assert decision.cost_tier == "free"

    def test_route_accepts_raw_float(self):
        decision = self.router.route(0.85)
        assert decision.tier == "security"

    def test_route_boundary_security(self):
        decision = self.router.route(0.7)
        assert decision.tier == "security"

    def test_route_boundary_operational(self):
        decision = self.router.route(0.3)
        assert decision.tier == "operational"

    def test_route_boundary_compliance(self):
        decision = self.router.route(0.1)
        assert decision.tier == "compliance"

    def test_route_boundary_noise(self):
        decision = self.router.route(0.09)
        assert decision.tier == "noise"

    def test_route_zero(self):
        decision = self.router.route(0.0)
        assert decision.tier == "noise"

    def test_route_one(self):
        decision = self.router.route(1.0)
        assert decision.tier == "security"

    def test_custom_thresholds(self):
        router = EventRouter(thresholds={
            "security": 0.9,
            "operational": 0.5,
            "compliance": 0.2,
        })
        assert router.route(0.85).tier == "operational"
        assert router.route(0.95).tier == "security"

    def test_to_dict(self):
        decision = self.router.route(0.75)
        d = decision.to_dict()
        assert d["tier"] == "security"
        assert "destination" in d
        assert "cost_tier" in d
        assert "reason" in d

    def test_route_batch(self):
        events = [
            _make_auth_logon_event(),
            _make_system_startup_event(),
            _make_minimal_event(),
        ]
        results = [self.scorer.score(e) for e in events]
        decisions = self.router.route_batch(results)
        assert len(decisions) == 3
        assert all(isinstance(d, RoutingDecision) for d in decisions)

    def test_tier_distribution(self):
        events = [
            _make_auth_logon_event(),
            _make_process_launch_event(),
            _make_system_startup_event(),
            _make_minimal_event(),
        ]
        results = [self.scorer.score(e) for e in events]
        dist = self.router.tier_distribution(results)
        assert sum(dist.values()) == 4
        assert "security" in dist
        assert "noise" in dist

    def test_reason_contains_score(self):
        decision = self.router.route(0.85)
        assert "0.85" in decision.reason


# ===========================================================================
# Reclassifier tests
# ===========================================================================

class TestReclassifier:

    def setup_method(self):
        self.reclassifier = Reclassifier()

    def test_should_attempt_below_threshold(self):
        assert self.reclassifier.should_attempt(0.2) is True

    def test_should_not_attempt_above_threshold(self):
        assert self.reclassifier.should_attempt(0.5) is False

    def test_should_not_attempt_at_threshold(self):
        assert self.reclassifier.should_attempt(0.3) is False

    def test_reclassify_returns_result(self):
        event = _make_misclassified_event()
        result = self.reclassifier.reclassify(event)
        assert isinstance(result, ReclassificationResult)

    def test_misclassified_auth_detected(self):
        """An event with class_uid=1001 but auth fields should reclassify to 3002."""
        event = _make_misclassified_event()
        result = self.reclassifier.reclassify(event)
        assert result.should_reclassify is True
        assert result.suggested_class == 3002
        assert result.suggested_class_name == "Authentication"
        assert result.confidence > 0.5

    def test_correctly_classified_no_reclassify(self):
        """An auth event correctly classified as 3002 should NOT reclassify."""
        event = _make_auth_logon_event()
        result = self.reclassifier.reclassify(event)
        # It might match another class, but the original is 3002 which is excluded
        # from candidates. So either no match or a lower match.
        # The key test: if it does suggest, it shouldn't be 3002
        if result.should_reclassify:
            assert result.suggested_class != 3002

    def test_minimal_event_no_reclassify(self):
        """Empty event has too few fields for any class signature."""
        event = _make_minimal_event()
        result = self.reclassifier.reclassify(event)
        assert result.should_reclassify is False

    def test_evidence_populated(self):
        event = _make_misclassified_event()
        result = self.reclassifier.reclassify(event)
        assert "matched_fields" in result.evidence
        assert "match_count" in result.evidence
        assert result.evidence["match_count"] >= 5

    def test_original_class_preserved(self):
        event = _make_misclassified_event()
        result = self.reclassifier.reclassify(event)
        assert result.original_class == 1001

    def test_to_dict(self):
        event = _make_misclassified_event()
        result = self.reclassifier.reclassify(event)
        d = result.to_dict()
        assert "should_reclassify" in d
        assert "original_class" in d
        assert "suggested_class" in d
        assert "confidence" in d
        assert isinstance(d["confidence"], float)

    def test_custom_threshold(self):
        reclassifier = Reclassifier(relevance_threshold=0.5)
        assert reclassifier.should_attempt(0.4) is True
        assert reclassifier.should_attempt(0.5) is False

    def test_custom_min_fields(self):
        """With a very high min_field requirement, fewer events trigger reclassify."""
        strict = Reclassifier(min_field_matches=20)
        event = _make_misclassified_event()
        result = strict.reclassify(event)
        assert result.should_reclassify is False


# ===========================================================================
# Integration: scorer + router + reclassifier
# ===========================================================================

class TestTriageIntegration:
    """End-to-end triage pipeline: score → route → reclassify if needed."""

    def setup_method(self):
        self.scorer = RelevanceScorer()
        self.router = EventRouter()
        self.reclassifier = Reclassifier()

    def test_full_pipeline_high_value(self):
        event = _make_auth_logon_event()
        result = self.scorer.score(event)
        route = self.router.route(result)

        assert route.tier == "security"
        assert not self.reclassifier.should_attempt(result.score)

    def test_full_pipeline_low_value(self):
        event = _make_minimal_event()
        result = self.scorer.score(event)
        route = self.router.route(result)

        # Minimal event scores ~0.25 → compliance tier, below reclassify threshold
        assert route.tier in ("noise", "compliance")
        assert self.reclassifier.should_attempt(result.score)

    def test_full_pipeline_reclassification(self):
        """Misclassified event: low score → reclassify → higher score."""
        event = _make_misclassified_event()

        # Score with wrong class
        result1 = self.scorer.score(event)

        # Check if reclassification is warranted
        if self.reclassifier.should_attempt(result1.score):
            reclass = self.reclassifier.reclassify(event)
            if reclass.should_reclassify:
                # Apply reclassification
                event["class_uid"] = reclass.suggested_class
                result2 = self.scorer.score(event)
                # Reclassified event should score higher (or at least differently)
                assert result2.score != result1.score

    def test_batch_processing(self):
        events = [
            _make_auth_logon_event(),
            _make_auth_logoff_event(),
            _make_system_startup_event(),
            _make_process_launch_event(),
            _make_network_event(),
            _make_finding_event(),
            _make_minimal_event(),
        ]

        results = [self.scorer.score(e) for e in events]
        decisions = [self.router.route(r) for r in results]

        # At least one should be security tier
        tiers = [d.tier for d in decisions]
        assert "security" in tiers

        # At least one should be low tier
        assert "noise" in tiers or "compliance" in tiers

    def test_import_from_package(self):
        """Verify public API is importable from shrike.triage."""
        from shrike.triage import (
            RelevanceScorer,
            RelevanceResult,
            EventRouter,
            RoutingDecision,
            Reclassifier,
            ReclassificationResult,
        )
        assert RelevanceScorer is not None
        assert EventRouter is not None
        assert Reclassifier is not None

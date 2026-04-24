"""Tests for Shrike configuration."""

import pytest

from shrike.config import Config


def test_config_defaults():
    """Config has sensible defaults."""
    cfg = Config()
    assert cfg.mode == "full"
    assert cfg.syslog_port == 1514
    assert cfg.destinations == ["splunk_hec"]
    assert cfg.wal_max_mb == 500  # 500MB default for brief outage handling


def test_config_from_env(monkeypatch):
    """Config.from_env() reads environment variables."""
    monkeypatch.setenv("SHRIKE_MODE", "collector")
    monkeypatch.setenv("SHRIKE_SYSLOG_PORT", "5514")
    monkeypatch.setenv("SHRIKE_DESTINATIONS", "file_jsonl,s3")
    monkeypatch.setenv("SPLUNK_HEC_URL", "https://splunk:8088")

    cfg = Config.from_env()
    assert cfg.mode == "collector"
    assert cfg.syslog_port == 5514
    assert cfg.destinations == ["file_jsonl", "s3"]
    assert cfg.splunk_hec_url == "https://splunk:8088"


def test_config_frozen():
    """Config is immutable."""
    cfg = Config()
    try:
        cfg.mode = "collector"  # type: ignore[misc]
        raise AssertionError("Should have raised FrozenInstanceError")
    except AttributeError:
        pass


def test_config_fixture(config):
    """The test fixture provides expected values."""
    assert config.mode == "full"
    assert config.destinations == ["file_jsonl"]
    assert config.wal_dir == "/tmp/shrike-test-wal"
    assert config.file_output_dir == "/tmp/shrike-test-output"


# ------------------------------------------------------------------
# Config validation tests
# ------------------------------------------------------------------


def test_validate_splunk_hec_missing_url():
    """Splunk HEC destination requires URL."""
    cfg = Config(destinations=["splunk_hec"], splunk_hec_url="", splunk_hec_token="tok")
    with pytest.raises(ValueError, match="SPLUNK_HEC_URL"):
        cfg.validate()


def test_validate_splunk_hec_missing_token():
    """Splunk HEC destination requires token."""
    cfg = Config(destinations=["splunk_hec"], splunk_hec_url="https://splunk:8088", splunk_hec_token="")
    with pytest.raises(ValueError, match="SPLUNK_HEC_TOKEN"):
        cfg.validate()


def test_validate_splunk_hec_valid():
    """Splunk HEC with URL and token passes validation."""
    cfg = Config(
        destinations=["splunk_hec"],
        splunk_hec_url="https://splunk:8088",
        splunk_hec_token="tok",
    )
    result = cfg.validate()
    assert result is cfg


def test_validate_forwarder_missing_forward_to():
    """Forwarder mode requires forward_to."""
    cfg = Config(mode="forwarder", forward_to="", destinations=["file_jsonl"])
    with pytest.raises(ValueError, match="SHRIKE_FORWARD_TO"):
        cfg.validate()


def test_validate_forwarder_valid():
    """Forwarder with forward_to passes."""
    cfg = Config(mode="forwarder", forward_to="upstream:4317", destinations=["file_jsonl"])
    result = cfg.validate()
    assert result is cfg


def test_validate_s3_missing_endpoint():
    """S3 destination requires endpoint."""
    cfg = Config(destinations=["s3"], s3_endpoint="", s3_bucket="mybucket")
    with pytest.raises(ValueError, match="S3_ENDPOINT"):
        cfg.validate()


def test_validate_s3_missing_bucket():
    """S3 destination requires bucket."""
    cfg = Config(destinations=["s3"], s3_endpoint="http://minio:9000", s3_bucket="")
    with pytest.raises(ValueError, match="S3_BUCKET"):
        cfg.validate()


def test_validate_file_jsonl_no_extra_requirements():
    """file_jsonl destination has no special validation."""
    cfg = Config(destinations=["file_jsonl"])
    result = cfg.validate()
    assert result is cfg

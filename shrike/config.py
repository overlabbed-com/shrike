"""Configuration for Shrike, loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields

_SECRET_SUBSTRINGS = ("key", "token", "secret", "password")


@dataclass(frozen=True)
class Config:
    """Immutable configuration loaded from environment variables."""

    mode: str = "full"
    forward_to: str = ""
    syslog_port: int = 1514
    docker_log_path: str = "/var/lib/docker/containers"
    otlp_grpc_port: int = 4317
    otlp_http_port: int = 4318
    http_port: int = 8080

    # LLM normalization
    llm_url: str = ""
    llm_model: str = ""
    llm_api_key: str = ""

    # ML models
    classifier_model: str = ""
    ner_model: str = ""

    # Ingest endpoint authentication
    ingest_api_key: str = ""

    # Destinations
    destinations: list[str] = field(default_factory=lambda: ["splunk_hec"])
    wal_dir: str = "/data/wal"
    wal_max_mb: int = 500

    # Splunk HEC
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    splunk_tls_verify: bool = True

    # S3 / object storage
    s3_endpoint: str = ""
    s3_bucket: str = ""
    s3_access_key: str = ""
    s3_secret_key: str = ""
    s3_format: str = "parquet"

    # Webhook
    webhook_url: str = ""
    webhook_auth_token: str = ""

    # Forwarder TLS
    forwarder_tls_insecure: bool = False

    # File output
    file_output_dir: str = "/data/output"

    def __repr__(self) -> str:
        """Mask fields containing secret-like names to prevent credential leakage."""
        parts: list[str] = []
        for f in fields(self):
            val = getattr(self, f.name)
            if any(s in f.name.lower() for s in _SECRET_SUBSTRINGS) and val:
                parts.append(f"{f.name}='***'")
            else:
                parts.append(f"{f.name}={val!r}")
        return f"Config({', '.join(parts)})"

    def validate(self) -> list[str]:
        """Validate configuration consistency. Returns a list of error messages (empty = valid).

        Checks destination-specific required fields and mode-specific requirements.
        """
        errors: list[str] = []

        if self.mode == "forwarder" and not self.forward_to:
            errors.append(
                "mode=forwarder requires SHRIKE_FORWARD_TO to be set"
            )

        if "splunk_hec" in self.destinations:
            if not self.splunk_hec_url:
                errors.append(
                    "destination 'splunk_hec' requires SPLUNK_HEC_URL to be set"
                )
            if not self.splunk_hec_token:
                errors.append(
                    "destination 'splunk_hec' requires SPLUNK_HEC_TOKEN to be set"
                )

        if "s3" in self.destinations:
            if not self.s3_endpoint:
                errors.append(
                    "destination 's3' requires S3_ENDPOINT to be set"
                )
            if not self.s3_bucket:
                errors.append(
                    "destination 's3' requires S3_BUCKET to be set"
                )

        return errors

    @classmethod
    def from_env(cls) -> Config:
        """Build Config from environment variables.

        Env var names follow the pattern SHRIKE_<FIELD> for core settings,
        and direct names (SPLUNK_HEC_URL, S3_BUCKET, etc.) for destinations.
        """

        def _str(key: str, default: str = "") -> str:
            return os.environ.get(key, default)

        def _int(key: str, default: int) -> int:
            raw = os.environ.get(key)
            return int(raw) if raw is not None else default

        def _list(key: str, default: list[str]) -> list[str]:
            raw = os.environ.get(key)
            if raw is None:
                return default
            return [s.strip() for s in raw.split(",") if s.strip()]

        return cls(
            mode=_str("SHRIKE_MODE", "full"),
            forward_to=_str("SHRIKE_FORWARD_TO"),
            syslog_port=_int("SHRIKE_SYSLOG_PORT", 1514),
            docker_log_path=_str("SHRIKE_DOCKER_LOG_PATH", "/var/lib/docker/containers"),
            otlp_grpc_port=_int("SHRIKE_OTLP_GRPC_PORT", 4317),
            otlp_http_port=_int("SHRIKE_OTLP_HTTP_PORT", 4318),
            http_port=_int("SHRIKE_HTTP_PORT", 8080),
            llm_url=_str("SHRIKE_LLM_URL"),
            llm_model=_str("SHRIKE_LLM_MODEL"),
            llm_api_key=_str("SHRIKE_LLM_API_KEY"),
            classifier_model=_str("SHRIKE_CLASSIFIER_MODEL"),
            ner_model=_str("SHRIKE_NER_MODEL"),
            ingest_api_key=_str("SHRIKE_INGEST_API_KEY"),
            destinations=_list("SHRIKE_DESTINATIONS", ["splunk_hec"]),
            wal_dir=_str("SHRIKE_WAL_DIR", "/data/wal"),
            wal_max_mb=_int("SHRIKE_WAL_MAX_MB", 500),
            splunk_hec_url=_str("SPLUNK_HEC_URL"),
            splunk_hec_token=_str("SPLUNK_HEC_TOKEN"),
            splunk_tls_verify=(
                _str("SHRIKE_SPLUNK_TLS_VERIFY", "true").lower() not in ("false", "0", "no")
            ),
            s3_endpoint=_str("S3_ENDPOINT"),
            s3_bucket=_str("S3_BUCKET"),
            s3_access_key=_str("S3_ACCESS_KEY"),
            s3_secret_key=_str("S3_SECRET_KEY"),
            s3_format=_str("S3_FORMAT", "parquet"),
            webhook_url=_str("WEBHOOK_URL"),
            webhook_auth_token=_str("WEBHOOK_AUTH_TOKEN"),
            forwarder_tls_insecure=(
                _str("SHRIKE_FORWARDER_TLS_INSECURE").lower() in ("true", "1", "yes")
            ),
            file_output_dir=_str("FILE_OUTPUT_DIR", "/data/output"),
        )

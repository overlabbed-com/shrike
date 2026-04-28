"""3-Tier extraction engine orchestrator.

Cascades through extraction tiers from fastest to slowest:
  Tier 1: PatternExtractor (deterministic, <10ms)
  Tier 2: PreparseExtractor (pre-parse + LLM mapping, ~200ms)
  Tier 3: SchemaInjectedExtractor (full LLM, ~750ms)

Each tier returns ExtractionResult or None (signaling fallthrough).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from shrike.detector.format_detector import LogFormat
from shrike.extractor.fingerprint_cache import FingerprintCache
from shrike.extractor.pattern_extractor import PatternExtractor
from shrike.extractor.preparsers import PreparsedFields, preparse
from shrike.extractor.schema_injected_extractor import (
    ExtractionResult,
    SchemaInjectedExtractor,
    _extract_json,
)
from shrike.extractor.template_miner import LogTemplateMiner

logger = logging.getLogger(__name__)


class PreparseExtractor:
    """Tier 2: Pre-parse fields then ask LLM to map to OCSF names.

    The LLM receives pre-parsed field names (not raw log) and outputs
    a field mapping. Values are looked up from the preparsed dict —
    the LLM never copies data, cutting output tokens by 3-4x.
    """

    MAPPING_SYSTEM = (
        "You are an OCSF field mapper. Given source field names and an OCSF class schema, "
        "output a JSON object mapping OCSF field names to source field names. "
        "Also include class_uid, class_name, category_uid, severity_id, and activity_id "
        "with their values (not mapped from source). Output ONLY valid JSON."
    )

    def __init__(
        self,
        schemas_dir: Path | None = None,
        api_base: str = "http://localhost:11434/v1",
        model: str = "shrike-extractor",
        api_key: str = "",
    ):
        self._schemas: dict[int, dict] = {}
        self._api_base = api_base.rstrip("/") if api_base else None
        if self._api_base and not self._api_base.startswith(("http://", "https://")):
            raise ValueError(f"LLM API URL must use http:// or https:// scheme, got: {api_base}")
        self._model = model
        self._api_key = api_key

        if schemas_dir is None:
            schemas_dir = Path(__file__).parent.parent.parent / "schemas" / "ocsf_v1.3" / "classes"
        if schemas_dir.exists():
            self._load_schemas(schemas_dir)

    def _load_schemas(self, schemas_dir: Path) -> None:
        for f in schemas_dir.glob("class_*.json"):
            try:
                import json
                with open(f) as fh:
                    schema = json.load(fh)
                self._schemas[schema["class_uid"]] = schema
            except Exception as e:
                logger.warning(f"Failed to load schema {f.name}: {e}")

    def try_extract(
        self,
        raw_log: str,
        log_format: LogFormat,
        class_uid: int,
        class_name: str,
    ) -> ExtractionResult | None:
        """Try pre-parse + LLM mapping extraction."""
        start = time.monotonic()

        # Step 1: Pre-parse
        preparsed = preparse(raw_log, log_format)
        if preparsed is None or len(preparsed.fields) < 2:
            return None  # Can't pre-parse this format

        # Step 2: Get schema
        schema = self._schemas.get(class_uid)
        if schema is None:
            return None

        # Step 3: Build mapping prompt
        source_fields = list(preparsed.fields.keys())
        # Remove internal fields from display
        display_fields = [f for f in source_fields if not f.startswith("_")]
        if not display_fields:
            display_fields = source_fields

        attrs = schema.get("attributes", {})
        ocsf_fields = []
        for name, spec in attrs.items():
            req = "REQUIRED" if spec.get("requirement") == "required" else spec.get("requirement", "optional")
            ocsf_fields.append(f"{name} ({req})")

        prompt = (
            f"Map source fields to OCSF {schema['class_name']} (class_uid: {class_uid}).\n"
            f"Source fields: {', '.join(display_fields)}\n"
            f"OCSF schema fields: {', '.join(ocsf_fields[:15])}\n"
            f"Output a JSON object with OCSF field names as keys and source field names as values.\n"
            f"Also set: class_uid={class_uid}, class_name=\"{schema['class_name']}\", "
            f"category_uid={class_uid // 1000}, severity_id (1-6), activity_id (0-99).\n"
            f"JSON:"
        )

        # Step 4: Call LLM
        try:
            response = self._call_api(prompt)
        except Exception:
            return None

        mapping = _extract_json(response)
        if mapping is None or not isinstance(mapping, dict):
            return None

        # Step 5: Apply mapping — look up values from preparsed fields
        event = self._apply_mapping(mapping, preparsed, class_uid, schema)
        elapsed = (time.monotonic() - start) * 1000

        return ExtractionResult(
            event=event,
            class_uid=class_uid,
            class_name=class_name,
            raw_log=raw_log,
            extraction_time_ms=elapsed,
        )

    def _apply_mapping(
        self,
        mapping: dict[str, Any],
        preparsed: PreparsedFields,
        class_uid: int,
        schema: dict,
    ) -> dict[str, Any]:
        """Build OCSF event by looking up mapped values from preparsed fields."""
        event: dict[str, Any] = {}

        for ocsf_field, value in mapping.items():
            if isinstance(value, str) and value in preparsed.fields:
                # It's a source field reference — look up the actual value
                event[ocsf_field] = preparsed.fields[value]
            else:
                # It's a literal value (class_uid, severity_id, etc.)
                event[ocsf_field] = value

        # Ensure class metadata
        event.setdefault("class_uid", class_uid)
        event.setdefault("class_name", schema.get("class_name", ""))
        event.setdefault("category_uid", class_uid // 1000)

        # Add timestamp from preparsed
        if "time" not in event and preparsed.timestamp:
            event["time"] = preparsed.timestamp

        return event

    def _call_api(self, user_prompt: str) -> str:
        """Call the LLM API for field mapping."""
        import json
        import urllib.request
        from urllib.parse import urlparse

        # Validate URL scheme - only allow http/https
        parsed = urlparse(self._api_base)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid API URL scheme: {parsed.scheme}. Only http/https allowed.")

        url = f"{self._api_base}/chat/completions"
        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": self.MAPPING_SYSTEM},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 256,
        }).encode()

        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {self._api_key}"} if self._api_key else {})},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
        return result["choices"][0]["message"]["content"]


class TieredExtractor:
    """Orchestrates 3-tier extraction: Pattern → Preparse+LLM → Full LLM."""

    def __init__(
        self,
        patterns_dir: Path | None = None,
        schemas_dir: Path | None = None,
        api_base: str = "http://localhost:11434/v1",
        model: str = "shrike-extractor",
        api_key: str = "",
        enable_tier1: bool = True,
        enable_tier2: bool = True,
        enable_tier3: bool = True,
    ):
        base = Path(__file__).parent.parent.parent
        if schemas_dir is None:
            schemas_dir = base / "schemas" / "ocsf_v1.3" / "classes"
        if patterns_dir is None:
            patterns_dir = base / "patterns"

        self._enable_tier1 = enable_tier1
        self._enable_tier2 = enable_tier2
        self._enable_tier3 = enable_tier3

        # Tier 0: Fingerprint cache (self-improving, O(1) lookup)
        cache_path = base / "data" / "fingerprint_cache.json"
        self._fingerprint_cache = FingerprintCache(cache_path=cache_path)

        # Tier 1.5a: NER extractor (SecureBERT 2.0 fine-tuned)
        from shrike.extractor.ner_extractor import NERExtractor
        ner_model_path = base / "models" / "shrike-ner"
        self._ner_extractor = NERExtractor(ner_model_path)

        # Tier 1.5b: Drain3 template miner (persisted across runs)
        template_cache_path = base / "data" / "template_cache.json"
        self._template_miner = LogTemplateMiner(save_path=template_cache_path)

        # Tier 1: Pattern library
        self._pattern_extractor = PatternExtractor(patterns_dir) if enable_tier1 else None

        # Tier 2: Pre-parse + LLM mapping
        self._preparse_extractor = PreparseExtractor(
            schemas_dir=schemas_dir, api_base=api_base, model=model, api_key=api_key,
        ) if enable_tier2 else None

        # Tier 3: Full LLM extraction
        self._full_extractor = SchemaInjectedExtractor(
            schemas_dir=schemas_dir, api_base=api_base, model=model, api_key=api_key,
        ) if enable_tier3 else None

    def extract(
        self,
        raw_log: str,
        log_format: LogFormat,
        class_uid: int,
        class_name: str = "",
    ) -> tuple[ExtractionResult, int]:
        """Extract OCSF fields using the fastest available tier.

        Returns (ExtractionResult, tier_number) where tier is 1, 2, or 3.
        """
        # Tier 0: Fingerprint cache (O(1) lookup, self-improving)
        if raw_log.strip().startswith("{"):
            try:
                import json as _json
                json_data = _json.loads(raw_log.strip())
                if isinstance(json_data, dict):
                    template = self._fingerprint_cache.lookup(json_data, class_uid)
                    if template:
                        event = self._fingerprint_cache.apply_template(template, json_data)
                        elapsed = (time.monotonic() - time.monotonic()) * 1000  # ~0ms
                        return ExtractionResult(
                            event=event,
                            class_uid=class_uid,
                            class_name=class_name or template.class_name,
                            raw_log=raw_log,
                            extraction_time_ms=0.0,
                            confidence={k: "cache" for k in event
                                       if k not in ("class_uid", "class_name", "category_uid",
                                                    "category_name", "activity_id", "severity_id")},
                        ), 0
            except Exception:
                pass

        # Tier 1: Pattern library (<10ms)
        if self._pattern_extractor:
            result = self._pattern_extractor.try_extract(raw_log, log_format, class_uid, class_name)
            if result is not None:
                # Learn from pattern extraction into cache
                if raw_log.strip().startswith("{"):
                    try:
                        json_data = _json.loads(raw_log.strip())
                        if isinstance(json_data, dict):
                            self._fingerprint_cache.learn(json_data, class_uid,
                                class_name or result.class_name, result.event, valid=True)
                    except Exception:
                        pass
                return result, 1

        # Tier 1.5a: NER extractor (SecureBERT 2.0 — ML entity extraction, ~10-50ms)
        if hasattr(self, '_ner_extractor') and self._ner_extractor.available:
            ner_result = self._ner_extractor.extract(raw_log, class_uid, class_name)
            if ner_result and ner_result["entity_count"] >= 3:
                from shrike.extractor.pattern_extractor import _set_nested
                event = {
                    "class_uid": class_uid,
                    "class_name": class_name,
                    "activity_id": 0,
                    "severity_id": 1,
                    "category_uid": class_uid // 1000,
                }
                confidence: dict[str, str] = {}
                for ocsf_path, value in ner_result["fields"].items():
                    _set_nested(event, ocsf_path, value)
                    confidence[ocsf_path] = "ner"
                return ExtractionResult(
                    event=event,
                    class_uid=class_uid,
                    class_name=class_name,
                    raw_log=raw_log,
                    extraction_time_ms=ner_result["elapsed_ms"],
                    confidence=confidence,
                ), 1  # Count as Tier 1 (fast, no LLM)

        # Tier 1.5b: Template miner (Drain3 — learned log structure, ~1ms)
        if hasattr(self, '_template_miner') and self._template_miner:
            tmpl_fields = self._template_miner.extract(raw_log)
            if tmpl_fields and len(tmpl_fields) >= 3:
                event = {
                    "class_uid": class_uid,
                    "class_name": class_name,
                    "activity_id": 0,
                    "severity_id": 1,
                    "category_uid": class_uid // 1000,
                }
                confidence: dict[str, str] = {}
                for ocsf_path, value in tmpl_fields.items():
                    from shrike.extractor.pattern_extractor import _set_nested, _coerce_value
                    _set_nested(event, ocsf_path, _coerce_value(str(value)) if isinstance(value, str) else value)
                    confidence[ocsf_path] = "template"
                return ExtractionResult(
                    event=event,
                    class_uid=class_uid,
                    class_name=class_name,
                    raw_log=raw_log,
                    extraction_time_ms=0.0,
                    confidence=confidence,
                ), 1  # Count as Tier 1 (fast, no LLM)

        # Tier 2: Pre-parse + LLM mapping (~200ms)
        if self._preparse_extractor:
            result = self._preparse_extractor.try_extract(raw_log, log_format, class_uid, class_name)
            if result is not None:
                # Learn from LLM extraction
                if raw_log.strip().startswith("{"):
                    try:
                        json_data = _json.loads(raw_log.strip())
                        if isinstance(json_data, dict):
                            self._fingerprint_cache.learn(json_data, class_uid,
                                class_name or result.class_name, result.event, valid=True)
                    except Exception:
                        pass
                return result, 2

        # Tier 3: Full LLM extraction (~750ms)
        if self._full_extractor:
            result = self._full_extractor.extract(raw_log, class_uid, class_name)
            # Learn from LLM extraction
            if raw_log.strip().startswith("{"):
                try:
                    json_data = _json.loads(raw_log.strip())
                    if isinstance(json_data, dict):
                        self._fingerprint_cache.learn(json_data, class_uid,
                            class_name or result.class_name, result.event, valid=True)
                except Exception:
                    pass
            return result, 3

        # No tiers enabled
        return ExtractionResult(
            event={"class_uid": class_uid, "raw_data": raw_log},
            class_uid=class_uid,
            class_name=class_name,
            raw_log=raw_log,
            error="No extraction tiers enabled",
        ), 0

    @property
    def pattern_count(self) -> int:
        return self._pattern_extractor.pattern_count if self._pattern_extractor else 0

    @property
    def pattern_sources(self) -> list[str]:
        return self._pattern_extractor.sources if self._pattern_extractor else []

    @property
    def cache_stats(self) -> dict:
        return self._fingerprint_cache.stats

    def save_cache(self):
        """Persist the fingerprint cache and template miner to disk."""
        self._fingerprint_cache.save()
        if self._template_miner:
            self._template_miner.save()

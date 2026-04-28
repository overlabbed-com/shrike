"""JSON fingerprint-based extraction cache — the self-improving engine.

When a JSON log is successfully extracted (by LLM or pattern), the fingerprint
(sorted top-level keys) and the field mapping are cached. Next time a log with
the same fingerprint arrives, the cached mapping is applied instantly — no LLM,
no pattern matching needed.

This is the JIT compiler for log parsing:
  - Cold start: LLM extracts → cache stores mapping
  - Warm: cached mapping applied in O(1)
  - Hot: promoted to permanent pattern after N consistent hits

The cache is the bridge between "LLM at runtime" and "patterns at compile time."
Over time, the LLM works itself out of a job.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CachedTemplate:
    """A learned extraction template from a successful LLM extraction."""
    fingerprint: str                    # Sorted top-level keys, pipe-separated
    class_uid: int
    class_name: str
    field_map: dict[str, str]           # source_field → ocsf_field
    static_fields: dict[str, Any]       # Always-set fields (class_uid, category, etc.)
    hit_count: int = 0
    last_hit: float = 0.0
    created: float = 0.0
    source: str = "llm"                 # "llm", "pattern", "manual"
    validation_passes: int = 0
    validation_fails: int = 0

    @property
    def confidence(self) -> float:
        """Confidence score based on hit count and validation rate."""
        if self.hit_count == 0:
            return 0.0
        total_validations = self.validation_passes + self.validation_fails
        if total_validations == 0:
            return 0.5
        val_rate = self.validation_passes / total_validations
        # Confidence increases with hits and validation rate
        hit_factor = min(self.hit_count / 10, 1.0)  # Saturates at 10 hits
        return val_rate * hit_factor

    @property
    def is_promotable(self) -> bool:
        """Whether this template should be promoted to a permanent pattern."""
        return (self.hit_count >= 3
                and self.confidence >= 0.8
                and self.validation_passes >= 2)


class FingerprintCache:
    """O(1) extraction cache keyed by JSON field fingerprints.

    Usage:
        cache = FingerprintCache()

        # Try cache first
        template = cache.lookup(json_data, class_uid)
        if template:
            event = cache.apply_template(template, json_data)
            # ... validate, done
        else:
            # Fall through to LLM
            event = llm_extract(raw_log)
            # Learn from the result
            cache.learn(json_data, class_uid, class_name, event)
    """

    def __init__(self, cache_path: Path | None = None, max_size: int = 10000):
        self._templates: dict[str, CachedTemplate] = {}  # fingerprint:class_uid → template
        self._max_size = max_size
        self._cache_path = cache_path
        self._hits = 0
        self._misses = 0

        if cache_path and cache_path.exists():
            self._load(cache_path)

    def _make_key(self, fingerprint: str, class_uid: int) -> str:
        return f"{fingerprint}:{class_uid}"

    def _fingerprint(self, json_data: dict) -> str:
        """Create a fingerprint from sorted top-level keys."""
        return "|".join(sorted(json_data.keys())[:12])

    def get(self, json_data: dict) -> CachedTemplate | None:
        return self.lookup(json_data, class_uid=0)


    def lookup(self, json_data: dict, class_uid: int) -> CachedTemplate | None:
        """Look up a cached extraction template for this JSON structure.

        Returns the template if found and confident, None otherwise.
        """
        fp = self._fingerprint(json_data)
        key = self._make_key(fp, class_uid)
        template = self._templates.get(key)

        if template and template.confidence >= 0.3:
            template.hit_count += 1
            template.last_hit = time.time()
            self._hits += 1
            return template

        self._misses += 1
        return None

    def apply_template(self, template: CachedTemplate, json_data: dict) -> dict[str, Any]:
        """Apply a cached template to extract OCSF fields from JSON data.

        This is the fast path — pure dict lookups, no LLM, no regex.
        """
        event: dict[str, Any] = {}

        # Apply static fields
        for k, v in template.static_fields.items():
            event[k] = v

        # Apply field map — look up values from JSON
        for source_field, ocsf_field in template.field_map.items():
            value = self._get_nested(json_data, source_field)
            if value is not None:
                self._set_nested(event, ocsf_field, value)

        # Ensure class metadata
        event["class_uid"] = template.class_uid
        event["class_name"] = template.class_name

        return event

    def set(self, json_data: dict, template: CachedTemplate) -> None:
        fp = self._fingerprint(json_data)
        key = self._make_key(fp, template.class_uid)
        self._templates[key] = template


    def learn(
        self,
        json_data: dict,
        class_uid: int,
        class_name: str,
        extracted_event: dict[str, Any],
        valid: bool = True,
    ) -> CachedTemplate:
        """Learn a new extraction template from a successful extraction.

        Analyzes which JSON fields mapped to which OCSF fields and stores
        the mapping for future use.
        """
        fp = self._fingerprint(json_data)
        key = self._make_key(fp, class_uid)

        # Check if we already have this template
        existing = self._templates.get(key)
        if existing:
            if valid:
                existing.validation_passes += 1
            else:
                existing.validation_fails += 1
            existing.hit_count += 1
            existing.last_hit = time.time()
            return existing

        # Build field map by matching extracted values back to JSON fields
        field_map = self._reverse_map(json_data, extracted_event)

        # Separate static fields (metadata that doesn't come from the JSON)
        static_fields = {}
        meta_keys = {"class_uid", "class_name", "category_uid", "category_name",
                     "activity_id", "severity_id"}
        for k in meta_keys:
            if k in extracted_event:
                static_fields[k] = extracted_event[k]

        template = CachedTemplate(
            fingerprint=fp,
            class_uid=class_uid,
            class_name=class_name,
            field_map=field_map,
            static_fields=static_fields,
            hit_count=1,
            last_hit=time.time(),
            created=time.time(),
            validation_passes=1 if valid else 0,
            validation_fails=0 if valid else 1,
        )

        # Evict oldest if at capacity
        if len(self._templates) >= self._max_size:
            self._evict()

        self._templates[key] = template
        return template

    def _reverse_map(self, json_data: dict, event: dict) -> dict[str, str]:
        """Reverse-engineer the field mapping by matching values.

        For each value in the extracted event, find the JSON field that
        contains the same value. This discovers the mapping automatically.
        """
        field_map: dict[str, str] = {}

        # Build a flat lookup of all JSON values
        json_flat: dict[str, Any] = {}
        def flatten(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    full = f"{prefix}.{k}" if prefix else k
                    json_flat[full] = v
                    if isinstance(v, dict):
                        flatten(v, full)
        flatten(json_data)

        # For each OCSF field, find a matching JSON value
        def walk_event(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    full = f"{prefix}.{k}" if prefix else k
                    if full in {"class_uid", "class_name", "category_uid",
                               "category_name", "activity_id", "severity_id"}:
                        continue
                    if isinstance(v, dict):
                        walk_event(v, full)
                    elif v is not None and str(v) != "unknown":
                        # Find this value in the JSON
                        for json_field, json_val in json_flat.items():
                            if json_val == v or str(json_val) == str(v):
                                field_map[json_field] = full
                                break
        walk_event(event)

        return field_map

    def _evict(self):
        """Evict the least recently used, lowest confidence templates."""
        if not self._templates:
            return
        # Sort by (confidence, last_hit) — evict lowest
        worst = min(self._templates.keys(),
                    key=lambda k: (self._templates[k].confidence, self._templates[k].last_hit))
        del self._templates[worst]

    def remove(self, json_data: dict, class_uid: int | None = None) -> bool:
        """Remove a template from the cache."""
        fp = self._fingerprint(json_data)
        uid = class_uid if class_uid is not None else 0
        key = self._make_key(fp, uid)
        if key in self._templates:
            del self._templates[key]
            return True
        return False

    def clear(self) -> None:
        """Remove all templates from the cache."""
        self._templates.clear()

    def cache_stats(self) -> dict:
        """Return cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0.0
        return {
            "templates": len(self._templates),
            "hits": self._hits,
            "misses": self._misses,
            "size": len(self._templates),
            "hit_rate": hit_rate,
        }

    def get_promotable(self) -> list[CachedTemplate]:
        """Get templates that are ready to be promoted to permanent patterns."""
        return [t for t in self._templates.values() if t.is_promotable]

    def save(self, path: Path | None = None):
        """Persist the cache to disk."""
        path = path or self._cache_path
        if path is None:
            return
        data = []
        for key, t in self._templates.items():
            data.append({
                "key": key,
                "fingerprint": t.fingerprint,
                "class_uid": t.class_uid,
                "class_name": t.class_name,
                "field_map": t.field_map,
                "static_fields": t.static_fields,
                "hit_count": t.hit_count,
                "created": t.created,
                "last_hit": t.last_hit,
                "source": t.source,
                "validation_passes": t.validation_passes,
                "validation_fails": t.validation_fails,
            })
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def _load(self, path: Path):
        """Load cache from disk."""
        try:
            with open(path) as f:
                data = json.load(f)
            for entry in data:
                template = CachedTemplate(
                    fingerprint=entry["fingerprint"],
                    class_uid=entry["class_uid"],
                    class_name=entry["class_name"],
                    field_map=entry["field_map"],
                    static_fields=entry["static_fields"],
                    hit_count=entry.get("hit_count", 0),
                    created=entry.get("created", 0),
                    last_hit=entry.get("last_hit", 0),
                    source=entry.get("source", "loaded"),
                    validation_passes=entry.get("validation_passes", 0),
                    validation_fails=entry.get("validation_fails", 0),
                )
                self._templates[entry["key"]] = template
        except Exception:
            pass

    @staticmethod
    def _get_nested(d: dict, dotted_path: str) -> Any:
        """Get a value from nested dict using dotted path."""
        parts = dotted_path.split(".")
        current = d
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    @staticmethod
    def _set_nested(d: dict, dotted_path: str, value: Any) -> None:
        """Set a value in nested dict using dotted path."""
        parts = dotted_path.split(".")
        for part in parts[:-1]:
            if part not in d:
                d[part] = {}
            elif not isinstance(d[part], dict):
                d[part] = {}
            d = d[part]
        d[parts[-1]] = value

    @property
    def size(self) -> int:
        return len(self._templates)

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    @property
    def stats(self) -> dict:
        return {
            "size": self.size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self.hit_rate, 3),
            "promotable": len(self.get_promotable()),
        }

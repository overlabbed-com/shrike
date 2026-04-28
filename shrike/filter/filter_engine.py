"""YAML-based filter pack engine for Shrike.

Evaluates keep/drop rules against classified log events.
This is Stage 3 of the Shrike pipeline — runs in <1ms per evaluation.

Filter packs are YAML files with ordered rules. First match wins.

Example:
    name: PCI-DSS
    rules:
      - keep: {classes: [3002, 3003, 3005, 4001, 4007]}
      - keep: {severity_id: {gte: 3}}
      - drop: {classes: [0]}
      - keep: all
"""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FilterResult:
    """Result of evaluating a filter pack."""
    action: str  # "keep" or "drop"
    rule_index: int  # Which rule matched (-1 if default)
    rule_description: str = ""


@dataclass
class FilterPack:
    """A loaded filter pack with evaluated rules."""
    name: str
    description: str = ""
    rules: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: Path) -> FilterPack:
        """Load a filter pack from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(
            name=data.get("name", path.stem),
            description=data.get("description", ""),
            rules=data.get("rules", []),
        )

    @classmethod
    def all_pass(cls) -> FilterPack:
        """Create a filter pack that keeps everything."""
        return cls(name="all-pass", rules=[{"keep": "all"}])

    def evaluate(
        self,
        class_uid: int,
        severity_id: int = 1,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> FilterResult:
        """Evaluate the filter pack against a classified event.

        Args:
            class_uid: The OCSF class UID from the classifier.
            severity_id: The severity ID (0-6).
            confidence: The classifier confidence (0.0-1.0).
            metadata: Optional additional metadata for rule evaluation.

        Returns:
            FilterResult with action ("keep" or "drop") and matched rule info.
        """
        for i, rule in enumerate(self.rules):
            if "keep" in rule:
                if self._matches(rule["keep"], class_uid, severity_id, confidence, metadata):
                    return FilterResult(action="keep", rule_index=i,
                                       rule_description=str(rule))
            elif "drop" in rule:
                if self._matches(rule["drop"], class_uid, severity_id, confidence, metadata):
                    return FilterResult(action="drop", rule_index=i,
                                       rule_description=str(rule))

        # Default: keep if no rules matched
        return FilterResult(action="keep", rule_index=-1, rule_description="default: keep")

    def _matches(
        self,
        condition: Any,
        class_uid: int,
        severity_id: int,
        confidence: float,
        metadata: dict[str, Any] | None,
    ) -> bool:
        """Check if a condition matches the event."""
        # "all" matches everything
        if condition == "all":
            return True

        if not isinstance(condition, dict):
            return False

        # Check class list
        if "classes" in condition:
            if class_uid not in condition["classes"]:
                return False

        # Check severity
        if "severity_id" in condition:
            sev_cond = condition["severity_id"]
            if isinstance(sev_cond, dict):
                if "gte" in sev_cond and severity_id < sev_cond["gte"]:
                    return False
                if "lte" in sev_cond and severity_id > sev_cond["lte"]:
                    return False
                if "eq" in sev_cond and severity_id != sev_cond["eq"]:
                    return False
            elif isinstance(sev_cond, int):
                if severity_id != sev_cond:
                    return False

        # Check confidence
        if "confidence" in condition:
            conf_cond = condition["confidence"]
            if isinstance(conf_cond, dict):
                if "gte" in conf_cond and confidence < conf_cond["gte"]:
                    return False
                if "lte" in conf_cond and confidence > conf_cond["lte"]:
                    return False

        # Check category (class_uid // 1000)
        if "categories" in condition:
            category = class_uid // 1000
            if category not in condition["categories"]:
                return False

        return True


class FilterEngine:
    """Manages multiple filter packs and evaluates events."""

    def __init__(self, packs_dir: Path | None = None):
        self._packs: dict[str, FilterPack] = {}
        self._active_pack: FilterPack = FilterPack.all_pass()
        self._evaluation_count: int = 0

        if packs_dir and packs_dir.exists():
            self.load_packs(packs_dir)

    def load_packs(self, packs_dir: Path) -> None:
        """Load all filter packs from a directory."""
        for f in packs_dir.glob("*.yaml"):
            try:
                pack = FilterPack.from_yaml(f)
                self._packs[pack.name] = pack
            except Exception as e:
                print(f"Warning: Failed to load filter pack {f}: {e}")

    def set_active(self, name: str) -> None:
        """Set the active filter pack by name."""
        if name in self._packs:
            self._active_pack = self._packs[name]
        else:
            raise KeyError(f"Filter pack '{name}' not found. Available: {list(self._packs.keys())}")

    def evaluate(self, class_uid: int, severity_id: int = 1, **kwargs) -> FilterResult:
        """Evaluate an event against the active filter pack."""
        self._evaluation_count += 1
        return self._active_pack.evaluate(class_uid, severity_id, **kwargs)

    @property
    def available_packs(self) -> list[str]:
        return list(self._packs.keys())

    def get_stats(self) -> dict[str, Any]:
        """Return filter engine statistics."""
        return {
            "packs_loaded": len(self._packs),
            "evaluations": self._evaluation_count,
            "active_pack": self._active_pack.name,
        }

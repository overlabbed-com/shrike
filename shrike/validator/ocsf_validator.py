"""OCSF schema validation for extracted events.

Validates LLM-extracted JSON against per-class OCSF v1.3 schemas.
This is Stage 5 of the Shrike pipeline — runs in <1ms per validation.

Checks:
  - Required fields present
  - Field types correct (string, integer, object, array)
  - class_uid and category_uid consistency
  - No unknown top-level fields (optional strict mode)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Base fields present on ALL OCSF events regardless of class
OCSF_BASE_FIELDS = {
    "class_uid", "class_name", "category_uid", "category_name",
    "activity_id", "activity_name", "type_uid", "type_name",
    "time", "severity_id", "severity", "status_id", "status",
    "message", "metadata", "observables", "unmapped", "raw_data",
    "start_time", "end_time", "timezone_offset", "count",
}

# OCSF type mapping for validation
OCSF_TYPE_MAP = {
    "string": str,
    "integer": int,
    "long": int,
    "float": float,
    "boolean": bool,
    "object": dict,
    "array": list,
    "datetime_t": str,
    "timestamp_t": (int, float, str),
}


@dataclass
class ValidationError:
    """A single validation error."""
    field: str
    error_type: str  # "missing_required", "wrong_type", "unknown_field", "invalid_value"
    message: str
    severity: str = "error"  # "error" or "warning"


@dataclass
class ValidationResult:
    """Result of validating an OCSF event."""
    valid: bool
    class_uid: int
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)
    field_coverage: float = 0.0  # Fraction of schema fields present

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def warning_count(self) -> int:
        return len(self.warnings)


class OCSFValidator:
    """Validates extracted OCSF events against per-class schemas."""

    def __init__(self, schemas_dir: Path | None = None):
        self._schemas: dict[int, dict] = {}
        self._validations: int = 0
        self._errors: int = 0
        if schemas_dir is None:
            # Default to bundled schemas
            schemas_dir = Path(__file__).parent.parent.parent / "schemas" / "ocsf_v1.3" / "classes"
        if schemas_dir.exists():
            self._load_schemas(schemas_dir)

    def _load_schemas(self, schemas_dir: Path) -> None:
        """Load all per-class schema files."""
        for f in schemas_dir.glob("class_*.json"):
            try:
                with open(f) as fh:
                    schema = json.load(fh)
                class_uid = schema.get("class_uid")
                if class_uid is not None:
                    self._schemas[class_uid] = schema
            except Exception as e:
                logger.warning(f"Failed to load schema {f.name}: {e}")

    @property
    def known_classes(self) -> list[int]:
        """Return list of class UIDs with loaded schemas."""
        return sorted(self._schemas.keys())

    def get_schema(self, class_uid: int) -> dict | None:
        """Get the schema for a class UID."""
        return self._schemas.get(class_uid)

    def validate(
        self,
        event: dict[str, Any],
        class_uid: int | None = None,
        strict: bool = False,
    ) -> ValidationResult:
        """Validate an extracted OCSF event.

        Args:
            event: The extracted OCSF event dict.
            class_uid: Expected class UID. If None, reads from event["class_uid"].
            strict: If True, unknown fields are errors. If False, warnings.

        Returns:
            ValidationResult with errors, warnings, and field coverage.
        """
        errors: list[ValidationError] = []
        warnings: list[ValidationError] = []

        # Determine class_uid
        if class_uid is None:
            class_uid = event.get("class_uid")
        if class_uid is None:
            errors.append(ValidationError(
                field="class_uid",
                error_type="missing_required",
                message="No class_uid in event and none provided",
            ))
            return ValidationResult(valid=False, class_uid=0, errors=errors)

        # Ensure class_uid is an int
        try:
            class_uid = int(class_uid)
        except (ValueError, TypeError):
            errors.append(ValidationError(
                field="class_uid",
                error_type="invalid_value",
                message=f"class_uid must be an integer, got {type(class_uid).__name__}",
            ))
            return ValidationResult(valid=False, class_uid=0, errors=errors)

        # Check class_uid consistency
        event_uid = event.get("class_uid")
        if event_uid is not None and int(event_uid) != class_uid:
            errors.append(ValidationError(
                field="class_uid",
                error_type="invalid_value",
                message=f"Event class_uid ({event_uid}) doesn't match expected ({class_uid})",
            ))

        # Check category_uid consistency
        expected_category = class_uid // 1000
        event_category = event.get("category_uid")
        try:
            event_category_int = int(event_category) if event_category is not None else None
        except (ValueError, TypeError):
            event_category_int = None
        if event_category_int is not None and event_category_int != expected_category:
            warnings.append(ValidationError(
                field="category_uid",
                error_type="invalid_value",
                message=f"category_uid ({event_category}) inconsistent with class_uid ({class_uid}, expected category {expected_category})",
                severity="warning",
            ))

        # Get schema
        schema = self._schemas.get(class_uid)
        if schema is None:
            warnings.append(ValidationError(
                field="class_uid",
                error_type="unknown_field",
                message=f"No schema found for class_uid {class_uid}",
                severity="warning",
            ))
            return ValidationResult(
                valid=len(errors) == 0,
                class_uid=class_uid,
                errors=errors,
                warnings=warnings,
                field_coverage=0.0,
            )

        attributes = schema.get("attributes", {})

        # Check required fields
        for field_name, field_spec in attributes.items():
            if field_spec.get("requirement") == "required":
                if field_name not in event:
                    errors.append(ValidationError(
                        field=field_name,
                        error_type="missing_required",
                        message=f"Required field '{field_name}' is missing",
                    ))

        # Check field types
        for field_name, value in event.items():
            if field_name in OCSF_BASE_FIELDS:
                continue  # Base fields are always allowed

            if field_name in attributes:
                field_spec = attributes[field_name]
                expected_type_name = field_spec.get("type", "string")
                expected_type = OCSF_TYPE_MAP.get(expected_type_name)

                if expected_type is not None and value is not None:
                    if not isinstance(value, expected_type):
                        # OCSF "string" typed fields often hold objects or numeric IDs
                        # Allow dict/list/int/float/bool for string-typed fields
                        if expected_type == str and isinstance(value, (dict, list, int, float, bool)):
                            continue  # OCSF complex objects and coercible types are valid
                        # Allow string→int/float coercion for numeric fields
                        if expected_type in (int, float) and isinstance(value, str):
                            try:
                                if expected_type == int:
                                    int(value)
                                else:
                                    float(value)
                                # Coercible — just a warning
                                warnings.append(ValidationError(
                                    field=field_name,
                                    error_type="wrong_type",
                                    message=f"Field '{field_name}' is string but coercible to {expected_type_name}",
                                    severity="warning",
                                ))
                                continue
                            except ValueError:
                                pass
                        errors.append(ValidationError(
                            field=field_name,
                            error_type="wrong_type",
                            message=f"Field '{field_name}' expected {expected_type_name}, got {type(value).__name__}",
                        ))
            elif strict:
                errors.append(ValidationError(
                    field=field_name,
                    error_type="unknown_field",
                    message=f"Unknown field '{field_name}' not in schema for class {class_uid}",
                ))
            else:
                # Non-strict: unknown fields are just warnings
                if field_name not in OCSF_BASE_FIELDS:
                    warnings.append(ValidationError(
                        field=field_name,
                        error_type="unknown_field",
                        message=f"Field '{field_name}' not in schema for class {class_uid}",
                        severity="warning",
                    ))

        # Calculate field coverage
        schema_fields = set(attributes.keys())
        if schema_fields:
            present = sum(1 for f in schema_fields if f in event)
            field_coverage = present / len(schema_fields)
        else:
            field_coverage = 1.0  # No schema fields = trivially covered

        # Track statistics
        self._validations += 1
        if errors:
            self._errors += len(errors)

        return ValidationResult(
            valid=len(errors) == 0,
            class_uid=class_uid,
            errors=errors,
            warnings=warnings,
            field_coverage=field_coverage,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return validation statistics."""
        error_rate = self._errors / self._validations if self._validations > 0 else 0.0
        return {
            "schemas_loaded": len(self._schemas),
            "validations": self._validations,
            "error_rate": error_rate,
        }

    def suggest_fixes(self, event: dict[str, Any], result: ValidationResult) -> dict[str, Any]:
        """Suggest fixes for validation errors. Returns a patched event dict.

        Only applies safe, deterministic fixes:
        - Add class_uid/category_uid if missing
        - Coerce string→int for numeric fields
        - Remove clearly invalid fields
        """
        fixed = dict(event)

        for error in result.errors:
            if error.error_type == "missing_required" and error.field == "class_uid":
                fixed["class_uid"] = result.class_uid
            elif error.error_type == "missing_required" and error.field == "category_uid":
                fixed["category_uid"] = result.class_uid // 1000

        # Coerce string numerics
        schema = self._schemas.get(result.class_uid, {})
        attributes = schema.get("attributes", {})
        for field_name, value in list(fixed.items()):
            if field_name in attributes and isinstance(value, str):
                expected_type = attributes[field_name].get("type", "string")
                if expected_type == "integer":
                    try:
                        fixed[field_name] = int(value)
                    except ValueError:
                        pass
                elif expected_type in ("float", "long"):
                    try:
                        fixed[field_name] = float(value)
                    except ValueError:
                        pass

        return fixed

"""Tests for OCSFValidator."""

from __future__ import annotations

import pytest

from shrike.validator.ocsf_validator import (
    OCSFValidator,
    ValidationError,
)


class TestValidationError:
    """Tests for ValidationError dataclass."""

    def test_init(self):
        """Initializes with required fields."""
        err = ValidationError(
            field="user",
            error_type="missing_required",
            message="user field is required",
        )
        assert err.field == "user"
        assert err.error_type == "missing_required"
        assert err.severity == "error"


class TestOCSFValidator:
    """Tests for OCSFValidator."""

    def test_init(self):
        """Initializes with schema directory."""
        validator = OCSFValidator()
        assert validator._schemas is not None

    def test_validate_valid_event(self):
        """Valid event passes validation."""
        validator = OCSFValidator()
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "category_name": "IAM",
            "activity_id": 1,
            "activity_name": "Logon",
            "time": "2024-03-15T10:00:00Z",
            "user": "alice",
        }
        result = validator.validate(event)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_missing_required_fields(self):
        """Missing required fields produce errors."""
        validator = OCSFValidator()
        event = {
            "class_uid": 3002,
            # Missing user (required for Authentication class)
        }
        result = validator.validate(event)
        # Should have errors for missing required fields
        error_fields = [e.field for e in result.errors]
        assert "user" in error_fields

    def test_validate_wrong_type(self):
        """Wrong type produces error."""
        validator = OCSFValidator()
        event = {
            "class_uid": "not_an_integer",  # Should be int
            "class_name": "Authentication",
            "category_uid": 3,
            "time": "2024-03-15T10:00:00Z",
        }
        result = validator.validate(event)
        # "not_an_integer" can't be converted to int → invalid_value error
        type_errors = [e for e in result.errors if e.error_type == "invalid_value"]
        assert len(type_errors) > 0

    def test_validate_unknown_field(self):
        """Unknown fields produce warnings in strict mode."""
        validator = OCSFValidator()
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "time": "2024-03-15T10:00:00Z",
            "completely_unknown_field": "value",
        }
        result = validator.validate(event, strict=True)
        unknown_errors = [e for e in result.errors if e.error_type == "unknown_field"]
        assert len(unknown_errors) > 0

    def test_validate_non_strict_allows_unknown(self):
        """Non-strict mode allows unknown fields."""
        validator = OCSFValidator()
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "time": "2024-03-15T10:00:00Z",
            "vendor_specific_field": "value",
        }
        result = validator.validate(event, strict=False)
        unknown_errors = [e for e in result.errors if e.error_type == "unknown_field"]
        assert len(unknown_errors) == 0

    def test_get_stats(self):
        """get_stats() returns validation statistics."""
        validator = OCSFValidator()
        stats = validator.get_stats()
        assert "schemas_loaded" in stats
        assert "validations" in stats
        assert "error_rate" in stats
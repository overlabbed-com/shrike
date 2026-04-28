"""Tests for S3/MinIO Parquet destination."""

import importlib.util
import pytest

# pyarrow is optional
pyarrow = importlib.util.find_spec("pyarrow")
pytestmark = pytest.mark.skipif(
    pyarrow is None,
    reason="pyarrow not installed",
)


import pytest

from shrike.destinations.s3_parquet import (
    S3ParquetDestination,
    _class_prefix,
    _flatten_event,
    _dicts_to_table,
)


class TestClassPrefix:
    """Test class UID to S3 prefix mapping."""

    def test_known_class_maps_to_prefix(self):
        assert _class_prefix(3002) == "authentication"
        assert _class_prefix(2004) == "threat_detection"
        assert _class_prefix(4001) == "connection"

    def test_unknown_class_maps_to_raw(self):
        assert _class_prefix(9999) == "raw"

    def test_none_maps_to_raw(self):
        assert _class_prefix(None) == "raw"


class TestFlattenEvent:
    """Test event flattening for Parquet."""

    def test_simple_dict(self):
        event = {"name": "test", "value": 42}
        result = _flatten_event(event)
        assert result == {"name": "test", "value": 42}

    def test_nested_dict(self):
        event = {"src_endpoint": {"ip": "1.2.3.4", "port": 22}}
        result = _flatten_event(event)
        assert result == {"src_endpoint.ip": "1.2.3.4", "src_endpoint.port": 22}

    def test_list_becomes_json_string(self):
        event = {"tags": ["tag1", "tag2"]}
        result = _flatten_event(event)
        assert result == {"tags": '["tag1", "tag2"]'}

    def test_deeply_nested(self):
        event = {"a": {"b": {"c": "deep"}}}
        result = _flatten_event(event)
        assert result == {"a.b.c": "deep"}


class TestDictsToTable:
    """Test PyArrow table conversion."""

    def test_empty_list(self):
        table = _dicts_to_table([])
        assert table.num_rows == 0

    def test_simple_dicts(self):
        data = [{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]
        table = _dicts_to_table(data)
        assert table.num_rows == 2
        assert table.num_columns == 2
        assert "name" in table.column_names
        assert "age" in table.column_names

    def test_none_values_handled(self):
        data = [{"name": "Alice", "value": 1}, {"name": "Bob", "value": None}]
        table = _dicts_to_table(data)
        assert table.num_rows == 2


@pytest.mark.skip(reason="Requires S3 bucket configuration")
class TestS3ParquetDestinationIntegration:
    """Integration tests for S3 destination. Requires real S3/MinIO."""

    @pytest.fixture
    def destination(self):
        # Requires env vars: S3_ENDPOINT_URL, S3_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
        import os

        if not os.getenv("S3_BUCKET"):
            pytest.skip("S3_BUCKET not configured")

        return S3ParquetDestination(
            bucket=os.environ["S3_BUCKET"],
            prefix="test-shrike",
            endpoint_url=os.getenv("S3_ENDPOINT_URL"),
        )

    @pytest.mark.asyncio
    async def test_send_batch(self, destination):
        events = [
            {"class_uid": 3002, "user": "test", "src_endpoint": {"ip": "1.2.3.4"}},
            {"class_uid": 3002, "user": "test2", "src_endpoint": {"ip": "5.6.7.8"}},
        ]
        result = await destination.send_batch(events)
        assert result.accepted == 2
        assert result.rejected == 0

    @pytest.mark.asyncio
    async def test_health(self, destination):
        health = await destination.health()
        assert health.healthy

    @pytest.mark.asyncio
    async def test_close(self, destination):
        await destination.close()

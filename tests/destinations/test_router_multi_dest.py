"""Tests for multi-destination routing."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pathlib import Path

import pytest

from shrike.destinations.router import DestinationRouter
from shrike.destinations.wal import WriteAheadLog


@pytest.fixture
def wal_dir(tmp_path: Path) -> Path:
    d = tmp_path / "wal"
    d.mkdir()
    return d


class FakeDestination:
    """Fake destination for testing."""

    def __init__(self, name: str, wal: WriteAheadLog) -> None:
        self.name = name
        self.wal = wal


class TestRouterMultiDestination:
    """Tests for multi-destination routing (3+ destinations)."""

    async def test_three_destinations_all_succeed(self, wal_dir: Path) -> None:
        """3 destinations, all succeed."""
        wal_a = WriteAheadLog("dest_a", wal_dir)
        wal_b = WriteAheadLog("dest_b", wal_dir)
        wal_c = WriteAheadLog("dest_c", wal_dir)

        router = DestinationRouter([
            FakeDestination("dest_a", wal_a),
            FakeDestination("dest_b", wal_b),
            FakeDestination("dest_c", wal_c),
        ])

        events = [{"n": 1}, {"n": 2}]
        results = await router.route(events)

        assert len(results) == 3
        assert results["dest_a"].accepted == 2
        assert results["dest_b"].accepted == 2
        assert results["dest_c"].accepted == 2

    async def test_three_destinations_one_fails_others_continue(self, wal_dir: Path) -> None:
        """3 destinations, one WAL full, others still deliver."""
        wal_overflow = WriteAheadLog("overflow", wal_dir, max_size_mb=0)
        wal_ok1 = WriteAheadLog("ok1", wal_dir)
        wal_ok2 = WriteAheadLog("ok2", wal_dir)

        router = DestinationRouter([
            FakeDestination("overflow", wal_overflow),
            FakeDestination("ok1", wal_ok1),
            FakeDestination("ok2", wal_ok2),
        ])

        events = [{"n": 1}]
        results = await router.route(events)

        # Overflow destination: WAL at capacity
        assert results["overflow"].accepted == 0
        assert results["overflow"].retryable == 0

        # Others succeed
        assert results["ok1"].accepted == 1
        assert results["ok2"].accepted == 1

    async def test_wal_overflow_on_one_destination_others_continue(self, wal_dir: Path) -> None:
        """WAL overflow on one destination does not affect others."""
        wal_overflow = WriteAheadLog("dest_overflow", wal_dir, max_size_mb=0)
        wal_ok = WriteAheadLog("dest_ok", wal_dir)

        router = DestinationRouter([
            FakeDestination("dest_overflow", wal_overflow),
            FakeDestination("dest_ok", wal_ok),
        ])

        events = [{"event": "test"}]
        results = await router.route(events)

        # Overflow: accepted=0, not rejected (events not written to WAL)
        assert results["dest_overflow"].accepted == 0
        assert results["dest_overflow"].retryable == 0
        assert "WAL at capacity" in results["dest_overflow"].errors[0]

        # OK destination unaffected
        assert results["dest_ok"].accepted == 1
        assert results["dest_ok"].rejected == 0
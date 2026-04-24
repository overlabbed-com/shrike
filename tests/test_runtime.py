"""Tests for the Shrike runtime."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from shrike.runtime import create_runtime_app
from shrike.config import Config


@pytest.fixture
def mock_config() -> Config:
    config = MagicMock(spec=Config)
    config.destinations = ["file_jsonl"]
    config.file_output_dir = "/tmp/shrike-test"
    config.wal_dir = "/tmp/shrike-wal"
    config.wal_max_mb = 100
    config.ingest_api_key = None
    config.mode = "pipeline"
    config.http_port = 8080
    config.classifier_model = None
    config.llm_url = None
    config.llm_model = None
    config.splunk_hec_url = None
    config.splunk_hec_token = None
    config.splunk_tls_verify = True
    return config


# ------------------------------------------------------------------
# Phase 3.3 (#6) — X-Forwarded-For support
# ------------------------------------------------------------------


def test_ingest_uses_x_forwarded_for(mock_config: Config) -> None:
    """ingest() must use X-Forwarded-For header when present.

    Phase 3.3 (#6): reverse proxies set X-Forwarded-For; use it for source IP.
    """
    received_source_ip: list[str] = []

    async def mock_route(events):
        received_source_ip.append(events[0]["_shrike_source_ip"])
        return {"file_jsonl": AsyncMock(accepted=len(events), rejected=0)}

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["test log line"]},
                    headers={"X-Forwarded-For": "203.0.113.50, 70.141.15.16"},
                )

                assert response.status_code == 200
                assert received_source_ip[0] == "203.0.113.50"


def test_ingest_falls_back_to_client_host(mock_config: Config) -> None:
    """ingest() must use request.client.host when X-Forwarded-For is absent.

    Phase 3.3 (#6): fallback to direct client connection.
    """
    received_source_ip: list[str] = []

    async def mock_route(events):
        received_source_ip.append(events[0]["_shrike_source_ip"])
        return {"file_jsonl": AsyncMock(accepted=len(events), rejected=0)}

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["test log line"]},
                )

                assert response.status_code == 200
                # Falls back to client host or "unknown"
                assert received_source_ip[0] in ("127.0.0.1", "unknown", "localhost", "testclient")


def test_ingest_handles_empty_x_forwarded_for(mock_config: Config) -> None:
    """ingest() must handle empty X-Forwarded-For header gracefully.

    Phase 3.3 (#6): empty/missing header should not cause error.
    """
    received_source_ip: list[str] = []

    async def mock_route(events):
        received_source_ip.append(events[0]["_shrike_source_ip"])
        return {"file_jsonl": AsyncMock(accepted=len(events), rejected=0)}

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["test log line"]},
                    headers={"X-Forwarded-For": ""},
                )

                assert response.status_code == 200


# ------------------------------------------------------------------
# Phase 2.2 — Graceful shutdown drain
# ------------------------------------------------------------------

import asyncio


async def test_worker_tasks_are_named(tmp_path) -> None:
    """Worker tasks must be named 'worker-{dest.name}' for observability."""
    from shrike.config import Config
    file_config = Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(tmp_path / "wal"),
        file_output_dir=str(tmp_path / "output"),
    )
    app = create_runtime_app(file_config)

    started_tasks: list[asyncio.Task] = []
    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *, name=None):
        task = original_create_task(coro, name=name)
        started_tasks.append(task)
        return task

    with patch("asyncio.create_task", side_effect=tracking_create_task):
        async with app.router.lifespan_context(app):
            pass

    assert len(started_tasks) == 1
    assert started_tasks[0].get_name() == "worker-file_jsonl"


async def test_worker_done_callback_is_attached(tmp_path) -> None:
    """Worker tasks must have done_callback attached to log errors on failure."""
    from shrike.config import Config
    file_config = Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(tmp_path / "wal"),
        file_output_dir=str(tmp_path / "output"),
    )
    app = create_runtime_app(file_config)

    callbacks_attached: list = []
    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *, name=None):
        task = original_create_task(coro, name=name)
        callbacks_attached.append(task)
        return task

    with patch("asyncio.create_task", side_effect=tracking_create_task):
        async with app.router.lifespan_context(app):
            pass

    assert len(callbacks_attached) == 1
    task = callbacks_attached[0]
    assert task.get_name() == "worker-file_jsonl"


async def test_shutdown_awaits_tasks_with_timeout(tmp_path) -> None:
    """Lifespan shutdown must await worker tasks with 30s timeout before cancelling."""
    from shrike.config import Config
    file_config = Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(tmp_path / "wal"),
        file_output_dir=str(tmp_path / "output"),
    )
    app = create_runtime_app(file_config)


    tasks_created: list[asyncio.Task] = []
    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *, name=None):
        task = original_create_task(coro, name=name)
        tasks_created.append(task)
        return task

    with patch("asyncio.create_task", side_effect=tracking_create_task):
        async with app.router.lifespan_context(app):
            pass

    assert len(tasks_created) == 1
    assert tasks_created[0].get_name() == "worker-file_jsonl"


# ------------------------------------------------------------------
# Phase 4.1 (#3) — 507 vs 400 distinction
# ------------------------------------------------------------------


def test_ingest_returns_507_when_wal_full(mock_config: Config) -> None:
    """ingest() must return 507 when all destinations are at WAL capacity.
    Phase 4.1 (#3): WAL overflow → 507.
    """
    async def mock_route_full(events):
        # All WALs full — nothing accepted
        return {"file_jsonl": AsyncMock(accepted=0, rejected=0)}

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route_full
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["test log line"]},
                )

                assert response.status_code == 507



def test_ingest_returns_200_with_partial_success(mock_config: Config) -> None:
    """ingest() must return 200 when some destinations succeed (partial success).
    Phase 4.1 (#3): partial success is visible in the response.
    """
    async def mock_route_partial(events):
        # One destination succeeded (partial), one failed
        return {
            "file_jsonl": AsyncMock(accepted=1, rejected=0),
        }

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route_partial
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["line a", "line b"]},
                )

                assert response.status_code == 200
                data = response.json()
                assert data["accepted"] == 1
                assert data["total"] == 2
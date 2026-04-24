"""Shrike production runtime — HTTP ingestion, pipeline, and destinations.

Starts the production stack:
1. HTTP server with /v1/ingest (receives logs from fluent-bit or direct HTTP)
2. WAL-backed destination fan-out (Splunk HEC, file/JSONL, etc.)

Usage:
    python -m shrike.runtime
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import signal
import time
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StringConstraints

import uvicorn

from shrike.config import Config
from shrike.destinations.file_jsonl import FileJSONLDestination
from shrike.destinations.router import DestinationRouter
from shrike.destinations.splunk_hec import SplunkHECDestination
from shrike.destinations.worker import DestinationWorker

logger = logging.getLogger("shrike.runtime")

# Destination factory
_DEST_FACTORIES = {
    "splunk_hec": lambda cfg: SplunkHECDestination(
        url=cfg.splunk_hec_url, token=cfg.splunk_hec_token, wal_dir=cfg.wal_dir,
        tls_verify=cfg.splunk_tls_verify, max_size_mb=cfg.wal_max_mb,
    ),
    "file_jsonl": lambda cfg: FileJSONLDestination(
        output_dir=cfg.file_output_dir, wal_dir=cfg.wal_dir, max_size_mb=cfg.wal_max_mb,
    ),
}


def create_runtime_app(config: Config) -> FastAPI:
    """Create FastAPI app with pipeline and destination fan-out."""
    destinations = []
    workers = []
    worker_tasks = []

    # Load the normalization pipeline
    _pipeline = None
    try:
        from shrike.pipeline import ShrikePipeline
        _pipeline = ShrikePipeline(
            classifier_model=config.classifier_model or None,
            extractor_api=config.llm_url or "http://localhost:11434/v1",
            extractor_model=config.llm_model or "shrike-extractor",
        )
        logger.info("Normalization pipeline loaded — %d classes",
                     len(_pipeline.known_classes) if hasattr(_pipeline, 'known_classes') else 0)
    except Exception as e:
        logger.warning("Pipeline not available, raw passthrough mode: %s", e)

    for name in config.destinations:
        factory = _DEST_FACTORIES.get(name)
        if factory:
            destinations.append(factory(config))
        else:
            logger.warning("Unknown destination: %s", name)

    router = DestinationRouter(destinations)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        for dest in destinations:
            w = DestinationWorker(dest, dest.wal)
            workers.append(w)
            worker_tasks.append(asyncio.create_task(w.run()))
        logger.info("Started %d destination workers", len(workers))
        yield
        for w in workers:
            w.stop()
        for t in worker_tasks:
            t.cancel()
        for dest in destinations:
            await dest.close()
        logger.info("Destination workers stopped")

    app = FastAPI(title="Shrike Runtime", version="0.1.0", lifespan=lifespan)

    # Auth dependency
    async def verify_auth(authorization: str | None = Header(None)):
        if not config.ingest_api_key:
            return
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Bearer token required")
        if not hmac.compare_digest(authorization[7:], config.ingest_api_key):
            raise HTTPException(status_code=401, detail="Invalid token")

    class IngestRequest(BaseModel):
        logs: Annotated[
            list[Annotated[str, StringConstraints(max_length=65536)]],
            Field(max_length=10000),
        ]

    @app.get("/health")
    async def health():
        dest_health = {}
        all_healthy = True
        for dest in destinations:
            h = await dest.health()
            dest_health[dest.name] = {
                "healthy": h.healthy,
                "pending": h.pending,
                "disk_usage_mb": round(h.disk_usage_mb, 2),
            }
            if not h.healthy:
                all_healthy = False
        return {
            "status": "healthy" if all_healthy else "degraded",
            "mode": config.mode,
            "pipeline": "active" if _pipeline else "passthrough",
            "destinations": dest_health,
        }

    @app.post("/v1/ingest", dependencies=[Depends(verify_auth)])
    async def ingest(body: IngestRequest, request: Request):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        source_ip = request.client.host if request.client else "unknown"

        events = []
        for raw_log in body.logs:
            if _pipeline:
                result = _pipeline.process(raw_log)
                if not result.dropped:
                    rd = result.to_dict()
                    # Extract the OCSF event (class_uid, fields) and merge metadata
                    event = rd.get("event", {})
                    event["_shrike_metadata"] = rd.get("metadata", {})
                    event["_shrike_received_at"] = now
                    event["_shrike_source_ip"] = source_ip
                    events.append(event)
            else:
                events.append({
                    "raw_event": raw_log,
                    "category_uid": None,
                    "_shrike_received_at": now,
                    "_shrike_source_ip": source_ip,
                })

        if not events:
            return {"accepted": 0, "total": len(body.logs), "normalized": 0}

        results = await router.route(events)
        total_accepted = sum(r.accepted for r in results.values())

        if total_accepted == 0 and events:
            raise HTTPException(status_code=507, detail="All destinations at capacity")

        return {
            "accepted": total_accepted,
            "total": len(body.logs),
            "normalized": len(events),
        }

    # Also expose the original normalize/batch endpoints
    if _pipeline:
        from fastapi.responses import JSONResponse

        class NormalizeRequest(BaseModel):
            raw_log: str

        class BatchRequest(BaseModel):
            logs: list[str]

        @app.post("/normalize")
        async def normalize(req: NormalizeRequest):
            result = _pipeline.process(req.raw_log)
            return JSONResponse(content=result.to_dict())

        @app.post("/batch")
        async def batch(req: BatchRequest):
            results = _pipeline.process_batch(req.logs)
            return JSONResponse(content=[r.to_dict() for r in results if not r.dropped])

    return app


def main():
    """Start shrike production runtime."""
    os.umask(0o077)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    )

    config = Config.from_env()
    errors = config.validate()
    if errors:
        for err in errors:
            logger.error("Config error: %s", err)
        raise SystemExit(1)

    logger.info("Shrike runtime v0.1.0 — destinations=%s", config.destinations)

    app = create_runtime_app(config)

    shutdown_event = asyncio.Event()

    async def run():
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, shutdown_event.set)

        uvi_config = uvicorn.Config(
            app, host="0.0.0.0", port=config.http_port, log_level="warning",
        )
        server = uvicorn.Server(uvi_config)

        async def shutdown_watcher():
            await shutdown_event.wait()
            logger.info("Shutdown signal received")
            server.should_exit = True

        await asyncio.gather(
            server.serve(),
            shutdown_watcher(),
        )

    asyncio.run(run())


if __name__ == "__main__":
    main()

# Shrike — Security Data Platform
# Any log in, triaged OCSF out.
#
# Build:
#   docker build -t shrike .
#
# Run (models are bundled — no volume mount needed):
#   docker run -p 8080:8080 shrike

# Stage 1: Shrike runtime
FROM python:3.12-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps — install in layers for cache efficiency
# Layer 1: Core runtime (FastAPI, uvicorn, aiohttp)
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

# Layer 2: Engine deps (YAML patterns, field aliases, drain3)
RUN pip install --no-cache-dir \
    pyyaml \
    drain3

# Layer 3: ML deps (classifier + NER — largest layer, ~1.5GB)
# These are lazy-loaded: container works without them (pattern-only mode)
# but classifier and NER need them
RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir \
    transformers \
    sentence-transformers \
    numpy

# Application code
COPY pyproject.toml README.md ./
COPY shrike/ shrike/
RUN pip install --no-cache-dir --no-deps .

# Static assets (patterns, schemas, aliases, filters)
COPY patterns/ patterns/
COPY schemas/ schemas/
COPY data/field_aliases.json data/field_aliases.json
COPY filters/ filters/

# ML models (bundled via Git LFS — ~830MB total)
# Override at runtime: docker run -v /path/to/models:/app/models:ro shrike
COPY models/ocsf-classifier/ models/ocsf-classifier/
COPY models/shrike-ner/ models/shrike-ner/
RUN mkdir -p data/ground_truth

# Runtime directories
RUN mkdir -p /data/wal /data/output /run/shrike

# Non-root user
RUN addgroup --system shrike && \
    adduser --system --ingroup shrike shrike && \
    chown -R shrike:shrike /data /run/shrike /app

# Ports
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

USER shrike

# Default: production runtime server (HTTP API + Splunk HEC)
# Override for CLI: docker run shrike python -m shrike.cli --input /data/logs.txt
CMD ["python", "-m", "shrike.runtime"]

# ===== TEST STAGE =====
# Build: docker build --target test -t shrike-test .
# Run:  docker compose --profile test run --rm test
# Or:   docker compose run --profile test --rm test
FROM python:3.12-slim AS test
WORKDIR /shrike
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]"
COPY tests/ tests/
COPY shrike/ shrike/
COPY patterns/ patterns/
COPY schemas/ schemas/
COPY data/ data/
COPY filters/ filters/
CMD ["python", "-m", "pytest", "tests/unit/", "tests/test_server.py", "tests/test_config.py", "-q"]

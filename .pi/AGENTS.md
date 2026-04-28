# shrike (overlabbed-com) — Pi Agent Context

Shrike is an open-source security data platform that normalizes raw logs to OCSF v1.3 and routes them to SIEMs, observability stacks, or archives.

## What This Repo Does

Accepts syslog, JSON, CEF, LEEF, and 14 other log formats. Outputs structured, validated OCSF v1.3 events. Designed to be the normalization layer between raw log sources and downstream consumers (Splunk, Elasticsearch, S3, etc.).

## Key Directories

```
data/              — Persistent data (mappings, state)
docs/
  assets/          — Shrike wordmark, diagrams
Dockerfile         — Container build
ARCHITECTURE.md    — System architecture
CONTRIBUTING.md    — Contribution guide
TODO.md            — Known gaps and roadmap
```

## Tech Stack

- Python 3.12+
- Docker-ready (Dockerfile included)
- OCSF v1.3 schema compliance

## Development

```bash
# Build container
docker build -t shrike .

# Run locally (see ARCHITECTURE.md for config)
docker run shrike
```

Check CONTRIBUTING.md for development setup and test instructions.

## Branch Pattern

`feature/<description>` or `fix/<description>`

## Relationship to homelab

The homelab runs Shrike on dockp01 and dockp04. Deployment config lives in `tmt-homelab/homelab-security/stacks/dockp01-shrike/` and `dockp04-shrike/`. Development of Shrike happens here; deployment is separate.

## PORTABLE CODE RULES — CRITICAL

This is an overlabbed-com repo. Shrike is open-source and must be deployable by anyone.

- **No homelab IPs** (no `192.168.20.*`)
- **No dockp* hostnames**
- **No homelab-specific SIEM destinations** hardcoded
- All destinations (Splunk HEC URL, etc.) must come from config/env vars
- Default config should use generic examples (`splunk.example.com`, `192.0.2.x`)
- Homelab deployment details belong in `tmt-homelab/homelab-security`, not here

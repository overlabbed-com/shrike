"""Drain3-based template miner for automatic log structure discovery.

Learns log templates (static vs variable parts) from raw traffic.
Maps variable positions to entity types via regex classification.
Produces extraction templates that the pattern engine can use.

This is the bridge between "unseen freetext" and "structured extraction"
without writing per-source regex patterns.

Architecture:
  1. Feed raw logs to Drain3 → discovers templates
  2. For each template, collect variable values across instances
  3. Classify each variable position by entity type (IP, port, user, etc.)
  4. Map entity types to OCSF fields via the alias table
  5. Apply learned templates to new logs for instant extraction

Usage:
    miner = LogTemplateMiner()
    miner.train(["log1", "log2", ...])  # Learn from batch
    result = miner.extract("new log")    # Extract using learned templates
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig


# Entity type classifiers — applied to values at each variable position
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
IP_PORT_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$")
PORT_RE = re.compile(r"^\d{1,5}$")
TIMESTAMP_HMS_RE = re.compile(r"^\d{2}:\d{2}:\d{2}$")
PID_BRACKET_RE = re.compile(r"^\w+\[\d+\]:?$")
MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
PATH_RE = re.compile(r"^/[\w./\-]+$")
HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")


@dataclass
class VariableSlot:
    """A variable position in a log template."""
    position: int
    entity_type: str        # "ip", "port", "user", "hostname", "timestamp", etc.
    ocsf_hint: str          # Suggested OCSF field path
    sample_values: list[str] = field(default_factory=list)


@dataclass
class LearnedTemplate:
    """A log template learned from traffic."""
    template_str: str                # "Accepted password for <*> from <*> port <*>"
    cluster_size: int                # How many logs matched this template
    variables: list[VariableSlot]    # Variable slots with entity types
    static_tokens: list[str]         # Non-variable tokens


# Context-aware OCSF mapping: (entity_type, preceding_static_token) → OCSF path
# The preceding token disambiguates: "from <IP>" = src, "to <IP>" = dst
CONTEXT_OCSF_MAP: dict[tuple[str, str], str] = {
    ("ip", "from"): "src_endpoint.ip",
    ("ip", "src"): "src_endpoint.ip",
    ("ip", "SRC"): "src_endpoint.ip",
    ("ip", "source"): "src_endpoint.ip",
    ("ip", "client"): "src_endpoint.ip",
    ("ip", "to"): "dst_endpoint.ip",
    ("ip", "dst"): "dst_endpoint.ip",
    ("ip", "DST"): "dst_endpoint.ip",
    ("ip", "dest"): "dst_endpoint.ip",
    ("ip", "destination"): "dst_endpoint.ip",
    ("ip", "server"): "dst_endpoint.ip",
    ("ip", "->"): "dst_endpoint.ip",
    ("port", "port"): "src_endpoint.port",
    ("port", "SPT"): "src_endpoint.port",
    ("port", "DPT"): "dst_endpoint.port",
    ("user", "for"): "user",
    ("user", "user"): "user",
    ("user", "User"): "user",
    ("user", "by"): "actor.user.name",
    ("hostname", ""): "device.hostname",
    ("process_ref", ""): "process.name",
    ("timestamp", ""): "time",
    ("path", ""): "process.file.path",
    ("email", ""): "user",
}

# Fallback: entity_type → default OCSF path (when no context match)
DEFAULT_OCSF_MAP: dict[str, str] = {
    "ip": "src_endpoint.ip",
    "port": "src_endpoint.port",
    "user": "user",
    "hostname": "device.hostname",
    "timestamp": "time",
    "process_ref": "process.name",
    "path": "process.file.path",
    "email": "user",
    "integer": "metadata.count",
    "string": "",  # Can't map without context
}


KV_TOKEN_RE = re.compile(r'^(\w+)="?([^"]*)"?$')
DURATION_RE = re.compile(r"^\d+\.\d+(?:ms|s|m|h)?$")
COMMA_NUM_RE = re.compile(r"^\d{1,3}(?:,\d{3})+$")  # "1,234" style


def classify_entity(value: str) -> str:
    """Classify a variable value into an entity type."""
    # KV token: key="value" — these are structured, not single entities
    if KV_TOKEN_RE.match(value):
        return "kv_token"
    if IP_RE.match(value):
        return "ip"
    if IP_PORT_RE.match(value):
        return "ip_port"
    if TIMESTAMP_HMS_RE.match(value):
        return "timestamp"
    if PID_BRACKET_RE.match(value):
        return "process_ref"
    if MAC_RE.match(value):
        return "mac"
    if EMAIL_RE.match(value):
        return "email"
    if PATH_RE.match(value):
        return "path"
    if DURATION_RE.match(value):
        return "duration"  # "7.94ms" is NOT a username
    if HEX_RE.match(value):
        return "hex"
    # Port check — only if > 1 and plausibly a port (not a day of month)
    if value.isdigit():
        n = int(value)
        if 1024 <= n <= 65535:
            return "port"
        return "integer"
    # Short alphanumeric
    if len(value) <= 32 and re.match(r"^[\w.\-]+$", value):
        # Contains dots + letters = likely hostname
        if "." in value and not value[0].isdigit():
            return "hostname"
        # All lowercase, no digits = likely username
        if value.isalpha() and len(value) >= 3:
            return "user"
        return "string"
    return "string"


class LogTemplateMiner:
    """Drain3-based log template miner with OCSF field mapping."""

    def __init__(
        self,
        sim_threshold: float = 0.4,
        depth: int = 4,
        save_path: Path | str | None = None,
    ):
        self._sim_threshold = sim_threshold
        self._depth = depth
        config = TemplateMinerConfig()
        config.drain_sim_th = sim_threshold
        config.drain_depth = depth
        config.profiling_enabled = False
        self._miner = TemplateMiner(config=config)
        self._templates: dict[int, LearnedTemplate] = {}
        # Track variable values per cluster per position
        self._var_values: dict[int, dict[int, list[str]]] = {}
        self._save_path: Path | None = Path(save_path) if save_path else None

        if self._save_path and self._save_path.exists():
            self.load(self._save_path)

    def train(self, logs: list[str]) -> int:
        """Feed a batch of logs to learn templates.

        Returns the number of distinct templates discovered.
        """
        for log in logs:
            result = self._miner.add_log_message(log)
            cluster_id = result["cluster_id"]

            # Track variable values for this cluster
            if cluster_id not in self._var_values:
                self._var_values[cluster_id] = {}

            template_str = result["template_mined"]
            tmpl_tokens = template_str.split()
            log_tokens = log.split()

            # Align tokens and record variable values
            for i, tmpl_tok in enumerate(tmpl_tokens):
                if tmpl_tok == "<*>" and i < len(log_tokens):
                    if i not in self._var_values[cluster_id]:
                        self._var_values[cluster_id][i] = []
                    self._var_values[cluster_id][i].append(log_tokens[i])

        # Build learned templates
        self._templates.clear()
        for cluster in self._miner.drain.clusters:
            if cluster.size < 2:
                continue  # Need at least 2 instances to generalize

            template_str = cluster.get_template()
            tmpl_tokens = template_str.split()
            var_positions = [i for i, t in enumerate(tmpl_tokens) if t == "<*>"]
            static_tokens = [t for t in tmpl_tokens if t != "<*>"]

            # Classify each variable position
            variables: list[VariableSlot] = []
            for pos in var_positions:
                values = self._var_values.get(cluster.cluster_id, {}).get(pos, [])
                if not values:
                    continue

                # Majority-vote entity type
                types = [classify_entity(v) for v in values]
                from collections import Counter
                type_counts = Counter(types)
                entity_type = type_counts.most_common(1)[0][0]

                # Get preceding static token for context
                preceding = ""
                for j in range(pos - 1, -1, -1):
                    if tmpl_tokens[j] != "<*>":
                        preceding = tmpl_tokens[j].rstrip(":")
                        break

                # Map to OCSF field
                if entity_type == "kv_token":
                    # KV tokens are mapped at extraction time via alias table
                    ocsf_hint = "_kv_dynamic"
                elif entity_type == "ip_port":
                    # IP:port composites are mapped at extraction time based on context
                    ocsf_hint = "_ip_port_dynamic"
                else:
                    ocsf_hint = CONTEXT_OCSF_MAP.get(
                        (entity_type, preceding),
                        DEFAULT_OCSF_MAP.get(entity_type, ""))

                variables.append(VariableSlot(
                    position=pos,
                    entity_type=entity_type,
                    ocsf_hint=ocsf_hint,
                    sample_values=values[:5],
                ))

            self._templates[cluster.cluster_id] = LearnedTemplate(
                template_str=template_str,
                cluster_size=cluster.size,
                variables=variables,
                static_tokens=static_tokens,
            )

        return len(self._templates)

    def get_stats(self) -> dict:
        """Return mining statistics."""
        return {
            "templates_learned": len(self._templates),
            "logs_processed": 0,
        }


    def extract(self, log: str) -> dict[str, Any] | None:
        """Extract OCSF fields from a log using learned templates.

        Returns dict of {ocsf_field: value} or None if no template matches.
        """
        match = self._miner.match(log)
        if match is None:
            return None

        template = self._templates.get(match.cluster_id)
        if template is None:
            return None

        # Align log tokens to template
        tmpl_tokens = template.template_str.split()
        log_tokens = log.split()
        if len(log_tokens) < len(tmpl_tokens):
            return None

        fields: dict[str, Any] = {}

        for var in template.variables:
            if var.position >= len(log_tokens):
                continue

            value = log_tokens[var.position]

            # Handle IP:port composite — split and map both
            if var.entity_type == "ip_port":
                m = IP_PORT_RE.match(value)
                if m:
                    # Determine if src or dst from context
                    preceding = self._get_preceding_token(
                        template.template_str.split(), var.position)
                    if preceding in ("->", "dst", "DST", "dest", "destination", "server"):
                        fields["dst_endpoint.ip"] = m.group(1)
                        fields["dst_endpoint.port"] = int(m.group(2))
                    else:
                        fields["src_endpoint.ip"] = m.group(1)
                        fields["src_endpoint.port"] = int(m.group(2))
                continue

            # Handle KV tokens — parse key="value" and map via alias table
            if var.entity_type == "kv_token":
                kv_m = KV_TOKEN_RE.match(value)
                if kv_m:
                    key, val = kv_m.group(1), kv_m.group(2)
                    ocsf_path = self._alias_lookup(key)
                    if ocsf_path and val:
                        fields[ocsf_path] = val
                continue

            # Skip unmapped variables
            if not var.ocsf_hint:
                continue

            # Coerce based on entity type
            if var.entity_type == "port" and value.isdigit():
                value = int(value)
            elif var.entity_type == "integer" and value.isdigit():
                value = int(value)
            elif var.entity_type == "process_ref":
                # "sshd[1234]:" → extract just the name
                m = re.match(r"(\w+)\[", value)
                if m:
                    value = m.group(1)

            fields[var.ocsf_hint] = value

        return fields if fields else None

    @staticmethod
    def _get_preceding_token(tmpl_tokens: list[str], position: int) -> str:
        """Get the static token preceding a variable position."""
        for j in range(position - 1, -1, -1):
            if tmpl_tokens[j] != "<*>":
                return tmpl_tokens[j].rstrip(":")
        return ""

    def _alias_lookup(self, field_name: str) -> str | None:
        """Look up a field name in the alias table."""
        if not hasattr(self, '_aliases'):
            try:
                from shrike.extractor.field_mapper import FieldMapper
                fm = FieldMapper()
                self._aliases = fm._aliases
            except Exception:
                self._aliases = {}
        return self._aliases.get(field_name)

    @property
    def template_count(self) -> int:
        return len(self._templates)

    @property
    def templates(self) -> list[LearnedTemplate]:
        return list(self._templates.values())

    def save(self, path: Path | str | None = None) -> None:
        """Persist learned templates and Drain3 state to disk (JSON).

        Serializes:
          - Each LearnedTemplate (template_str, cluster_size, variables, static_tokens)
          - Drain3 internal cluster state (cluster_id, template, size, log_template_tokens)
          - Variable value samples per cluster per position
        """
        path = Path(path) if path else self._save_path
        if path is None:
            return

        path.parent.mkdir(parents=True, exist_ok=True)

        # Serialize templates
        templates_data = []
        for cluster_id, tmpl in self._templates.items():
            templates_data.append({
                "cluster_id": cluster_id,
                "template_str": tmpl.template_str,
                "cluster_size": tmpl.cluster_size,
                "static_tokens": tmpl.static_tokens,
                "variables": [
                    {
                        "position": v.position,
                        "entity_type": v.entity_type,
                        "ocsf_hint": v.ocsf_hint,
                        "sample_values": v.sample_values,
                    }
                    for v in tmpl.variables
                ],
            })

        # Serialize Drain3 cluster state for reconstruction
        drain_clusters = []
        for cluster in self._miner.drain.clusters:
            drain_clusters.append({
                "cluster_id": cluster.cluster_id,
                "size": cluster.size,
                "log_template_tokens": list(cluster.log_template_tokens),
            })

        # Serialize variable value samples
        var_values_data: dict[str, dict[str, list[str]]] = {}
        for cid, positions in self._var_values.items():
            var_values_data[str(cid)] = {
                str(pos): vals[:10] for pos, vals in positions.items()
            }

        data = {
            "version": 1,
            "sim_threshold": self._sim_threshold,
            "depth": self._depth,
            "templates": templates_data,
            "drain_clusters": drain_clusters,
            "var_values": var_values_data,
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, path: Path | str | None = None) -> int:
        """Restore learned templates and Drain3 state from disk.

        Returns the number of templates loaded.
        """
        path = Path(path) if path else self._save_path
        if path is None or not Path(path).exists():
            return 0

        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return 0

        version = data.get("version", 0)
        if version != 1:
            return 0

        # Restore Drain3 cluster state
        for dc in data.get("drain_clusters", []):
            tokens = dc["log_template_tokens"]
            template_str = " ".join(tokens)
            # Feed the template itself to Drain3 so it rebuilds its prefix tree.
            # Drain3 will create a cluster; we then correct the cluster_id and size.
            self._miner.add_log_message(template_str)

        # After feeding templates, patch cluster sizes and IDs to match saved state
        saved_clusters = {dc["cluster_id"]: dc for dc in data.get("drain_clusters", [])}
        # Build a mapping from template_str to saved cluster_id
        tmpl_to_saved: dict[str, dict] = {}
        for dc in data.get("drain_clusters", []):
            tmpl_str = " ".join(dc["log_template_tokens"])
            tmpl_to_saved[tmpl_str] = dc

        for cluster in self._miner.drain.clusters:
            tmpl_str = cluster.get_template()
            if tmpl_str in tmpl_to_saved:
                saved = tmpl_to_saved[tmpl_str]
                cluster.size = saved["size"]

        # Restore variable values
        self._var_values.clear()
        for cid_str, positions in data.get("var_values", {}).items():
            cid = int(cid_str)
            self._var_values[cid] = {}
            for pos_str, vals in positions.items():
                self._var_values[cid][int(pos_str)] = vals

        # Restore learned templates
        self._templates.clear()
        for entry in data.get("templates", []):
            variables = [
                VariableSlot(
                    position=v["position"],
                    entity_type=v["entity_type"],
                    ocsf_hint=v["ocsf_hint"],
                    sample_values=v.get("sample_values", []),
                )
                for v in entry["variables"]
            ]
            # Find the matching Drain3 cluster_id in the newly rebuilt miner
            # by matching template strings
            tmpl_str = entry["template_str"]
            matched_cid: int | None = None
            for cluster in self._miner.drain.clusters:
                if cluster.get_template() == tmpl_str:
                    matched_cid = cluster.cluster_id
                    break

            # Use the matched cluster_id, or the saved one as fallback
            cid = matched_cid if matched_cid is not None else entry["cluster_id"]

            self._templates[cid] = LearnedTemplate(
                template_str=tmpl_str,
                cluster_size=entry["cluster_size"],
                variables=variables,
                static_tokens=entry["static_tokens"],
            )

        return len(self._templates)

    def summary(self) -> str:
        """Human-readable summary of learned templates."""
        lines = [f"LogTemplateMiner: {len(self._templates)} templates"]
        for t in sorted(self._templates.values(), key=lambda x: -x.cluster_size):
            vars_desc = ", ".join(
                f"pos{v.position}={v.entity_type}→{v.ocsf_hint}"
                for v in t.variables if v.ocsf_hint
            )
            lines.append(f"  [{t.cluster_size:3d} logs] {t.template_str}")
            if vars_desc:
                lines.append(f"           → {vars_desc}")
        return "\n".join(lines)

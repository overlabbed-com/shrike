"""Schema-injected LLM extractor for OCSF field extraction.

Given a classified log line and its OCSF class, injects only that class's
schema into the LLM prompt. The LLM extracts field values — it doesn't need
to know all 65 classes, just the 10-20 fields for the current class.

This is Stage 4 of the Shrike pipeline — ~500ms on CPU (3B Q4_K_M).

Supports multiple backends:
  - OpenAI-compatible API (vLLM, Ollama, llama.cpp server)
  - Direct llama-cpp-python bindings (no server needed)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    """Result of field extraction."""
    event: dict[str, Any]  # The extracted OCSF event
    class_uid: int
    class_name: str
    raw_log: str
    extraction_time_ms: float = 0.0
    retries: int = 0
    error: str | None = None
    confidence: dict[str, str] = field(default_factory=dict)
    # confidence maps OCSF field → derivation method:
    #   "pattern"   = extracted by specific regex pattern (highest)
    #   "alias"     = mapped via field alias table (high)
    #   "fuzzy"     = mapped via fuzzy substring rules (medium)
    #   "default"   = filled with default value (lowest)
    #   "llm"       = extracted by LLM (medium-high)
    #   "auto"      = auto-extracted from JSON field name match (high)


SYSTEM_PROMPT = """You are a log normalization engine. Given a raw log line and an OCSF event class schema, extract the relevant fields into a valid JSON object.

Rules:
1. Output ONLY valid JSON — no explanation, no markdown, no comments.
2. Include class_uid, class_name, category_uid, category_name, activity_id, severity_id, and time.
3. Extract values directly from the log. Do not invent or hallucinate values.
4. Use the exact field names from the schema.
5. If a field's value cannot be determined from the log, omit it entirely.
6. For severity_id: 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal.
7. For activity_id: 0=Unknown, 1=Logon/Create/Allow, 2=Logoff/Read/Deny, 99=Other.
8. Preserve original values (IPs, usernames, timestamps) exactly as they appear."""


def _build_schema_context(schema: dict) -> str:
    """Build a compact schema description for prompt injection."""
    attrs = schema.get("attributes", {})
    if not attrs:
        return f"Class: {schema['class_name']} (UID: {schema['class_uid']})\nNo class-specific fields defined."

    lines = [
        f"Class: {schema['class_name']} (UID: {schema['class_uid']})",
        f"Category: {schema.get('category_uid', 'unknown')}",
        f"Description: {schema.get('description', '')[:200]}",
        "",
        "Fields:",
    ]

    for name, spec in attrs.items():
        req = spec.get("requirement", "optional")
        ftype = spec.get("type", "string")
        desc = spec.get("description", "")[:80]
        marker = "**REQUIRED**" if req == "required" else req
        lines.append(f"  - {name} ({ftype}, {marker}): {desc}")

    return "\n".join(lines)


def _extract_json(text: str) -> dict | None:
    """Extract JSON from LLM output, handling common formatting issues."""
    text = text.strip()

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code blocks
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Try finding the first { ... } block
    brace_start = text.find("{")
    if brace_start >= 0:
        depth = 0
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[brace_start : i + 1])
                    except json.JSONDecodeError:
                        break

    return None


class SchemaInjectedExtractor:
    """LLM-based field extractor with per-class schema injection."""

    def __init__(
        self,
        schemas_dir: Path | None = None,
        api_base: str = "http://localhost:11434/v1",
        model: str = "shrike-extractor",
        api_key: str = "",
        max_retries: int = 2,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ):
        """Initialize the extractor.

        Args:
            schemas_dir: Path to per-class OCSF schema JSON files.
            api_base: OpenAI-compatible API base URL.
            model: Model name/tag for the API.
            api_key: API key (usually not needed for local inference).
            max_retries: Max extraction retry attempts on JSON parse failure.
            temperature: Sampling temperature (low = deterministic).
            max_tokens: Maximum output tokens.
        """
        self._schemas: dict[int, dict] = {}
        self._api_base = api_base.rstrip("/") if api_base else None
        if self._api_base and not self._api_base.startswith(("http://", "https://")):
            raise ValueError(f"LLM API URL must use http:// or https:// scheme, got: {api_base}")
        self._model = model
        self._api_key = api_key
        self._max_retries = max_retries
        self._temperature = temperature
        self._max_tokens = max_tokens

        if schemas_dir is None:
            schemas_dir = Path(__file__).parent.parent.parent / "schemas" / "ocsf_v1.3" / "classes"
        self._load_schemas(schemas_dir)

    def _load_schemas(self, schemas_dir: Path) -> None:
        """Load per-class schema files."""
        if not schemas_dir.exists():
            return
        for f in schemas_dir.glob("class_*.json"):
            try:
                with open(f) as fh:
                    schema = json.load(fh)
                self._schemas[schema["class_uid"]] = schema
            except Exception as e:
                logger.warning(f"Failed to load schema {f.name}: {e}")

    def extract(
        self,
        raw_log: str,
        class_uid: int,
        class_name: str = "",
    ) -> ExtractionResult:
        """Extract OCSF fields from a raw log using the class-specific schema.

        Args:
            raw_log: The raw log line.
            class_uid: The classified OCSF class UID.
            class_name: The class name (for context).

        Returns:
            ExtractionResult with the extracted event or error.
        """
        import time

        start = time.monotonic()

        if self._api_base is None:
            return ExtractionResult(
                event={"class_uid": class_uid, "raw_data": raw_log},
                class_uid=class_uid,
                class_name=class_name or f"Unknown ({class_uid})",
                raw_log=raw_log,
                error="LLM extraction disabled (no api_base)",
            )

        schema = self._schemas.get(class_uid)

        start = time.monotonic()
        if schema is None:
            return ExtractionResult(
                event={"class_uid": class_uid, "raw_data": raw_log},
                class_uid=class_uid,
                class_name=class_name or f"Unknown ({class_uid})",
                raw_log=raw_log,
                error=f"No schema for class_uid {class_uid}",
            )

        schema_context = _build_schema_context(schema)
        user_prompt = f"Schema:\n{schema_context}\n\nRaw log:\n{raw_log}\n\nExtract OCSF JSON:"

        event = None
        retries = 0
        last_error = None

        for attempt in range(1 + self._max_retries):
            try:
                response_text = self._call_api(user_prompt)
                event = _extract_json(response_text)
                if event is not None:
                    # Ensure class_uid is set correctly
                    event["class_uid"] = class_uid
                    event.setdefault("class_name", schema.get("class_name", class_name))
                    event.setdefault("category_uid", class_uid // 1000)
                    break
                else:
                    last_error = f"Failed to parse JSON from response (attempt {attempt + 1})"
                    retries += 1
            except Exception as e:
                last_error = str(e)
                # Fail fast on connection errors — don't retry infrastructure failures
                import urllib.error
                if isinstance(e, (ConnectionError, urllib.error.URLError, urllib.error.HTTPError)):
                    retries = self._max_retries + 1  # Skip remaining retries
                    break
                retries += 1

        elapsed_ms = (time.monotonic() - start) * 1000

        if event is None:
            event = {
                "class_uid": class_uid,
                "class_name": schema.get("class_name", class_name),
                "raw_data": raw_log,
            }

        return ExtractionResult(
            event=event,
            class_uid=class_uid,
            class_name=schema.get("class_name", class_name),
            raw_log=raw_log,
            extraction_time_ms=elapsed_ms,
            retries=retries,
            error=last_error if event.get("raw_data") == raw_log and "class_name" in event and len(event) <= 3 else None,
        )

    def _call_api(self, user_prompt: str) -> str:
        """Call the OpenAI-compatible API."""
        import urllib.request
        import urllib.error

        url = f"{self._api_base}/chat/completions"

        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}),
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read())
            return result["choices"][0]["message"]["content"]
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to reach extraction API at {url}: {e}")

    def extract_batch(
        self,
        logs: list[tuple[str, int, str]],
    ) -> list[ExtractionResult]:
        """Extract fields from a batch of classified logs.

        Args:
            logs: List of (raw_log, class_uid, class_name) tuples.

        Returns:
            List of ExtractionResults.
        """
        return [self.extract(log, uid, name) for log, uid, name in logs]

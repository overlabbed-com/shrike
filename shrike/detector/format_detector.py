"""Log format detection via regex/heuristic fingerprinting.

Identifies the format family of a raw log line without any ML.
This is Stage 1 of the Shrike pipeline — runs in <1ms per log.
"""

from __future__ import annotations

import re
from enum import Enum


class LogFormat(str, Enum):
    """Detected log format families."""

    SYSLOG_RFC5424 = "syslog_rfc5424"
    SYSLOG_RFC3164 = "syslog_rfc3164"
    SYSLOG_BSD = "syslog_bsd"
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    TSV = "tsv"
    KV = "kv"
    WINDOWS_EVTX_JSON = "evtx_json"
    W3C = "w3c"
    CLF = "clf"
    CUSTOM = "custom"


_SYSLOG_RFC5424 = re.compile(r"^<\d{1,3}>\d\s")
_SYSLOG_RFC3164 = re.compile(r"^<\d{1,3}>[A-Z][a-z]{2}\s")
_SYSLOG_BSD = re.compile(
    r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s"
)
# BSD syslog with milliseconds: "Oct 21 18:35:43.579 ..."
_SYSLOG_BSD_MS = re.compile(
    r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\.\d+\s"
)
# BSD syslog with year: "Jul  3 2024 16:40:48: ..."
_SYSLOG_BSD_YEAR = re.compile(
    r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}"
)
# Plex-style: "Mar 29, 2026 17:50:27.680 ..."
_SYSLOG_BSD_COMMA_YEAR = re.compile(
    r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}\s+\d{2}:\d{2}:\d{2}"
)
_CEF = re.compile(r"CEF:\d\|")
_LEEF = re.compile(r"LEEF:\d(?:\.\d)?\|")
_CLF = re.compile(
    r'^\S+\s+\S+\s+\S+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s'
)
# CLF variant with different date separators: "IP - - [DD/MM/YYYY HH:MM:SS]"
_CLF_ALT = re.compile(
    r'^\d+\.\d+\.\d+\.\d+\s+\S+\s+\S+\s+\[\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\]'
)
_KV = re.compile(r"(?:^|\s)\w+=\S+(?:\s\w+=\S+){2,}")
# logfmt: level=X msg="..." (KV variant with quoted values)
_LOGFMT = re.compile(r'(?:^|\s)level=\w+\s+msg=')
# LDAP log: conn=N op=N (KV variant)
_LDAP_KV = re.compile(r'(?:^|\s)conn=\d+\s+op=\d+')
_W3C_HEADER = re.compile(r"^#Fields:\s")
_ZEEK_HEADER = re.compile(r"^#separator\s")
_ISO_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
# Slash-format timestamp: 2026/03/29 11:07:11
_SLASH_TIMESTAMP = re.compile(r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}")
# Epoch timestamp with decimal: 1564655684.277
_EPOCH_TIMESTAMP = re.compile(r"^\d{10}\.\d+\s")
# Kernel dmesg: [    6.367234] ...
_DMESG = re.compile(r"^\[\s*\d+\.\d+\]\s")
# Cisco syslog mnemonic: %FACILITY-SEV-MNEMONIC:
_CISCO_MNEMONIC = re.compile(r"^%[A-Z][A-Z0-9_]+-\d+-[A-Z0-9_]+:")
# ANSI escape codes
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m|\[(?:\d+m|\d+;?\d*m)")
# Bracketed timestamp: [2026/03/30 01:52:25.598 +00:00] [INFO]
_BRACKETED_TS = re.compile(r"^\[\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}")
# Pipe-delimited log: HH:MM:SS.mmm | LEVEL | ...
_PIPE_LOG = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d+\s+\|\s+\w+\s+\|")
# Uvicorn/ASGI: "INFO:     IP:port - "METHOD /path"
_UVICORN = re.compile(r"^(?:INFO|WARNING|ERROR|DEBUG|CRITICAL):\s+\d+\.\d+\.\d+\.\d+:\d+\s+-\s+\"")
# VPC flow log: version account-id eni-xxx ...
_VPC_FLOW = re.compile(r"^\d+\s+\d+\s+eni-[a-f0-9]+\s")
# DHCP log with CLF-style timestamp
_DHCP_TS = re.compile(r"^\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s")
# DNS query: "client [@0x...] IP#port (domain): query:"
_DNS_QUERY = re.compile(r"^client\s+(?:@\S+\s+)?\S+#\d+")
# Juniper RT_ prefix
_JUNIPER_RT = re.compile(r"^RT_[A-Z_]+:")


def _strip_ansi(s: str) -> str:
    """Strip ANSI escape codes from a string."""
    return _ANSI_ESCAPE.sub("", s)


def detect_format(raw_log: str) -> LogFormat:
    """Detect the format of a raw log line. <1ms per call."""
    if not raw_log or len(raw_log) < 5:
        return LogFormat.CUSTOM

    s = raw_log.strip()

    # Strip ANSI escape codes if present (e.g., container management logs)
    if "\x1b[" in s or "[0m" in s[:50]:
        s = _strip_ansi(s).strip()
        if not s or len(s) < 5:
            return LogFormat.CUSTOM

    c = s[0]

    if c == "{":
        if '"EventID"' in s[:200] and any(f'"{k}"' in s[:300] for k in ("Channel", "Computer", "Description")):
            return LogFormat.WINDOWS_EVTX_JSON
        return LogFormat.JSON

    if c == "[" and len(s) > 1 and s[1] == "{":
        return LogFormat.JSON

    if c == "<":
        if _SYSLOG_RFC5424.match(s):
            return LogFormat.SYSLOG_RFC5424
        if _SYSLOG_RFC3164.match(s):
            return LogFormat.SYSLOG_RFC3164
        if s.startswith("<?xml") or s.startswith("<Event"):
            return LogFormat.XML
        if re.match(r"<\d{1,3}>", s):
            return LogFormat.SYSLOG_RFC3164
        return LogFormat.XML

    if _CEF.search(s[:100]):
        return LogFormat.CEF

    if _LEEF.search(s[:100]):
        return LogFormat.LEEF

    if _W3C_HEADER.match(s):
        return LogFormat.W3C

    if _ZEEK_HEADER.match(s) or ("\t" in s[:200] and s[:500].count("\t") >= 5):
        return LogFormat.TSV

    # Bracketed timestamp logs (Go apps, databases): [2026/03/30 01:52:25.598 +00:00]
    if c == "[" and _BRACKETED_TS.match(s):
        if _KV.search(s[:300]):
            return LogFormat.KV
        return LogFormat.SYSLOG_BSD

    # BSD syslog — check all variants
    if _SYSLOG_BSD.match(s) or _SYSLOG_BSD_MS.match(s):
        return LogFormat.SYSLOG_BSD

    if _SYSLOG_BSD_YEAR.match(s):
        return LogFormat.SYSLOG_BSD

    if _SYSLOG_BSD_COMMA_YEAR.match(s):
        return LogFormat.SYSLOG_BSD

    if _CLF.match(s):
        return LogFormat.CLF

    # CLF variant with different date format
    if _CLF_ALT.match(s):
        return LogFormat.CLF

    # DHCP/CLF-style timestamp at start: DD/Mon/YYYY:HH:MM:SS
    if _DHCP_TS.match(s):
        return LogFormat.CLF

    # Cisco syslog mnemonic without timestamp: %ASA-6-302021:
    if _CISCO_MNEMONIC.match(s):
        return LogFormat.SYSLOG_BSD

    # Pipe-delimited structured logs: HH:MM:SS.mmm | LEVEL |
    if _PIPE_LOG.match(s):
        return LogFormat.KV

    # Uvicorn/ASGI access logs
    if _UVICORN.match(s):
        return LogFormat.CLF

    # Kernel dmesg: [    6.367234] ...
    if _DMESG.match(s):
        return LogFormat.SYSLOG_BSD

    # KV checks — includes logfmt and LDAP
    if _KV.search(s[:300]):
        return LogFormat.KV

    if _LOGFMT.search(s[:300]):
        return LogFormat.KV

    if _LDAP_KV.search(s[:300]):
        return LogFormat.KV

    if _ISO_TIMESTAMP.match(s):
        if "," in s and s.count(",") >= 3:
            return LogFormat.CSV
        # Check for KV pairs after the timestamp
        if _KV.search(s[:500]):
            return LogFormat.KV
        # Structured app log with ISO timestamp — treat as syslog_bsd
        # (many app logs use ISO timestamps with similar structure)
        return LogFormat.SYSLOG_BSD

    # Slash-format timestamp: 2026/03/29 11:07:11
    if _SLASH_TIMESTAMP.match(s):
        if _KV.search(s[:500]):
            return LogFormat.KV
        return LogFormat.SYSLOG_BSD

    # Epoch timestamp (Squid-style): 1564655684.277
    if _EPOCH_TIMESTAMP.match(s):
        return LogFormat.CLF

    # VPC flow logs: space-delimited with eni- prefix
    if _VPC_FLOW.match(s):
        return LogFormat.TSV

    # DNS query logs: client IP#port
    if _DNS_QUERY.match(s):
        return LogFormat.SYSLOG_BSD

    # Juniper RT_ logs
    if _JUNIPER_RT.match(s):
        if _KV.search(s[:500]):
            return LogFormat.KV
        return LogFormat.SYSLOG_BSD

    if "," in s and s[:500].count(",") >= 3:
        return LogFormat.CSV

    return LogFormat.CUSTOM

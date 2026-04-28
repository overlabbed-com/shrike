"""Syslog bridge — receives syslog and feeds the normalization pipeline.


Listens on port 1514 (TCP/UDP), parses RFC 3164 / RFC 5424 messages,
and feeds raw log lines into the Shrike pipeline via the destination router.
"""

from __future__ import annotations

import asyncio
import re

from shrike.metrics import events_normalized
import socket
import time
from typing import Optional

import structlog

logger = structlog.get_logger("shrike.syslog")


# RFC 3164 syslog parse
_SYSLOG_REGEX = re.compile(
    rb"^<(?P<pri>\d+)>?(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<tag>\S+?(?:\[\d+\])?):\s*(?P<msg>.*)$",
    re.DOTALL,
)
_FACILITY_MAP = {
    0: "kernel", 1: "user", 2: "mail", 3: "system", 4: "auth", 5: "syslog",
    6: "printer", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv",
    11: "ftp", 12: "ntp", 13: "security", 14: "console",
}
_PRIORITY_MAP = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warn",
    5: "notice", 6: "info", 7: "debug",
}


def _parse_priority(pri: int) -> tuple[str, str]:
    facility = _FACILITY_MAP.get(pri >> 3, "unknown")
    severity = _PRIORITY_MAP.get(pri & 7, "unknown")
    return facility, severity


def _parse_message(data: bytes) -> Optional[dict]:
    """Parse a syslog message. Returns None if unparseable."""
    data = data.strip(b"\x00\r\n ")
    if not data:
        return None

    m = _SYSLOG_REGEX.match(data)
    if m:
        raw = m.group("msg").decode("utf-8", errors="replace").strip()
        if not raw:
            return None
        pri = int(m.group("pri"))
        facility, severity = _parse_priority(pri)
        return {
            "raw_log": raw,
            "syslog_facility": facility,
            "syslog_severity": severity,
            "syslog_host": m.group("host").decode("utf-8", errors="replace"),
            "syslog_tag": m.group("tag").decode("utf-8", errors="replace"),
            "syslog_timestamp": m.group("ts").decode("utf-8", errors="replace"),
        }

    # Fallback: treat entire line as raw log
    try:
        raw = data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    if not raw or len(raw) < 4:
        return None
    return {"raw_log": raw}


class SyslogBridge:
    """Receives syslog and feeds raw logs into the Shrike pipeline."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 1514,
        pipeline=None,
        router=None,
        batch_size: int = 50,
        batch_interval: float = 2.0,
    ):
        self.host = host
        self.port = port
        self._pipeline = pipeline
        self._router = router
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        self._buffer: list[str] = []
        self._last_send = time.monotonic()
        self._lock = asyncio.Lock()
        self._running = False

    async def _send_buffer(self):
        """Flush buffer to pipeline."""
        async with self._lock:
            if not self._buffer:
                return
            logger.warning("send_buffer flushing", count=len(self._buffer))
            logs = self._buffer[:]
            self._buffer.clear()

        if not logs:
            return

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        events = []

        for raw_log in logs:
            if self._pipeline:
                result = self._pipeline.process(raw_log)
                logger.warning("pipeline result", dropped=result.dropped, class_uid=result.class_uid)
                if not result.dropped:
                    rd = result.to_dict()
                    event = rd.get("event", {})
                    event["_shrike_metadata"] = rd.get("metadata", {})
                    event["_shrike_received_at"] = now
                    event["_shrike_source_ip"] = "syslog"
                    events.append(event)
            else:
                events.append({
                    "raw_event": raw_log,
                    "_shrike_received_at": now,
                    "_shrike_source_ip": "syslog",
                })

        if events and self._router:
            try:
                logger.warning("routing events", count=len(events))
                await self._router.route(events)
                events_normalized.inc(len(events))
            except Exception as e:
                logger.warning("router error", error=str(e))

    async def _tick(self):
        """Periodic flush."""
        logger.debug("tick starting", interval=self.batch_interval)
        while self._running:
            await asyncio.sleep(self.batch_interval)
            logger.debug("tick firing", pending=len(self._buffer))
            if time.monotonic() - self._last_send >= self.batch_interval:
                self._last_send = time.monotonic()
                await self._send_buffer()

    async def _handle(self, data: bytes):
        """Handle incoming syslog message."""
        logger.debug("handle called", data_len=len(data))
        parsed = _parse_message(data)
        raw = parsed["raw_log"] if parsed else None
        if not raw:
            # fallback: raw bytes
            try:
                raw = data.decode("utf-8", errors="replace").strip()
            except Exception:
                return
        if not raw or len(raw) < 4:
            return
        logger.debug("handle raw", raw=raw[:50])

        async with self._lock:
            self._buffer.append(raw)
            self._last_send = time.monotonic()
            if len(self._buffer) >= self.batch_size:
                asyncio.create_task(self._send_buffer())

    async def _udp_server(self, sock: socket.socket):
        loop = asyncio.get_running_loop()
        logger.info("UDP server starting", host=self.host, port=self.port)
        while self._running:
            try:
                data = await loop.sock_recv(sock, 4096)
                logger.debug("UDP received", data_len=len(data))
                if data:
                    await self._handle(data)
            except Exception as e:
                logger.debug("UDP error", error=str(e))
                pass

    async def _tcp_server(self, sock: socket.socket):
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                conn, _ = await loop.sock_accept(sock)
                asyncio.create_task(self._handle_tcp(conn))
            except Exception:
                pass

    async def _handle_tcp(self, conn: socket.socket):
        buf = b""
        try:
            conn.settimeout(5.0)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while buf:
                    if buf[0:1] == b"\n":
                        buf = buf[1:]
                        continue
                    m = re.match(rb"(\d+)\s", buf)
                    if m:
                        msg_len = int(m.group(1))
                        total_len = m.end() + msg_len
                        if len(buf) >= total_len:
                            msg_data = buf[m.end():total_len]
                            buf = buf[total_len:]
                            await self._handle(msg_data)
                        else:
                            break
                    else:
                        if b"\n" in buf:
                            lines = buf.split(b"\n")
                            buf = lines[-1]
                            for line in lines[:-1]:
                                await self._handle(line)
                        break
        except Exception:
            pass
        finally:
            conn.close()

    async def start(self):
        """Start the syslog bridge."""
        self._running = True

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind((self.host, self.port))
        udp_sock.setblocking(False)

        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_sock.bind((self.host, self.port))
        tcp_sock.setblocking(False)
        tcp_sock.listen(128)

        logger.info("Syslog bridge listening", host=self.host, port=self.port)

        await asyncio.gather(
            self._udp_server(udp_sock),
            self._tcp_server(tcp_sock),
            self._tick(),
        )

    def stop(self):
        self._running = False
"""HTTP 蜜罐：收一個 request、記 method / path / User-Agent、回靜態頁。

HTTPS 不在這裡：443 由 tls.py 的 TlsProbeService 處理，只看 ClientHello、不握手。
"""

from __future__ import annotations

import datetime as dt
import logging
import socket
from typing import Any

from ..notify import Event, Notifier
from .base import Service

log = logging.getLogger("honeypot")

MAX_REQUEST_BYTES = 64 * 1024

_STATUS_TEXT = {
    200: "OK", 301: "Moved Permanently", 302: "Found", 400: "Bad Request",
    401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    500: "Internal Server Error", 503: "Service Unavailable",
}


def parse_request(raw: bytes) -> dict[str, Any]:
    """只解析 request line 與 headers，body 不理。"""
    info: dict[str, Any] = {"method": "?", "path": "?", "version": "?", "headers": {}}
    text = raw.decode("latin-1")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    parts = lines[0].split(" ", 2) if lines and lines[0] else []
    if len(parts) >= 2:
        info["method"], info["path"] = parts[0], parts[1]
    if len(parts) >= 3:
        info["version"] = parts[2]
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            info["headers"][key.strip()] = value.strip()
    return info


def build_response(response_cfg: dict[str, Any]) -> bytes:
    status = int(response_cfg.get("status", 200))
    body = str(response_cfg.get("body", "")).encode("utf-8")
    headers = [
        f"HTTP/1.1 {status} {_STATUS_TEXT.get(status, 'OK')}",
        f"Date: {dt.datetime.now(dt.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}",
        f"Server: {response_cfg.get('server_header', 'Apache')}",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "", "",
    ]
    return "\r\n".join(headers).encode("ascii") + body


class HttpService(Service):
    name = "http"

    def __init__(self, cfg: dict[str, Any], notifier: Notifier, response_cfg: dict[str, Any],
                 name: str | None = None):
        super().__init__(cfg, notifier, name=name)
        self.response = build_response(response_cfg)

    def handle(self, client: socket.socket, addr: tuple[str, int]) -> Event | None:
        raw = self.recv_until(client, b"\r\n\r\n", MAX_REQUEST_BYTES)
        if not raw:
            return self.no_data_event(addr)

        req = parse_request(raw)
        try:
            client.sendall(self.response)
        except OSError:
            pass   # 對方先關了也無所謂，事件照記

        return self.event(
            addr, f"HTTP {req['method']} {req['path']}",
            method=req["method"],
            path=req["path"],
            user_agent=req["headers"].get("User-Agent", "-"),
            host=req["headers"].get("Host", "-"),
        )

"""HTTPS 蜜罐（免憑證）：收 TLS ClientHello、記 SNI 與版本、斷線。

ClientHello 是明文，光看第一包就知道對方想連哪個主機名、支援哪些 TLS 版本，
不必握手、不必憑證。代價是拿不到握手之後才加密送來的 request path 與 User-Agent。

打到 443 的明文 HTTP 與其他非 TLS 資料也照樣記成事件。
"""

from __future__ import annotations

import socket
from typing import Any

from ..notify import Event
from .base import ByteReader, Service, first_packet_details, recv_first

MAX_HELLO_BYTES = 16 * 1024         # TLS record 上限 16 KiB，再多就是在亂送
_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ", b"DELETE ", b"CONNECT ", b"PATCH ", b"TRACE ")

_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

_EXT_SNI = 0x0000
_EXT_SUPPORTED_VERSIONS = 0x002B


def _decode_name(raw: bytes) -> str:
    """SNI 是 IDNA 編碼的 ASCII；idna codec 不支援 errors 參數，壞掉就退回 latin-1。"""
    try:
        return raw.decode("idna")
    except UnicodeError:
        return raw.decode("latin-1")


def version_name(code: int) -> str:
    return _VERSION_NAMES.get(code, f"0x{code:04x}")


def parse_client_hello(data: bytes) -> dict[str, Any] | None:
    """從 TLS record 開頭解析 ClientHello。不是 ClientHello 或資料不完整就回 None。

    回傳欄位：record_version、hello_version、sni（可能沒有）、
    versions（supported_versions 擴充列出的版本，TLS 1.3 只在這裡看得到）、cipher_count。
    """
    try:
        rec = ByteReader(data)
        if rec.u8() != 0x16:                      # handshake record
            return None
        record_version = rec.u16()
        record_len = rec.u16()
        body = rec.sub(min(record_len, rec.remaining()))

        if body.u8() != 0x01:                     # ClientHello
            return None
        hello_len = body.u24()
        hello = body.sub(min(hello_len, body.remaining()))

        info: dict[str, Any] = {
            "record_version": version_name(record_version),
            "hello_version": version_name(hello.u16()),
        }
        hello.take(32)                            # random
        hello.take(hello.u8())                    # session id
        info["cipher_count"] = hello.u16() // 2
        hello.take(info["cipher_count"] * 2)
        hello.take(hello.u8())                    # compression methods

        if hello.remaining() < 2:
            return info                           # 沒有 extensions（古老 client）
        exts = hello.sub(min(hello.u16(), hello.remaining()))
    except ValueError:
        return None

    # 固定欄位都讀到了；extensions 被截斷或亂寫就只回報已經拿到的部分
    try:
        while exts.remaining() >= 4:
            ext_type = exts.u16()
            ext = exts.sub(min(exts.u16(), exts.remaining()))
            if ext_type == _EXT_SNI:
                names = ext.sub(min(ext.u16(), ext.remaining()))
                while names.remaining() >= 3:
                    name_type = names.u8()
                    name = names.take(names.u16())
                    if name_type == 0 and "sni" not in info:
                        info["sni"] = _decode_name(name)
            elif ext_type == _EXT_SUPPORTED_VERSIONS:
                count = ext.u8() // 2
                info["versions"] = [version_name(ext.u16()) for _ in range(count)]
    except ValueError:
        pass
    return info


def read_tls_record(client: socket.socket) -> bytes:
    """收第一個 TLS record（5 byte 表頭 + 長度）。不是 TLS 就回已收到的那段，沒送就回 b""。"""
    data = recv_first(client)
    if len(data) >= 5 and data[0] == 0x16 and data[1] == 0x03:
        want = 5 + int.from_bytes(data[3:5], "big")
        while len(data) < min(want, MAX_HELLO_BYTES):
            try:
                chunk = client.recv(4096)
            except socket.timeout:
                break                     # 對方只送了一半：已收到的照樣拿去解析
            if not chunk:
                break
            data += chunk
    return data


class TlsProbeService(Service):
    name = "https"
    client_timeout = 5.0

    def handle(self, client: socket.socket, addr: tuple[str, int]) -> Event | None:
        data = read_tls_record(client)
        if not data:
            return self.no_data_event(addr)

        details = first_packet_details(data)

        if data.startswith(_HTTP_METHODS):
            line = data.split(b"\r\n", 1)[0].decode("latin-1")[:200]
            return self.event(addr, f"明文 HTTP 打到 {self.name} port {self.port}", request_line=line, **details)

        if data[0] & 0x80 and len(data) >= 3 and data[2] == 0x01:
            return self.event(addr, "TLS 探測（SSLv2 格式 ClientHello）", **details)

        if data[0] != 0x16:
            return self.event(addr, f"連線 {self.name} port {self.port}（非 TLS 資料）", **details)

        hello = parse_client_hello(data)
        if hello is None:
            return self.event(addr, "TLS 探測（無法解析 ClientHello）", **details)

        del details["head_hex"]                   # 解析成功就不必留 hex
        details.update(hello)
        message = "TLS ClientHello"
        if "sni" in hello:
            message += f" SNI={hello['sni']}"
        return self.event(addr, message, **details)

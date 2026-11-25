"""MSSQL 蜜罐（只記連線）：收第一包、認一下是不是 TDS、記 hex、斷線。

不回 prelogin response，所以 client 不會送出帳號密碼。
要升級成完整互動需回 prelogin response 並解析 Login7 封包。
"""

from __future__ import annotations

import socket

from ..notify import Event
from .base import Service, first_packet_details, recv_first

# TDS 封包型別，看第一個 byte 就知道對方在幹嘛
_TDS_TYPES = {
    0x01: "SQL Batch",
    0x02: "Pre-TDS7 Login",
    0x03: "RPC",
    0x04: "Tabular Result",
    0x06: "Attention",
    0x07: "Bulk Load",
    0x0E: "Transaction Manager",
    0x10: "TDS7 Login",
    0x11: "SSPI",
    0x12: "Pre-Login",
}


class MssqlService(Service):
    name = "mssql"
    client_timeout = 5.0

    def handle(self, client: socket.socket, addr: tuple[str, int]) -> Event | None:
        data = recv_first(client)
        if not data:
            return self.no_data_event(addr)

        details = first_packet_details(data)
        kind = _TDS_TYPES.get(data[0])
        if kind and len(data) >= 8:
            details["tds_type"] = kind
            details["tds_length"] = int.from_bytes(data[2:4], "big")
            return self.event(addr, f"MSSQL TDS {kind}", **details)
        return self.event(addr, f"連線 {self.name} port {self.port}（非 TDS 資料）", **details)

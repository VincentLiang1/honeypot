"""UDP 蜜罐：DNS（53）與 SNMP（161）。每個封包一個事件，不回應。

DNS：解析第一個 question 的名稱與型別，掃 open resolver 的通常會查 version.bind 或隨便一個網域。
SNMP：從 BER 裡抓 version 與 community string，掃描器幾乎都用 public。
兩個解析器都用 ByteReader：封包截斷或長度欄亂寫就回 None，事件記成「非 DNS / 非 SNMP」加 hex。
"""

from __future__ import annotations

from typing import Any

from ..notify import Event
from .base import ByteReader, UdpService, first_packet_details

_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
              28: "AAAA", 33: "SRV", 255: "ANY"}
_SNMP_VERSIONS = {0: "v1", 1: "v2c", 3: "v3"}

MAX_DNS_NAME = 255        # RFC 1035 的名稱上限（octets），再長就不是 DNS
MAX_COMMUNITY = 64        # community 只留前幾個字；它會進信件主旨，不能讓對方塞 4 KB 進來


def parse_dns_question(data: bytes) -> dict[str, Any] | None:
    """回傳 {"name", "qtype", "id"}；不像 DNS 查詢（回應、沒有 question、截斷、壓縮指標）就回 None。"""
    try:
        rd = ByteReader(data)
        qid = rd.u16()
        if rd.u16() & 0x8000:                        # QR=1 是回應，不是查詢
            return None
        if rd.u16() == 0:                            # qdcount
            return None
        rd.take(6)                                   # ancount、nscount、arcount
        labels: list[str] = []
        total = 0
        while True:
            length = rd.u8()
            if length == 0:
                break
            if length & 0xC0:                        # 壓縮指標不該出現在 question
                return None
            total += length + 1
            if total > MAX_DNS_NAME:
                return None
            labels.append(rd.take(length).decode("ascii", errors="replace"))
        qtype = rd.u16()
    except ValueError:
        return None
    return {
        "name": ".".join(labels) or ".",
        "qtype": _DNS_TYPES.get(qtype, str(qtype)),
        "id": qid,
    }


def _ber_len(rd: ByteReader) -> int:
    """讀 BER 定長長度。不定長度（0x80）與超過 4 byte 的長度欄都當亂送，丟 ValueError。"""
    first = rd.u8()
    if first < 0x80:
        return first
    count = first & 0x7F
    if count == 0 or count > 4:
        raise ValueError("BER 長度欄無效")
    return int.from_bytes(rd.take(count), "big")


def parse_snmp(data: bytes) -> dict[str, Any] | None:
    """SNMP v1/v2c：SEQUENCE { INTEGER version, OCTET STRING community, PDU }；v3 只回版本。"""
    try:
        rd = ByteReader(data)
        if rd.u8() != 0x30:
            return None
        _ber_len(rd)                                 # 整個 SEQUENCE 的長度，用不到
        if rd.u8() != 0x02:
            return None
        length = _ber_len(rd)
        if not 1 <= length <= 4:                     # version 是個小整數，幾千 byte 的 INTEGER 是在亂送
            return None
        version = int.from_bytes(rd.take(length), "big")
        info: dict[str, Any] = {"version": _SNMP_VERSIONS.get(version, str(version))}
        if version == 3:
            return info                              # v3 沒有明文 community
        if rd.u8() != 0x04:
            return info
        info["community"] = rd.take(_ber_len(rd))[:MAX_COMMUNITY].decode("latin-1")
        return info
    except ValueError:
        return None


class DnsService(UdpService):
    name = "dns"

    def handle_datagram(self, data: bytes, addr: tuple[str, int]) -> Event | None:
        question = parse_dns_question(data)
        if question is None:
            return self.event(addr, f"UDP {self.port}（非 DNS 查詢）", **first_packet_details(data))
        return self.event(addr, f"DNS 查詢 {question['qtype']} {question['name']}", bytes=len(data), **question)


class SnmpService(UdpService):
    name = "snmp"

    def handle_datagram(self, data: bytes, addr: tuple[str, int]) -> Event | None:
        details = first_packet_details(data)
        info = parse_snmp(data)
        if info is None:
            return self.event(addr, f"UDP {self.port}（非 SNMP）", **details)
        details.update(info)
        message = f"SNMP {info['version']}"
        if "community" in info:
            message += f" community={info['community']}"
        return self.event(addr, message, **details)

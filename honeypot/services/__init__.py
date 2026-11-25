"""蜜罐服務與名稱登錄表。config 的 services.<name> 以這裡的名稱為準，預設 port 在 config.SERVICE_PORTS。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import SERVICE_PORTS
from ..notify import Notifier
from .base import Service, UdpService
from .generic import PROFILES, GenericService
from .http import HttpService
from .mssql import MssqlService
from .tls import TlsProbeService
from .udp import DnsService, SnmpService


@dataclass(frozen=True)
class Entry:
    label: str              # 安裝精靈顯示用
    cls: type[Service]      # 用哪個類別跑；UDP / TCP 由類別決定（cls.proto / cls.sock_type），不另外手打


# 名稱 → 說明與類別。預設 port 只寫在 config.SERVICE_PORTS 一處，下面會檢查兩邊的名稱一致。
CATALOG: dict[str, Entry] = {
    "http":        Entry("HTTP", HttpService),
    "https":       Entry("HTTPS（只記 ClientHello）", TlsProbeService),
    "mssql":       Entry("MSSQL", MssqlService),
    "ssh":         Entry("SSH", GenericService),
    "rdp":         Entry("RDP 遠端桌面", GenericService),
    "mysql":       Entry("MySQL", GenericService),
    "postgres":    Entry("PostgreSQL", GenericService),
    "redis":       Entry("Redis", GenericService),
    "mongodb":     Entry("MongoDB", GenericService),
    "vnc":         Entry("VNC", GenericService),
    "ldap":        Entry("LDAP", GenericService),
    "ldaps":       Entry("LDAPS", GenericService),
    "oracle":      Entry("Oracle TNS", GenericService),
    "winrm":       Entry("WinRM（HTTP）", HttpService),
    "winrm_https": Entry("WinRM（HTTPS）", TlsProbeService),
    "dns":         Entry("DNS", DnsService),
    "snmp":        Entry("SNMP", SnmpService),
}

if set(CATALOG) != set(SERVICE_PORTS):
    raise RuntimeError(f"services.CATALOG 與 config.SERVICE_PORTS 的名稱不一致：{sorted(set(CATALOG) ^ set(SERVICE_PORTS))}")
_GENERIC = {name for name, entry in CATALOG.items() if entry.cls is GenericService}
if set(PROFILES) != _GENERIC:
    raise RuntimeError(f"generic.PROFILES 與 CATALOG 裡用 GenericService 的名稱不一致：{sorted(set(PROFILES) ^ _GENERIC)}")


def create_service(name: str, cfg: dict[str, Any], notifier: Notifier, http_response: dict[str, Any]) -> Service:
    """依名稱建立服務實例。名稱不在 CATALOG 裡會丟 KeyError（config 驗證階段就該擋掉）。"""
    cls = CATALOG[name].cls
    if cls is HttpService:
        return HttpService(cfg, notifier, http_response, name=name)   # 只有 HTTP 要帶回應頁的設定
    return cls(cfg, notifier, name=name)


__all__ = [
    "CATALOG", "Entry", "Service", "UdpService", "HttpService", "MssqlService", "TlsProbeService",
    "GenericService", "DnsService", "SnmpService", "create_service",
]

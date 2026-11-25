"""設定檔載入與驗證。

只有一個 config.json，缺的欄位用 DEFAULTS 補。啟動時就把 port、白名單、
heartbeat 時間全部驗過，寫錯直接報錯結束，不要跑到半夜才炸。
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
from typing import Any

# 服務名稱 → 預設 port，預設 port 只有這一份。名稱必須與 honeypot/services/__init__.py 的 CATALOG 一致（services 匯入時會檢查）。
# 這裡不 import services（services → notify → config，反方向會繞成循環），由 services 那邊來讀這張表。
SERVICE_PORTS: dict[str, int] = {
    "http": 80, "https": 443, "mssql": 1433,
    "ssh": 22, "rdp": 3389, "mysql": 3306, "postgres": 5432, "redis": 6379,
    "mongodb": 27017, "vnc": 5900,
    "ldap": 389, "ldaps": 636, "oracle": 1521, "winrm": 5985, "winrm_https": 5986,
    "dns": 53, "snmp": 161,
}

DEFAULTS: dict[str, Any] = {
    "log_file": "honeypot.log",
    # 一天一個檔；1827 天 = 5 年（含閏日），更舊的自動刪；單日上限防被大量掃描時寫滿磁碟（2026-11-03 指定）
    "log_rotate": {"keep_days": 1827, "daily_max_mb": 50},
    "state_file": "state.json",
    "services": {
        name: {"enabled": True, "port": port, "interface": "0.0.0.0"}
        for name, port in SERVICE_PORTS.items()
    },
    "http_response": {
        "status": 200,
        "server_header": "Microsoft-IIS/10.0",
        "body": "<html><head><title>Welcome</title></head>"
                "<body><h1>Welcome</h1></body></html>",
    },
    "whitelist": ["127.0.0.1", "::1"],
    "notify": {
        "cooldown_minutes": 10,
        "email": {
            "enabled": False,
            "smtp_server": "",
            "smtp_port": 587,
            "use_tls": True,
            "username": "",
            "password": "",
            "from_email": "",
            "to_emails": [],
            "timeout_seconds": 30,
        },
    },
    "heartbeat": {"enabled": True, "time": "09:00"},
}

# 環境變數可以蓋掉 SMTP 密碼，config.json 就不必放明文
SMTP_PASSWORD_ENV = "HONEYPOT_SMTP_PASSWORD"


class ConfigError(ValueError):
    """設定檔內容有誤。"""


def _deep_merge(base: dict, override: dict) -> dict:
    """把 override 疊到 base 上（巢狀 dict 遞迴合併，其他型別直接取代）。"""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_config(path: str | None) -> dict[str, Any]:
    """讀 config.json 並與預設值合併。path 為 None 或檔案不存在時只用預設值。"""
    data: dict[str, Any] = {}
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ConfigError(f"{path} 不是合法的 JSON：{exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{path} 最外層必須是物件")

    cfg = _deep_merge(DEFAULTS, data)

    env_password = os.environ.get(SMTP_PASSWORD_ENV)
    if env_password:
        cfg["notify"]["email"]["password"] = env_password

    validate_config(cfg)
    return cfg


def parse_hhmm(text: str) -> tuple[int, int]:
    """把 "09:00" 轉成 (9, 0)，格式不對就丟 ConfigError。"""
    try:
        hour_s, minute_s = text.strip().split(":")
        hour, minute = int(hour_s), int(minute_s)
    except (ValueError, AttributeError) as exc:
        raise ConfigError(f"heartbeat.time 必須是 HH:MM，收到 {text!r}") from exc
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ConfigError(f"heartbeat.time 超出範圍：{text!r}")
    return hour, minute


def validate_config(cfg: dict[str, Any]) -> None:
    """檢查會讓程式跑到一半才出事的欄位。"""
    for name, svc in cfg["services"].items():
        if name not in SERVICE_PORTS:
            raise ConfigError(f"services.{name} 不是支援的服務，可用：{', '.join(SERVICE_PORTS)}")
        if not isinstance(svc, dict):
            raise ConfigError(f"services.{name} 必須是物件")
        port = svc.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not (0 <= port <= 65535):
            raise ConfigError(f"services.{name}.port 必須是 0 到 65535 的整數，收到 {port!r}")
        if not isinstance(svc.get("interface", ""), str):
            raise ConfigError(f"services.{name}.interface 必須是字串")

    for entry in cfg["whitelist"]:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ConfigError(f"whitelist 內有無法解析的項目 {entry!r}：{exc}") from exc

    parse_hhmm(cfg["heartbeat"]["time"])

    rotate = cfg["log_rotate"]
    # 舊版的 max_mb / backups 留在 config.json 裡也沒關係，直接忽略（安裝精靈曾把整份預設值寫進去）
    keep_days, daily_max_mb = rotate.get("keep_days"), rotate.get("daily_max_mb")
    if not isinstance(keep_days, int) or isinstance(keep_days, bool) or keep_days < 1:
        raise ConfigError(f"log_rotate.keep_days 必須是正整數，收到 {keep_days!r}")
    if not isinstance(daily_max_mb, (int, float)) or isinstance(daily_max_mb, bool) or daily_max_mb <= 0:
        raise ConfigError(f"log_rotate.daily_max_mb 必須是正數，收到 {daily_max_mb!r}")

    cooldown = cfg["notify"]["cooldown_minutes"]
    if not isinstance(cooldown, (int, float)) or cooldown < 0:
        raise ConfigError(f"notify.cooldown_minutes 必須是非負數，收到 {cooldown!r}")

    email = cfg["notify"]["email"]
    if email.get("enabled"):
        if not email.get("smtp_server"):
            raise ConfigError("notify.email.enabled 為 true 時必須填 smtp_server")
        if not email.get("to_emails"):
            raise ConfigError("notify.email.enabled 為 true 時必須填 to_emails")
        if isinstance(email["to_emails"], str):
            email["to_emails"] = [
                addr.strip() for addr in email["to_emails"].split(",") if addr.strip()
            ]


def is_whitelisted(ip: str, whitelist: list[str]) -> bool:
    """ip 是否落在白名單（支援單一 IP 與 CIDR，IPv4 / IPv6 都可）。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in whitelist:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False

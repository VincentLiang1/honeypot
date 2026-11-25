"""通用的「收第一包就記錄」TCP 蜜罐，一張 profile 表涵蓋 SSH、RDP、MySQL 等常被掃的 port。

server 先說話的協定（SSH、VNC、MySQL）送一段 banner / greeting，對方就會把版本、帳號或下一步送過來；
client 先說話的協定（RDP、Redis、LDAP、Oracle）直接等第一包；PostgreSQL 的 libpq 會先送 SSLRequest、
等到一個 byte 的 N 才肯送帶帳號的 StartupMessage，所以 profile 可以指定「第一包是這個就回這個、再收一次」。
不做其他協定互動，第一包記完就斷線。能看到的東西：來源、可列印的文字片段（RDP 的 mstshash=帳號、
PostgreSQL 的 user=、MySQL 的帳號與資料庫名、Oracle 的 CONNECT_DATA、SSH client 版本）、前 32 byte 的 hex。
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Any

from ..notify import Event, Notifier
from .base import Service, first_packet_details, recv_first

TEXT_PREVIEW = 300        # details.text 最多留幾個字：sqlplus 的 TNS connect descriptor 要兩百多字才走到 USER=
MESSAGE_PREVIEW = 60      # 事件訊息（會進信件主旨）最多帶幾個字
REPLY_ROUNDS = 3          # 最多照 profile.replies 回幾次再收：libpq 可能 GSSENCRequest → N → SSLRequest → N → Startup

# MySQL 是 server 先說話：先送 Protocol::HandshakeV10，client 才回 HandshakeResponse41（帳號、資料庫名明文）。
# 不宣告 CLIENT_SSL（0x0800），否則新版 client 預設 ssl-mode=PREFERRED 會先送不含帳號的 SSLRequest；
# sequence id 必須是 0，填 1 的話 client 會以 packets out of order 收場、什麼都不送。
MYSQL_GREETING = (
    b"\x4a\x00\x00" + b"\x00"               # payload 長度 74（little-endian）、sequence id 0
    + b"\x0a" + b"5.7.44\x00"               # protocol 10、server 版本
    + b"\x01\x00\x00\x00"                   # connection id
    + b"12345678" + b"\x00"                 # auth-plugin-data-part-1、filler
    + b"\xff\xf7"                           # capability 低 16 位：0xF7FF，全開但拿掉 CLIENT_SSL
    + b"\x21"                               # charset utf8_general_ci
    + b"\x02\x00"                           # status：autocommit
    + b"\xff\xc1"                           # capability 高 16 位：0xC1FF（含 PLUGIN_AUTH、CONNECT_ATTRS）
    + b"\x15"                               # auth-plugin-data 總長 21
    + b"\x00" * 10                          # reserved
    + b"abcdefghijkl\x00"                   # auth-plugin-data-part-2
    + b"mysql_native_password\x00"          # 新舊 client 與 bot 都懂的 plugin
)

# PostgreSQL：libpq 預設 sslmode=prefer、gssencmode=prefer，第一包是 8 byte 的 SSLRequest / GSSENCRequest，
# 要收到一個 byte 的 N（不支援）才會改送明文 StartupMessage（user=、database=）。
PG_SSL_REQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
PG_GSSENC_REQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x30"


@dataclass(frozen=True)
class Profile:
    label: str                                                  # 事件訊息裡的名稱
    banner: bytes = b""                                         # 連上就先送的字串；空的就是等對方先講
    replies: dict[bytes, bytes] = field(default_factory=dict)   # 收到的第一包剛好是 key 就回 value、再收一次


PROFILES: dict[str, Profile] = {
    "ssh":      Profile("SSH", b"SSH-2.0-OpenSSH_8.9\r\n"),       # 暴力破解帳密；對方會回自己的版本字串
    "rdp":      Profile("RDP"),                                    # 暴力破解、BlueKeep；第一包常帶 mstshash=帳號
    "mysql":    Profile("MySQL", MYSQL_GREETING),                  # 弱密碼；回應帶帳號、資料庫名、client 名稱
    "postgres": Profile("PostgreSQL",                              # 弱密碼；StartupMessage 帶 user= 與 database=
                        replies={PG_SSL_REQUEST: b"N", PG_GSSENC_REQUEST: b"N"}),
    "redis":    Profile("Redis"),                                  # 無密碼直接寫檔，挖礦常客
    "mongodb":  Profile("MongoDB"),                                # 無認證資料庫勒索
    "vnc":      Profile("VNC", b"RFB 003.008\n"),                  # 無密碼遠端桌面；對方會回自己的 RFB 版本
    "ldap":     Profile("LDAP"),                                   # AD 列舉、Log4Shell 回連
    "ldaps":    Profile("LDAPS"),                                  # 同 LDAP，TLS 版
    "oracle":   Profile("Oracle"),                                 # TNS 弱密碼；第一包帶 CONNECT_DATA
}

_NONPRINT = re.compile(rb"[^ -~]+")


def text_preview(data: bytes, limit: int = TEXT_PREVIEW) -> str:
    """把可列印的 ASCII 片段抓出來（帳號、版本字串都藏在裡面），每段不可列印的 byte 換成一個「.」。"""
    return _NONPRINT.sub(b".", data).decode("ascii").strip(".")[:limit]


class GenericService(Service):
    client_timeout = 5.0

    def __init__(self, cfg: dict[str, Any], notifier: Notifier, name: str):
        super().__init__(cfg, notifier, name=name)
        self.profile = PROFILES[name]

    def handle(self, client: socket.socket, addr: tuple[str, int]) -> Event | None:
        profile = self.profile
        if profile.banner:
            try:
                client.sendall(profile.banner)
            except OSError:
                pass   # 對方連上就關也要記

        data = b""
        for _ in range(REPLY_ROUNDS + 1):
            data = recv_first(client)
            reply = profile.replies.get(data) if data else None
            if reply is None:
                break
            try:
                client.sendall(reply)
            except OSError:
                break

        if not data:
            return self.no_data_event(addr)

        preview = text_preview(data)
        details = first_packet_details(data)
        message = f"{profile.label} 連線"
        if preview:
            details["text"] = preview
            message += f"：{preview[:MESSAGE_PREVIEW]}"
        return self.event(addr, message, **details)

"""新加的 port：通用 TCP（banner / 回覆 + 第一包）、UDP DNS / SNMP、登錄表、Event 消毒、安裝精靈的 port 檢查。"""

import contextlib
import io
import json
import os
import socket
import tempfile
import unittest
from email.message import EmailMessage

from honeypot.config import DEFAULTS, SERVICE_PORTS, ConfigError, load_config, validate_config
from honeypot.notify import Event, clean_text
from honeypot.services import CATALOG, create_service
from honeypot.services.base import open_socket
from honeypot.services.generic import MYSQL_GREETING, PG_SSL_REQUEST, PROFILES, GenericService, text_preview
from honeypot.services.udp import DnsService, SnmpService, parse_dns_question, parse_snmp
from tests.helpers import LOCAL, drain, make_cfg, make_notifier, quiet_logging, svc_cfg


class RegistryTests(unittest.TestCase):
    def test_catalog_matches_config_and_classes(self):
        """每個名稱建出來的是登錄的類別、預設 port 來自 SERVICE_PORTS（名稱兩邊不一致時 import 就會炸，不必再驗）。"""
        quiet_logging()
        notifier, _cap = make_notifier(make_cfg())
        try:
            for name, entry in CATALOG.items():
                with self.subTest(name=name):
                    svc = create_service(name, svc_cfg(), notifier, DEFAULTS["http_response"])
                    self.assertEqual(svc.name, name)
                    self.assertIsInstance(svc, entry.cls)
                    self.assertEqual(DEFAULTS["services"][name]["port"], SERVICE_PORTS[name])
        finally:
            notifier.close()

    def test_generic_profiles_are_all_in_catalog(self):
        for name in PROFILES:
            self.assertIn(name, CATALOG)

    def test_unknown_service_rejected(self):
        cfg = make_cfg()
        cfg["services"]["telnet"] = svc_cfg(23)
        with self.assertRaises(ConfigError):
            validate_config(cfg)


class TextPreviewTests(unittest.TestCase):
    def test_rdp_cookie_survives(self):
        raw = b"\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00Cookie: mstshash=Administrator\r\n\x01\x00\x08\x00"
        self.assertIn("mstshash=Administrator", text_preview(raw))

    def test_binary_collapses_to_single_dot(self):
        self.assertEqual(text_preview(b"\x00\x01\x02abc\xff\xfe"), "abc")
        self.assertEqual(text_preview(b"a\x00\x00\x00b"), "a.b")
        self.assertEqual(text_preview(b""), "")

    def test_limit(self):
        self.assertEqual(text_preview(b"a" * 500), "a" * 300)
        self.assertEqual(text_preview(b"abc", limit=2), "ab")


class GenericServiceTests(unittest.TestCase):
    def setUp(self):
        quiet_logging()
        self.notifier, self.cap = make_notifier(make_cfg())

    def tearDown(self):
        self.notifier.close()

    def _start(self, name):
        svc = GenericService(svc_cfg(), self.notifier, name)
        svc.start()
        self.addCleanup(svc.stop)
        return svc

    def test_ssh_sends_banner_and_logs_client_version(self):
        svc = self._start("ssh")
        with socket.create_connection((LOCAL, svc.port), timeout=5) as s:
            banner = s.recv(100)
            self.assertTrue(banner.startswith(b"SSH-2.0-"))
            s.sendall(b"SSH-2.0-libssh2_1.10.0\r\n")
            drain(s)
        self.cap.wait_events(1)
        ev, _ = self.cap.events[0]
        self.assertEqual(ev.service, "ssh")
        self.assertIn("SSH-2.0-libssh2_1.10.0", ev.details["text"])
        self.assertIn("SSH 連線", ev.message)

    def test_rdp_waits_for_client_and_logs_cookie(self):
        svc = self._start("rdp")
        with socket.create_connection((LOCAL, svc.port), timeout=5) as s:
            s.sendall(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00Cookie: mstshash=bob\r\n")
            drain(s)
        self.cap.wait_events(1)
        ev, _ = self.cap.events[0]
        self.assertEqual(ev.service, "rdp")
        self.assertIn("mstshash=bob", ev.details["text"])

    def test_connect_only_is_still_an_event(self):
        svc = self._start("redis")
        svc.client_timeout = 0.5
        with socket.create_connection((LOCAL, svc.port), timeout=5):
            pass
        self.cap.wait_events(1)
        self.assertIn("沒送資料", self.cap.events[0][0].message)

    def test_mysql_sends_greeting_and_logs_username(self):
        """MySQL 是 server 先說話：沒有 greeting，真正的 client 一個 byte 都不會送。"""
        svc = self._start("mysql")
        with socket.create_connection((LOCAL, svc.port), timeout=5) as s:
            greeting = s.recv(200)
            self.assertEqual(greeting, MYSQL_GREETING)
            self.assertEqual(greeting[3], 0)        # sequence id 必須是 0，client 才肯回
            self.assertEqual(greeting[4], 0x0a)     # HandshakeV10
            # HandshakeResponse41：caps、max packet、charset、23 byte 保留、帳號（NUL 結尾）、auth response、plugin
            response = (b"\x8d\xa6\x0f\x00" + b"\x00\x00\x00\x01" + b"\x21" + bytes(23)
                        + b"root\x00" + b"\x14" + bytes(20) + b"mysql_native_password\x00")
            s.sendall(len(response).to_bytes(3, "little") + b"\x01" + response)
            drain(s)
        self.cap.wait_events(1)
        ev, _ = self.cap.events[0]
        self.assertEqual(ev.service, "mysql")
        self.assertIn("root", ev.details["text"])
        self.assertIn("mysql_native_password", ev.details["text"])

    def test_postgres_answers_sslrequest_then_logs_startup(self):
        """libpq 先送 SSLRequest、要收到 N 才會送帶 user= 的 StartupMessage。"""
        svc = self._start("postgres")
        params = b"user\x00honeytest\x00database\x00shop\x00\x00"
        startup = (len(params) + 8).to_bytes(4, "big") + b"\x00\x03\x00\x00" + params
        with socket.create_connection((LOCAL, svc.port), timeout=5) as s:
            s.sendall(PG_SSL_REQUEST)
            self.assertEqual(s.recv(1), b"N")
            s.sendall(startup)
            drain(s)
        self.cap.wait_events(1)
        ev, _ = self.cap.events[0]
        self.assertEqual(ev.service, "postgres")
        self.assertIn("user.honeytest.database.shop", ev.details["text"])


class AliasedServiceTests(unittest.TestCase):
    """同一個類別跑在別的名稱（winrm_https）時，訊息也要用那個名稱，不能寫死 https。"""

    def test_winrm_https_message_uses_its_own_name(self):
        quiet_logging()
        notifier, cap = make_notifier(make_cfg())
        svc = create_service("winrm_https", svc_cfg(), notifier, DEFAULTS["http_response"])
        svc.client_timeout = 0.5
        svc.start()
        try:
            with socket.create_connection((LOCAL, svc.port), timeout=5):
                pass
            cap.wait_events(1)
            ev, _ = cap.events[0]
            self.assertEqual(ev.service, "winrm_https")
            self.assertIn("連線 winrm_https port", ev.message)
        finally:
            svc.stop()
            notifier.close()


def _dns_query(name: str, qtype: int = 1) -> bytes:
    labels = b"".join(len(part).to_bytes(1, "big") + part.encode() for part in name.split("."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"


def _ber_length(n: int) -> bytes:
    return bytes([n]) if n < 0x80 else b"\x82" + n.to_bytes(2, "big")


_SNMP_PDU = b"\xa0\x0b\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x00"


def _snmp_get(community: bytes, version: int = 1) -> bytes:
    body = b"\x02\x01" + bytes([version]) + b"\x04" + _ber_length(len(community)) + community + _SNMP_PDU
    return b"\x30" + _ber_length(len(body)) + body


class UdpParseTests(unittest.TestCase):
    def test_dns_question(self):
        q = parse_dns_question(_dns_query("version.bind", 16))
        self.assertEqual(q["name"], "version.bind")
        self.assertEqual(q["qtype"], "TXT")
        self.assertEqual(q["id"], 0x1234)

    def test_dns_response_and_garbage_rejected(self):
        response = b"\x12\x34\x81\x80\x00\x01" + bytes(6) + b"\x01a\x00\x00\x01\x00\x01"   # QR=1 且 qdcount=1
        self.assertIsNone(parse_dns_question(response))
        self.assertIsNone(parse_dns_question(b"hello"))
        self.assertIsNone(parse_dns_question(_dns_query("a.b")[:15]))      # 切在 label 中間
        self.assertIsNone(parse_dns_question(_dns_query("a.b")[:-4]))      # 切在 qtype 前面，不能回 qtype "0"
        self.assertIsNone(parse_dns_question(_dns_query("a.b")[:-3]))
        self.assertIsNone(parse_dns_question(_dns_query(".".join(["a" * 63] * 5))))   # 超過 255 octets

    def test_snmp_community(self):
        info = parse_snmp(_snmp_get(b"public"))
        self.assertEqual(info["version"], "v2c")
        self.assertEqual(info["community"], "public")
        self.assertIsNone(parse_snmp(b"\x16\x03\x01"))
        self.assertIsNone(parse_snmp(b"\x30"))
        self.assertIsNone(parse_snmp(b"\x30\x80\x02\x01\x01"))              # 不定長度不是 SNMP

    def test_snmp_rejects_oversized_fields(self):
        huge = b"\x02\x82\x06\xfa" + b"\xff" * 1786 + b"\x04\x06public" + _SNMP_PDU   # version INTEGER 1786 byte
        self.assertIsNone(parse_snmp(b"\x30\x82" + len(huge).to_bytes(2, "big") + huge))
        self.assertEqual(len(parse_snmp(_snmp_get(b"c" * 200))["community"]), 64)
        self.assertIsNone(parse_snmp(_snmp_get(b"public")[:9]))             # community 截斷：不回半截


class UdpServiceTests(unittest.TestCase):
    def setUp(self):
        quiet_logging()
        self.notifier, self.cap = make_notifier(make_cfg())

    def tearDown(self):
        self.notifier.close()

    def _send(self, svc, payload: bytes):
        svc.start()
        self.addCleanup(svc.stop)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(payload, (LOCAL, svc.port))
        self.cap.wait_events(1)
        self.assertEqual(len(self.cap.events), 1)
        return self.cap.events[0][0]

    def test_dns_query_logged(self):
        ev = self._send(DnsService(svc_cfg(), self.notifier), _dns_query("evil.example"))
        self.assertEqual(ev.service, "dns")
        self.assertIn("DNS 查詢 A evil.example", ev.message)
        self.assertEqual(ev.source_ip, LOCAL)

    def test_snmp_logged(self):
        ev = self._send(SnmpService(svc_cfg(), self.notifier), _snmp_get(b"public"))
        self.assertIn("community=public", ev.message)

    def test_garbage_udp_logged(self):
        ev = self._send(DnsService(svc_cfg(), self.notifier), b"\x00")
        self.assertIn("非 DNS", ev.message)

    def test_large_datagram_logged(self):
        """Windows 上 recvfrom 的緩衝區比 datagram 小會丟 WSAEMSGSIZE、整包不見；要收得到 4096 以上的封包。"""
        ev = self._send(DnsService(svc_cfg(), self.notifier), b"\x00" * 5000)
        self.assertEqual(ev.details["bytes"], 5000)
        self.assertIn("非 DNS", ev.message)


class EventSanitizeTests(unittest.TestCase):
    def test_control_characters_never_reach_subject_or_log(self):
        """DNS 名稱、SNMP community 是攻擊者的 byte：帶換行會讓 EmailMessage 的 Subject 炸掉、log 被偽造一行。"""
        quiet_logging()
        cfg = make_cfg(notify={"email": {"enabled": True, "smtp_server": "relay", "to_emails": ["a@b"]}})
        notifier, cap = make_notifier(cfg)
        try:
            notifier.emit(Event(service="dns", message="DNS 查詢 A evil\r\nSubject: pwned\x85.example",
                                source_ip="203.0.113.5", source_port=5, details={"name": "evil\nx"}))
            cap.wait_events(1)
        finally:
            notifier.close()
        ev, decision = cap.events[0]
        self.assertEqual(decision, "sent")
        subject, _body = cap.mails[0]
        self.assertEqual(len(subject.splitlines()), 1)
        EmailMessage()["Subject"] = subject            # 以前這裡丟 ValueError，整封告警寄不出去
        self.assertEqual(ev.message, "DNS 查詢 A evil.Subject: pwned..example")
        self.assertEqual(ev.details["name"], "evil.x")

    def test_clean_text_covers_every_splitlines_separator(self):
        for sep in ("\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " ", "\t"):
            self.assertEqual(clean_text(f"a{sep}b"), "a.b", repr(sep))
        self.assertEqual(clean_text("DNS 查詢 A evil.example"), "DNS 查詢 A evil.example")


class SetupCheckPortsTests(unittest.TestCase):
    """安裝精靈的 port 檢查只能把綁不到的 enabled 翻成 false 寫回檔案，不能把合併後的設定（含環境變數密碼）倒回去。"""

    def setUp(self):
        import setup

        self.setup = setup
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "config.json")
        self.addCleanup(setattr, setup, "CONFIG_FILE", setup.CONFIG_FILE)
        setup.CONFIG_FILE = self.path
        self.holder = open_socket(socket.SOCK_STREAM, LOCAL, 0)      # 占住一個 port，當「綁不到」的案例
        self.addCleanup(self.holder.close)

    def _cfg_from(self, user_file: dict) -> dict:
        """把 user_file 寫成 config.json、走正式的 load_config；所有服務先綁 loopback 並關閉，測試再開自己要的。"""
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(user_file, fh)
        cfg = load_config(self.path)
        for svc in cfg["services"].values():
            svc["interface"] = LOCAL
            svc["enabled"] = False
        return cfg

    def _check_ports(self, cfg: dict) -> bool:
        with contextlib.redirect_stdout(io.StringIO()):
            return self.setup.check_ports(cfg)

    def test_busy_port_disabled_without_leaking_env_password(self):
        os.environ["HONEYPOT_SMTP_PASSWORD"] = "secret-from-env"
        self.addCleanup(os.environ.pop, "HONEYPOT_SMTP_PASSWORD", None)
        cfg = self._cfg_from({
            "services": {
                "http": {"enabled": False, "port": 80},
                "https": {"enabled": False, "port": 443},
                "mssql": {"enabled": False, "port": 1433},
            },
            "notify": {"email": {"enabled": True, "smtp_server": "relay", "to_emails": ["a@b"],
                                 "username": "u", "password": ""}},
        })
        cfg["services"]["ssh"].update(enabled=True, port=self.holder.getsockname()[1])   # 被占
        cfg["services"]["redis"].update(enabled=True, port=0)                             # 可用
        self.assertTrue(self._check_ports(cfg))

        self.assertFalse(cfg["services"]["ssh"]["enabled"])
        self.assertTrue(cfg["services"]["redis"]["enabled"])
        with open(self.path, encoding="utf-8") as fh:
            written = json.load(fh)
        self.assertEqual(set(written["services"]), {"http", "https", "mssql", "ssh"})
        self.assertEqual(written["services"]["ssh"], {"enabled": False})
        self.assertEqual(written["notify"]["email"]["password"], "")
        self.assertNotIn("secret-from-env", json.dumps(written))

    def test_nothing_bindable_leaves_config_untouched(self):
        """全部綁不到時不能把全部 enabled=false 寫回去，不然下次開機服務就以「沒有任何服務」失敗、被 SCM 一直重啟。"""
        cfg = self._cfg_from({"services": {"ssh": {"enabled": True}}})
        with open(self.path, "rb") as fh:
            before = fh.read()
        cfg["services"]["ssh"].update(enabled=True, port=self.holder.getsockname()[1])
        self.assertFalse(self._check_ports(cfg))
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), before)


if __name__ == "__main__":
    unittest.main()

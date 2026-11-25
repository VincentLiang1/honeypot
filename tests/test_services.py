import socket
import ssl
import unittest

from honeypot.services import HttpService, MssqlService, TlsProbeService
from honeypot.services.http import parse_request
from honeypot.services.tls import parse_client_hello
from tests.helpers import LOCAL, drain, make_cfg, make_notifier, quiet_logging, svc_cfg


class ParseTests(unittest.TestCase):
    def test_parse_request(self):
        info = parse_request(b"GET /a?b=1 HTTP/1.1\r\nHost: h\r\nUser-Agent: ua\r\n\r\n")
        self.assertEqual(info["method"], "GET")
        self.assertEqual(info["path"], "/a?b=1")
        self.assertEqual(info["headers"]["User-Agent"], "ua")

    def test_parse_garbage(self):
        info = parse_request(b"\x16\x03\x01junk")
        self.assertEqual(info["method"], "?")


class HttpServiceTests(unittest.TestCase):
    def setUp(self):
        quiet_logging()
        self.notifier, self.cap = make_notifier(make_cfg())
        self.svc = HttpService(svc_cfg(), self.notifier, {"status": 200, "body": "<h1>hi</h1>", "server_header": "X"})
        self.svc.start()

    def tearDown(self):
        self.svc.stop()
        self.notifier.close()

    def test_request_gets_page_and_one_event(self):
        with socket.create_connection((LOCAL, self.svc.port), timeout=5) as s:
            s.sendall(b"GET /probe HTTP/1.1\r\nHost: x\r\nUser-Agent: scanner/1\r\n\r\n")
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        self.assertTrue(resp.startswith(b"HTTP/1.1 200 OK"))
        self.assertIn(b"Server: X", resp)
        self.assertTrue(resp.endswith(b"<h1>hi</h1>"))
        self.cap.wait_events(1)
        self.assertEqual(len(self.cap.events), 1)
        ev, _ = self.cap.events[0]
        self.assertEqual(ev.service, "http")
        self.assertEqual(ev.details["path"], "/probe")
        self.assertEqual(ev.details["user_agent"], "scanner/1")

    def test_connect_without_data_still_logged(self):
        self.svc.client_timeout = 0.5
        with socket.create_connection((LOCAL, self.svc.port), timeout=5):
            pass
        self.cap.wait_events(1)
        self.assertEqual(len(self.cap.events), 1)
        self.assertIn("沒送資料", self.cap.events[0][0].message)

    def test_second_bind_same_port_fails(self):
        other = HttpService(svc_cfg(self.svc.port), self.notifier, {})
        with self.assertRaises(OSError):
            other.start()


class MssqlServiceTests(unittest.TestCase):
    def setUp(self):
        quiet_logging()
        self.notifier, self.cap = make_notifier(make_cfg())
        self.svc = MssqlService(svc_cfg(), self.notifier)
        self.svc.start()

    def tearDown(self):
        self.svc.stop()
        self.notifier.close()

    def test_prelogin_recognised(self):
        prelogin = bytes([0x12, 0x01, 0x00, 0x2F, 0x00, 0x00, 0x01, 0x00]) + b"\x00" * 39
        with socket.create_connection((LOCAL, self.svc.port), timeout=5) as s:
            s.sendall(prelogin)
            drain(s)
        self.cap.wait_events(1)
        self.assertEqual(len(self.cap.events), 1)
        ev, _ = self.cap.events[0]
        self.assertEqual(ev.details["tds_type"], "Pre-Login")
        self.assertEqual(ev.details["tds_length"], 0x2F)

    def test_non_tds_data(self):
        with socket.create_connection((LOCAL, self.svc.port), timeout=5) as s:
            s.sendall(b"hello")
            drain(s)
        self.cap.wait_events(1)
        self.assertIn("非 TDS", self.cap.events[0][0].message)


def _client_hello(sni: str | None = "evil.example", tls13: bool = True) -> bytes:
    """手工組一個 ClientHello，確定性、不靠 ssl 模組。"""
    exts = b""
    if sni is not None:
        name = sni.encode("idna")
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        payload = len(entry).to_bytes(2, "big") + entry
        exts += b"\x00\x00" + len(payload).to_bytes(2, "big") + payload
    if tls13:
        payload = b"\x04\x03\x04\x03\x03"
        exts += b"\x00\x2b" + len(payload).to_bytes(2, "big") + payload
    hello = (
        b"\x03\x03" + bytes(32)          # version + random
        + b"\x00"                        # session id
        + b"\x00\x04\x13\x01\xc0\x2f"    # 兩個 cipher
        + b"\x01\x00"                    # compression
        + len(exts).to_bytes(2, "big") + exts
    )
    hs = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


class ClientHelloParseTests(unittest.TestCase):
    def test_sni_and_versions(self):
        info = parse_client_hello(_client_hello())
        self.assertEqual(info["sni"], "evil.example")
        self.assertEqual(info["versions"], ["TLS 1.3", "TLS 1.2"])
        self.assertEqual(info["cipher_count"], 2)
        self.assertEqual(info["hello_version"], "TLS 1.2")
        self.assertEqual(info["record_version"], "TLS 1.0")

    def test_without_extensions(self):
        info = parse_client_hello(_client_hello(sni=None, tls13=False))
        self.assertNotIn("sni", info)
        self.assertNotIn("versions", info)

    def test_real_ssl_module_client_hello(self):
        """用標準庫 ssl 產生真正的 ClientHello（memory BIO，不需要對方），確認解析得到 SNI。"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname="probe.example")
        with self.assertRaises(ssl.SSLWantReadError):
            obj.do_handshake()
        info = parse_client_hello(outgoing.read())
        self.assertEqual(info["sni"], "probe.example")
        self.assertIn("TLS 1.3", info["versions"])

    def test_truncated_and_garbage(self):
        data = _client_hello()
        for cut in (3, 5, 9, 20, 40, 48):      # 切在 header、random、session id、cipher 裡
            self.assertIsNone(parse_client_hello(data[:cut]), msg=f"cut={cut}")
        # 切在 extensions 裡：前面的欄位照樣回報，只是尾端的 supported_versions 不見了
        partial = parse_client_hello(data[:len(data) - 3])
        self.assertIsNotNone(partial)
        self.assertEqual(partial["sni"], "evil.example")
        self.assertNotIn("versions", partial)
        self.assertIsNone(parse_client_hello(b"GET / HTTP/1.1"))
        self.assertIsNone(parse_client_hello(b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00"))  # ServerHello 型別

    def test_wrong_length_fields_do_not_raise(self):
        data = bytearray(_client_hello())
        data[3:5] = b"\xff\xff"      # record 長度亂寫，後面照樣能解
        self.assertIsNotNone(parse_client_hello(bytes(data)))
        data[43] = 0xFF              # session id 長度亂寫
        self.assertIsNone(parse_client_hello(bytes(data)))


class TlsProbeServiceTests(unittest.TestCase):
    def setUp(self):
        quiet_logging()
        self.notifier, self.cap = make_notifier(make_cfg())
        self.svc = TlsProbeService(svc_cfg(), self.notifier)
        self.svc.start()

    def tearDown(self):
        self.svc.stop()
        self.notifier.close()

    def _send(self, data: bytes) -> None:
        with socket.create_connection((LOCAL, self.svc.port), timeout=5) as s:
            s.sendall(data)
            drain(s)
        self.cap.wait_events(1)
        self.assertEqual(len(self.cap.events), 1)

    def test_client_hello_records_sni_without_handshake(self):
        self._send(_client_hello())
        ev, _ = self.cap.events[0]
        self.assertEqual(ev.service, "https")
        self.assertIn("SNI=evil.example", ev.message)
        self.assertEqual(ev.details["sni"], "evil.example")
        self.assertNotIn("head_hex", ev.details)

    def test_real_tls_client_is_logged(self):
        """真的 TLS client 來連：握手會失敗（我們不回應），但事件已經記下。"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((LOCAL, self.svc.port), timeout=5) as raw:
            with self.assertRaises((ssl.SSLError, OSError)):
                with ctx.wrap_socket(raw, server_hostname="scanner.example"):
                    pass
        self.cap.wait_events(1)
        self.assertEqual(self.cap.events[0][0].details["sni"], "scanner.example")

    def test_plaintext_http_to_tls_port(self):
        self._send(b"GET /admin HTTP/1.0\r\n\r\n")
        ev, _ = self.cap.events[0]
        self.assertIn("明文 HTTP", ev.message)
        self.assertEqual(ev.details["request_line"], "GET /admin HTTP/1.0")

    def test_garbage(self):
        self._send(b"\x00\x01\x02hello")
        self.assertIn("非 TLS", self.cap.events[0][0].message)

    def test_sslv2_hello(self):
        self._send(b"\x80\x2e\x01\x00\x02" + bytes(44))
        self.assertIn("SSLv2", self.cap.events[0][0].message)

    def test_connect_without_data(self):
        self.svc.client_timeout = 0.5
        with socket.create_connection((LOCAL, self.svc.port), timeout=5):
            pass
        self.cap.wait_events(1)
        self.assertIn("沒送資料", self.cap.events[0][0].message)


if __name__ == "__main__":
    unittest.main()

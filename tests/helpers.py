"""測試共用：抓事件的 Notifier、暫存 log。"""

from __future__ import annotations

import copy
import logging
import threading
import time

from honeypot.config import DEFAULTS, _deep_merge
from honeypot.notify import Event, Notifier

LOCAL = "127.0.0.1"


def make_cfg(**overrides) -> dict:
    """以 DEFAULTS 為底，疊上測試要改的欄位。"""
    return _deep_merge(copy.deepcopy(DEFAULTS), overrides)


def svc_cfg(port: int = 0) -> dict:
    """單一服務的設定：綁 loopback，port 0 讓系統配一個空的。"""
    return {"enabled": True, "port": port, "interface": LOCAL}


def drain(sock) -> None:
    """等蜜罐那端關閉連線（它記完第一包就斷），再回來斷言事件。"""
    try:
        sock.recv(10)
    except OSError:
        pass


class Capture:
    """收下所有事件與寄信，供斷言用。"""

    def __init__(self):
        self.events: list[tuple[Event, str]] = []
        self.mails: list[tuple[str, str]] = []
        self.fail_mail = False
        self._lock = threading.Lock()

    def listener(self, event: Event, decision: str) -> None:
        with self._lock:
            self.events.append((event, decision))

    def wait_events(self, count: int, timeout: float = 5.0) -> None:
        """等到至少 count 個事件處理完。服務執行緒 emit 與測試斷言之間有競態，要等。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.events) >= count:
                    return
            time.sleep(0.02)

    def mail_sender(self, subject: str, body: str) -> None:
        if self.fail_mail:
            raise RuntimeError("SMTP down")
        with self._lock:
            self.mails.append((subject, body))


def make_notifier(cfg: dict | None = None) -> tuple[Notifier, Capture]:
    cfg = cfg or make_cfg()
    cap = Capture()
    notifier = Notifier(cfg, mail_sender=cap.mail_sender, listeners=[cap.listener])
    notifier.start()
    return notifier, cap


def quiet_logging() -> None:
    logging.getLogger("honeypot").setLevel(logging.CRITICAL)

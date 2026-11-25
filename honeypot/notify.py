"""事件通知：console、文字 log、Email，一條背景執行緒依序送出。

服務執行緒只負責 emit()，不等寄信。白名單與冷卻的判斷都在這裡做，
被抑制的事件照樣寫 console 與 log，只是不寄信。
"""

from __future__ import annotations

import datetime as dt
import logging
import queue
import re
import smtplib
import socket
import threading
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Callable

from .config import is_whitelisted

log = logging.getLogger("honeypot")

MailSender = Callable[[str, str], None]  # (subject, body) -> None，失敗就丟例外

# C0 / DEL / C1 控制字元與 U+2028、U+2029：這些是 str.splitlines() 會切的字元（含 latin-1 解出來的 \x85）
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")


def clean_text(text: str) -> str:
    """把一段控制字元壓成一個「.」。

    DNS 名稱、SNMP community、SNI、HTTP path 都是攻擊者的 byte，會進 log 行與信件主旨：
    EmailMessage 的標頭不收換行（丟 ValueError，整封告警寄不出去），log 也不能讓人偽造出獨立的一行。
    """
    return _CONTROL.sub(".", text)


@dataclass
class Event:
    """一次值得記錄的事情：蜜罐被連、程式啟停、heartbeat。"""

    service: str                      # services.CATALOG 的名稱（http、dns……）或 system
    message: str                      # 一句話描述，會進 log 與信件主旨
    source_ip: str = "-"
    source_port: int = 0
    details: dict[str, Any] = field(default_factory=dict)
    system: bool = False              # True 時跳過白名單與冷卻
    time: dt.datetime = field(default_factory=dt.datetime.now)
    cooldown_key: str | None = None   # 冷卻用的鍵；None 就用 source_ip。UDP 來源可偽造，改用服務名

    def __post_init__(self) -> None:
        # 攻擊者的 byte 只在這一處消毒：Event 一建好就是乾淨的，之後的 log、主旨、內文都不必再防。
        # details 重建成新 dict，不改呼叫端傳進來的那份。
        self.message = clean_text(self.message)
        self.details = {k: clean_text(v) if isinstance(v, str) else v for k, v in self.details.items()}

    @property
    def cooldown_id(self) -> str:
        return self.cooldown_key or self.source_ip


def hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown-host"


class SmtpMailSender:
    """用 smtplib 寄純文字信。每封信開一條新連線，簡單可靠。"""

    def __init__(self, email_cfg: dict[str, Any]):
        self.cfg = email_cfg

    def __call__(self, subject: str, body: str) -> None:
        cfg = self.cfg
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg["from_email"] or cfg["username"]
        msg["To"] = ", ".join(cfg["to_emails"])
        msg.set_content(body)

        timeout = cfg.get("timeout_seconds", 30)
        with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"], timeout=timeout) as smtp:
            if cfg.get("use_tls", True):
                smtp.starttls()
            if cfg.get("username"):
                smtp.login(cfg["username"], cfg["password"])
            smtp.send_message(msg)


class Notifier:
    """事件佇列 + 一條 worker 執行緒。

    mail_sender 可注入（測試用），listeners 會在每個事件處理完後被呼叫。
    """

    _STOP = object()

    def __init__(
        self,
        cfg: dict[str, Any],
        mail_sender: MailSender | None = None,
        listeners: list[Callable[[Event, str], None]] | None = None,
    ):
        self.whitelist: list[str] = list(cfg.get("whitelist", []))
        notify_cfg = cfg.get("notify", {})
        self.cooldown = dt.timedelta(minutes=notify_cfg.get("cooldown_minutes", 0))
        email_cfg = notify_cfg.get("email", {})
        self.mail_enabled = bool(email_cfg.get("enabled"))
        self.mail_sender: MailSender = mail_sender or SmtpMailSender(email_cfg)
        self.listeners = listeners or []
        self.host = hostname()

        self._queue: queue.Queue = queue.Queue()
        self._last_mail: dict[str, dt.datetime] = {}   # cooldown_id（source_ip 或服務名）-> 上次寄信時間
        self._worker = threading.Thread(target=self._run, name="notify", daemon=False)
        self._started = False

    # ---- 對外 ----

    def start(self) -> None:
        if not self._started:
            self._started = True
            self._worker.start()

    def emit(self, event: Event) -> None:
        """放進佇列立刻返回，不會阻塞呼叫端。"""
        self._queue.put(event)

    def system(self, message: str, **details: Any) -> None:
        """程式本身的事件（啟動、結束、heartbeat、服務失敗）。"""
        self.emit(Event(service="system", message=message, details=details, system=True))

    def flush(self, timeout: float | None = None) -> None:
        """等佇列裡的事件全部處理完（測試與關機時用）。"""
        if timeout is None:
            self._queue.join()
            return
        deadline = dt.datetime.now() + dt.timedelta(seconds=timeout)
        while self._queue.unfinished_tasks and dt.datetime.now() < deadline:
            threading.Event().wait(0.05)

    def close(self, timeout: float = 30.0) -> None:
        """送完佇列裡剩下的事件再停 worker。關機信靠這個才寄得出去。"""
        if not self._started:
            return
        self._queue.put(self._STOP)
        self._worker.join(timeout=timeout)
        if self._worker.is_alive():
            log.warning("通知執行緒在 %.0f 秒內沒有結束，放棄等待", timeout)

    # ---- 內部 ----

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is self._STOP:
                    return
                self._handle(item)
            except Exception:  # noqa: BLE001  worker 不能死
                log.exception("處理事件時發生未預期錯誤")
            finally:
                self._queue.task_done()

    def _decide_mail(self, event: Event) -> str:
        """回傳寄信決定：sent / disabled / whitelist / cooldown。"""
        if not self.mail_enabled:
            return "disabled"
        if event.system:
            return "sent"
        if is_whitelisted(event.source_ip, self.whitelist):
            return "whitelist"
        if self.cooldown > dt.timedelta(0):
            last = self._last_mail.get(event.cooldown_id)
            if last is not None and event.time - last < self.cooldown:
                return "cooldown"
            self._prune_cooldown(event.time)
        return "sent"

    def _prune_cooldown(self, now: dt.datetime) -> None:
        expired = [ip for ip, t in self._last_mail.items() if now - t >= self.cooldown]
        for ip in expired:
            del self._last_mail[ip]

    _MAIL_LABEL = {
        "sent": "已寄信",
        "disabled": "未啟用寄信",
        "whitelist": "白名單，不寄信",
        "cooldown": "冷卻中，不寄信",
    }

    def _handle(self, event: Event) -> None:
        decision = self._decide_mail(event)
        where = f"{event.source_ip}:{event.source_port}" if not event.system else "-"
        detail_text = " ".join(f"{k}={v!r}" for k, v in event.details.items())
        log.warning(
            "[%s] [%s] %s %s(%s)",
            event.service, where, event.message,
            f"| {detail_text} " if detail_text else "",
            self._MAIL_LABEL[decision],
        )

        if decision == "sent":
            try:
                self.mail_sender(self._subject(event), self._body(event))
                if not event.system:
                    self._last_mail[event.cooldown_id] = event.time
            except Exception as exc:  # noqa: BLE001
                decision = "failed"
                log.error("寄信失敗（%s）：%s", event.message, exc)

        for listener in self.listeners:
            try:
                listener(event, decision)
            except Exception:  # noqa: BLE001
                log.exception("listener 發生錯誤")

    def _subject(self, event: Event) -> str:
        if event.system:
            return f"[蜜罐] [{self.host}] {event.message}"
        return f"[蜜罐] [{self.host}] {event.service} 來自 {event.source_ip}：{event.message}"

    def _body(self, event: Event) -> str:
        lines = [
            "蜜罐通知" if event.system else "蜜罐告警",
            "=" * 12,
            f"主機名稱: {self.host}",
            f"時間: {event.time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"服務: {event.service}",
        ]
        if not event.system:
            lines.append(f"來源: {event.source_ip}:{event.source_port}")
        lines.append(f"事件: {event.message}")
        if event.details:
            lines.append("")
            lines.append("詳細資料:")
            for key, value in event.details.items():
                lines.append(f"  {key}: {value}")
        return "\n".join(lines) + "\n"

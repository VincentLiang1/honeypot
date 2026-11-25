"""服務基底：開 TCP / UDP 監聽、每條連線丟一條執行緒、把結果交給 Notifier。

TCP 子類實作 handle(client, addr) -> Event | None；UDP 子類（UdpService）實作 handle_datagram(data, addr)。
accept / recv 迴圈裡不做任何可能阻塞的事（解析、TLS 握手、寄信都不在這裡）。
"""

from __future__ import annotations

import logging
import socket
import sys
import threading
from typing import Any

from ..notify import Event, Notifier

log = logging.getLogger("honeypot")

HEX_BYTES = 32              # 事件的 head_hex 記前幾個 byte
UDP_MAX_DATAGRAM = 65535    # recvfrom 的緩衝區。Windows 上緩衝區比 datagram 小會丟 WSAEMSGSIZE 並把整包丟掉


def open_socket(kind: int, interface: str, port: int) -> socket.socket:
    """建一個已綁好的 socket（SOCK_STREAM 會順便 listen）。綁不到就先關掉 socket 再把 OSError 丟出去。

    Windows 的 SO_REUSEADDR 會讓兩個程式同時綁同一個 port 都「成功」，
    真正的服務在用時我們收不到任何連線還以為沒事。改用獨占（SO_EXCLUSIVEADDRUSE）。
    這條規則只寫在這裡：服務啟動與安裝精靈的試綁都走這個函式。
    """
    sock = socket.socket(socket.AF_INET, kind)
    if sys.platform == "win32":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((interface, port))
        if kind == socket.SOCK_STREAM:
            sock.listen(16)
    except OSError:
        sock.close()
        raise
    return sock


def first_packet_details(data: bytes) -> dict[str, Any]:
    """「收第一包就記錄」的服務共用的 details：長度與前 HEX_BYTES 個 byte 的 hex。回新的 dict，呼叫端可再加減欄位。"""
    return {"bytes": len(data), "head_hex": data[:HEX_BYTES].hex(" ")}


def recv_first(client: socket.socket) -> bytes:
    """收第一包；等到逾時就當作沒送（回 b""）。"""
    try:
        return client.recv(4096)
    except socket.timeout:
        return b""


class ByteReader:
    """帶界線檢查的位元組讀取器：讀超過就丟 ValueError，解析器統一接住後回 None。

    切片 data[pos:pos + n] 遇到截斷不會丟例外、只會靜默回短資料，解析器就會把半截封包當成合法值記下來；
    所有攻擊者餵進來的協定（TLS、DNS、SNMP）都用這個讀。
    """

    def __init__(self, data: bytes, start: int = 0, end: int | None = None):
        self.data = data
        self.pos = start
        self.end = len(data) if end is None else end

    def remaining(self) -> int:
        return self.end - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise ValueError("短封包")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def sub(self, n: int) -> "ByteReader":
        """切出一段長度 n 的子讀取器，父讀取器跳過那段。"""
        start = self.pos
        self.take(n)
        return ByteReader(self.data, start, start + n)


class Service:
    name = "base"
    proto = "tcp"              # 安裝精靈顯示用；UDP / TCP 由類別決定
    sock_type = socket.SOCK_STREAM
    client_timeout = 10.0      # 單一連線最多等幾秒沒資料就放棄
    accept_timeout = 1.0       # accept / recvfrom 每秒醒一次檢查 stop 旗標

    def __init__(self, cfg: dict[str, Any], notifier: Notifier, name: str | None = None):
        self.cfg = cfg
        self.notifier = notifier
        if name:
            self.name = name          # 同一個類別跑在不同 port（http / winrm）時用名稱區分
        self.interface: str = cfg.get("interface", "0.0.0.0")
        self.port: int = int(cfg.get("port", 0))
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ---- 生命週期 ----

    def start(self) -> None:
        """綁 port 並開始收。綁不到就丟 OSError，由呼叫端決定要不要通知。"""
        sock = open_socket(self.sock_type, self.interface, self.port)
        self.port = sock.getsockname()[1]   # port 設 0 時拿到實際分配的
        sock.settimeout(self.accept_timeout)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._run_loop, name=f"{self.name}-listen", daemon=True)
        self._thread.start()
        log.info("[%s] 監聽 %s%s:%d", self.name, "UDP " if self.proto == "udp" else "", self.interface, self.port)

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=self.accept_timeout * 3)
            self._thread = None
        log.info("[%s] 已停止", self.name)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ---- 連線處理 ----

    def _run_loop(self) -> None:
        """監聽執行緒的本體：TCP 是 accept 迴圈，UdpService 覆寫成 recvfrom 迴圈。"""
        sock = self._sock   # 綁成區域變數：stop() 會把 self._sock 設回 None，不要在迴圈裡讀它
        assert sock is not None
        while not self._stop.is_set():
            try:
                client, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                log.exception("[%s] accept 失敗", self.name)
                break
            client.settimeout(self.client_timeout)
            threading.Thread(
                target=self._serve, args=(client, addr),
                name=f"{self.name}-{addr[0]}", daemon=True,
            ).start()

    def _serve(self, client: socket.socket, addr: tuple[str, int]) -> None:
        event: Event | None = None
        try:
            event = self.handle(client, addr)
        except (socket.timeout, ConnectionError, OSError) as exc:
            event = self.event(addr, f"連線 {self.name} port {self.port}（{exc.__class__.__name__}）")
        except Exception as exc:  # noqa: BLE001  協定解析炸掉也要留下紀錄
            log.exception("[%s] 處理 %s:%d 時發生錯誤", self.name, addr[0], addr[1])
            event = self.event(addr, f"連線 {self.name} port {self.port}（處理錯誤：{exc}）")
        finally:
            try:
                client.close()
            except OSError:
                pass
        if event is not None:
            self.notifier.emit(event)

    def handle(self, client: socket.socket, addr: tuple[str, int]) -> Event | None:
        """子類實作：與對方互動並回傳事件。回 None 表示不記錄。"""
        raise NotImplementedError

    def event(self, addr: tuple[str, int], message: str, **details: Any) -> Event:
        details.setdefault("port", self.port)
        return Event(
            service=self.name, message=message,
            source_ip=addr[0], source_port=addr[1], details=details,
        )

    def no_data_event(self, addr: tuple[str, int]) -> Event:
        """對方連上但一個 byte 都沒送（或等到逾時）：各服務共用同一句話。"""
        return self.event(addr, f"連線 {self.name} port {self.port} 但沒送資料")

    @staticmethod
    def recv_until(client: socket.socket, marker: bytes, limit: int) -> bytes:
        """收到 marker 或滿 limit bytes 或對方關閉為止。"""
        buf = b""
        while marker not in buf and len(buf) < limit:
            chunk = client.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf


class UdpService(Service):
    """UDP 版：沒有連線，每個 datagram 就是一個事件。子類實作 handle_datagram(data, addr)。"""

    proto = "udp"
    sock_type = socket.SOCK_DGRAM

    def _run_loop(self) -> None:
        sock = self._sock
        assert sock is not None
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(UDP_MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                # 這個 socket 從不 sendto，不會有 ICMP 造成的 ConnectionResetError；會走到這裡的是真的出事
                # （例如洪水下的 WSAENOBUFS）。記一行、歇一拍再收：不無聲空轉，也不讓監聽就此死掉。
                log.warning("[%s] recvfrom 失敗：%s，%.0f 秒後重試", self.name, exc, self.accept_timeout)
                self._stop.wait(self.accept_timeout)
                continue
            try:
                event = self.handle_datagram(data, addr)
            except Exception as exc:  # noqa: BLE001
                log.exception("[%s] 處理 %s:%d 的封包時發生錯誤", self.name, addr[0], addr[1])
                event = self.event(addr, f"UDP {self.name} port {self.port}（處理錯誤：{exc}）")
            if event is not None:
                self.notifier.emit(event)

    def handle_datagram(self, data: bytes, addr: tuple[str, int]) -> Event | None:
        raise NotImplementedError

    def event(self, addr: tuple[str, int], message: str, **details: Any) -> Event:
        # UDP 沒有握手、來源 IP 可以偽造：冷卻改以服務為鍵，整個 port 在冷卻期內只寄一封，
        # 偽造來源的洪水就灌不爆信箱（每個封包照樣寫 log）
        ev = super().event(addr, message, **details)
        ev.cooldown_key = f"udp:{self.name}"
        return ev

    def handle(self, client: socket.socket, addr: tuple[str, int]) -> Event | None:
        raise NotImplementedError("UDP 服務沒有連線")

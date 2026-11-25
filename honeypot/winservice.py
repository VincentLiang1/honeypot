"""Windows 服務介接：只用 ctypes 跟 SCM（服務控制管理員）說話，不靠 pywin32。

流程：
  main.py --service  →  ServiceRunner.run()  →  StartServiceCtrlDispatcherW（卡住主執行緒）
      SCM 另開一條執行緒呼叫 _service_main  →  回報 START_PENDING  →  跑蜜罐本體
      SCM 送 STOP / SHUTDOWN  →  _handler 設 stop 旗標、回報 STOP_PENDING
      本體收尾返回  →  回報 STOPPED，dispatcher 跟著返回

注意：
  - ctypes callback 裡的例外會被吞掉不會往外丟，所以 _service_main 自己 try/except，
    無論如何都要回報 STOPPED，否則服務會永遠卡在「正在啟動」。
  - callback 與 service table 都掛在物件上，dispatcher 卡住期間不能被回收。
  - 本體跑在 SCM 開的執行緒，不是主執行緒：signal.signal 會失敗，不要在裡面用。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
import subprocess
import sys
import threading
from typing import Any, Callable

log = logging.getLogger("honeypot")

SERVICE_NAME = "Honeypot"
DISPLAY_NAME = "Honeypot 蜜罐"
DESCRIPTION = "低互動蜜罐：監聽 HTTP / HTTPS / MSSQL / SSH / RDP / DNS / SNMP 等 17 個常被掃的 port，有人連就寫 log、寄信"

SERVICE_WIN32_OWN_PROCESS = 0x00000010

SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4

SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_SHUTDOWN = 0x00000004

SERVICE_CONTROL_STOP = 1
SERVICE_CONTROL_INTERROGATE = 4
SERVICE_CONTROL_SHUTDOWN = 5

ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063
ERROR_SERVICE_SPECIFIC_ERROR = 1066

STOP_WAIT_HINT_MS = 90_000        # 比 notifier.close(timeout=60) 長，SCM 才不會提早判定失敗
SHUTDOWN_CLOSE_TIMEOUT = 15.0     # 關機時 Windows 只給約 20 秒
NORMAL_CLOSE_TIMEOUT = 60.0


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wt.DWORD),
        ("dwCurrentState", wt.DWORD),
        ("dwControlsAccepted", wt.DWORD),
        ("dwWin32ExitCode", wt.DWORD),
        ("dwServiceSpecificExitCode", wt.DWORD),
        ("dwCheckPoint", wt.DWORD),
        ("dwWaitHint", wt.DWORD),
    ]


SERVICE_MAIN_FUNCTION = ctypes.WINFUNCTYPE(None, wt.DWORD, ctypes.POINTER(wt.LPWSTR))
HANDLER_FUNCTION_EX = ctypes.WINFUNCTYPE(wt.DWORD, wt.DWORD, wt.DWORD, wt.LPVOID, wt.LPVOID)


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wt.LPWSTR),
        ("lpServiceProc", SERVICE_MAIN_FUNCTION),
    ]


class Advapi32:
    """真正的 advapi32 呼叫。測試時換成假物件。"""

    def __init__(self) -> None:
        dll = ctypes.WinDLL("advapi32", use_last_error=True)
        self._start = dll.StartServiceCtrlDispatcherW
        self._start.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRYW)]
        self._start.restype = wt.BOOL
        self._register = dll.RegisterServiceCtrlHandlerExW
        self._register.argtypes = [wt.LPCWSTR, HANDLER_FUNCTION_EX, wt.LPVOID]
        self._register.restype = wt.HANDLE
        self._set_status = dll.SetServiceStatus
        self._set_status.argtypes = [wt.HANDLE, ctypes.POINTER(SERVICE_STATUS)]
        self._set_status.restype = wt.BOOL

    def start_dispatcher(self, table: Any) -> None:
        if not self._start(table):
            err = ctypes.get_last_error()
            raise OSError(err, ctypes.FormatError(err))

    def register_handler(self, name: str, handler: Any) -> int | None:
        return self._register(name, handler, None)

    def set_status(self, handle: int, status: SERVICE_STATUS) -> bool:
        return bool(self._set_status(handle, ctypes.byref(status)))


# body(runner) -> exit code。本體要在服務準備好時呼叫 runner.set_running()，
# 並監看 runner.stop；runner.shutting_down 為 True 表示是關機不是手動停止。
ServiceBody = Callable[["ServiceRunner"], int]


class ServiceRunner:
    def __init__(self, name: str, body: ServiceBody, api: Any | None = None):
        self.name = name
        self.body = body
        self.api = api or Advapi32()
        self.stop = threading.Event()
        self.shutting_down = False
        self.exit_code: int | None = None
        self.reported: list[tuple[int, int, int]] = []   # (state, win32 exit, specific exit) 歷史，測試看這個

        self._handle: int | None = None
        self._status = SERVICE_STATUS()
        self._status.dwServiceType = SERVICE_WIN32_OWN_PROCESS
        # callback 物件必須活得跟 runner 一樣久
        self._main_cb = SERVICE_MAIN_FUNCTION(self._service_main)
        self._handler_cb = HANDLER_FUNCTION_EX(self._handler)
        self._table = (SERVICE_TABLE_ENTRYW * 2)()
        self._table[0].lpServiceName = name
        self._table[0].lpServiceProc = self._main_cb

    # ---- 對外 ----

    def run(self) -> int:
        """主執行緒呼叫；交給 SCM 直到服務結束。不是 SCM 啟動的會丟 OSError(1063)。"""
        self.api.start_dispatcher(self._table)
        return self.exit_code or 0

    def set_running(self) -> None:
        self._report(SERVICE_RUNNING)

    # ---- SCM callback ----

    def _service_main(self, argc: int, argv: Any) -> None:
        code = 1
        try:
            self._handle = self.api.register_handler(self.name, self._handler_cb)
            if not self._handle:
                log.error("RegisterServiceCtrlHandlerExW 失敗")
                return
            self._report(SERVICE_START_PENDING, wait_hint=30_000)
            code = int(self.body(self))
        except Exception:  # noqa: BLE001  callback 裡的例外不會往外傳，只能自己記
            log.exception("服務本體發生未處理的例外")
            code = 1
        finally:
            self.exit_code = code
            if self._handle:
                if code:
                    self._report(SERVICE_STOPPED, exit_code=ERROR_SERVICE_SPECIFIC_ERROR, specific=code)
                else:
                    self._report(SERVICE_STOPPED)

    def _handler(self, control: int, event_type: int, event_data: Any, context: Any) -> int:
        if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
            self.shutting_down = control == SERVICE_CONTROL_SHUTDOWN
            self._report(SERVICE_STOP_PENDING, wait_hint=STOP_WAIT_HINT_MS)
            self.stop.set()
            return 0
        if control == SERVICE_CONTROL_INTERROGATE:
            self._report(self._status.dwCurrentState)
            return 0
        return ERROR_CALL_NOT_IMPLEMENTED

    def _report(self, state: int, exit_code: int = 0, specific: int = 0, wait_hint: int = 0) -> None:
        st = self._status
        st.dwCurrentState = state
        st.dwWin32ExitCode = exit_code
        st.dwServiceSpecificExitCode = specific
        st.dwWaitHint = wait_hint
        st.dwControlsAccepted = (
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN if state == SERVICE_RUNNING else 0
        )
        st.dwCheckPoint = 0
        self.reported.append((state, exit_code, specific))
        if self._handle is not None:
            self.api.set_status(self._handle, st)


# ---- 安裝 / 移除（呼叫內建的 sc.exe，不必自己接 CreateService）----


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def service_command_line(main_py: str, config: str | None) -> str:
    """服務的 binPath：目前這顆 python.exe + main.py --service，路徑都加引號。"""
    parts = [f'"{sys.executable}"', f'"{os.path.abspath(main_py)}"', "--service"]
    if config:
        parts += ["-c", f'"{os.path.abspath(config)}"']
    return " ".join(parts)


def _sc(*args: str) -> int:
    cmd = ["sc.exe", *args]
    print("> " + " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    out = (proc.stdout + proc.stderr).strip()
    if out:
        print(out)
    return proc.returncode


def install(main_py: str, config: str | None, name: str = SERVICE_NAME) -> int:
    if not is_admin():
        print("安裝服務需要系統管理員權限：請用「以系統管理員身分執行」的命令提示字元再跑一次", file=sys.stderr)
        return 3
    bin_path = service_command_line(main_py, config)
    rc = _sc("create", name, "binPath=", bin_path, "start=", "auto", "DisplayName=", DISPLAY_NAME)
    if rc != 0:
        return rc
    _sc("description", name, DESCRIPTION)
    # 當掉自動重啟：5 秒、5 秒、60 秒，一天後重算；failureflag 讓非 0 結束碼也算失敗
    _sc("failure", name, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000")
    _sc("failureflag", name, "1")
    print(f"服務 {name} 已安裝（開機自動啟動）。現在啟動：sc start {name}")
    return 0


def uninstall(name: str = SERVICE_NAME) -> int:
    if not is_admin():
        print("移除服務需要系統管理員權限", file=sys.stderr)
        return 3
    _sc("stop", name)
    return _sc("delete", name)

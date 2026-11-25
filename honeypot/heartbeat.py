"""每日 heartbeat：到了設定時間就寄一封「還活著」。

已發送日期存在 state 檔，不回寫 config.json。
判斷規則：今天還沒寄過、而且現在已經過了設定時間，就寄。
所以 09:00 設定、程式 15:00 才啟動，啟動後一分鐘內會補寄當天那封。
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import threading
from typing import Any

from .config import parse_hhmm
from .notify import Notifier

log = logging.getLogger("honeypot")

STATE_KEY = "last_heartbeat_date"


def should_send(now: dt.datetime, target: str, last_date: str | None) -> bool:
    """純函式，方便測試。target 是 "HH:MM"，last_date 是 "YYYY-MM-DD" 或 None。"""
    today = now.date().isoformat()
    if last_date == today:
        return False
    hour, minute = parse_hhmm(target)
    return (now.hour, now.minute) >= (hour, minute)


def load_state(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("state 檔 %s 讀取失敗，當作空的：%s", path, exc)
        return {}


def save_state(path: str, state: dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


class Heartbeat(threading.Thread):
    """每 60 秒醒來看一次要不要寄。stop() 後最多一個 interval 內結束。"""

    def __init__(
        self,
        notifier: Notifier,
        target_time: str,
        state_file: str,
        interval_seconds: float = 60.0,
    ):
        super().__init__(name="heartbeat", daemon=True)
        self.notifier = notifier
        self.target_time = target_time
        self.state_file = state_file
        self.interval = interval_seconds
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick(dt.datetime.now())
            except Exception:  # noqa: BLE001
                log.exception("heartbeat 檢查時發生錯誤")
            self._stop.wait(self.interval)

    def tick(self, now: dt.datetime) -> bool:
        """檢查一次；有寄就回 True。拆出來讓測試不用等執行緒。"""
        state = load_state(self.state_file)
        if not should_send(now, self.target_time, state.get(STATE_KEY)):
            return False
        self.notifier.system(
            "Heartbeat：蜜罐正常運行",
            時間=now.strftime("%Y-%m-%d %H:%M"),
            設定時間=self.target_time,
        )
        state[STATE_KEY] = now.date().isoformat()
        save_state(self.state_file, state)
        log.info("heartbeat 已送出（%s）", state[STATE_KEY])
        return True

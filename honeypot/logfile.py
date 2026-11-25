"""一天一個 log 檔，保留固定天數，單日有大小上限。

log_file 設 "honeypot.log" 時，實際寫的是 honeypot-2026-11-03.log 這種檔名：
副檔名留在最後，檔案總管雙擊就能用記事本開。

為什麼不用標準庫的 TimedRotatingFileHandler：
- 它沒有單日大小上限。離線的 DMZ 機器沒人顧磁碟，被大量掃描的那天不能把磁碟寫滿。
- 它換日時要 rename 正在用的檔案，Windows 上只要有別的程式開著那個檔案就會失敗。
  直接寫到帶日期的檔名就不必 rename。

清理依檔名裡的日期判斷，不看修改時間（複製、備份還原都會改到修改時間）。
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import re
from typing import BinaryIO


def daily_path(log_file: str, day: dt.date) -> str:
    """honeypot.log + 2026-11-03 → honeypot-2026-11-03.log"""
    stem, ext = os.path.splitext(log_file)
    return f"{stem}-{day.isoformat()}{ext}"


class DailyFileHandler(logging.Handler):
    def __init__(self, log_file: str, keep_days: int, daily_max_mb: float) -> None:
        super().__init__()
        self.log_file = log_file
        self.keep_days = keep_days
        self.max_bytes = int(daily_max_mb * 1024 * 1024)
        self._day: dt.date | None = None
        self._fh: BinaryIO | None = None
        self._size = 0
        self._full = False
        folder = os.path.dirname(log_file)
        if folder:
            os.makedirs(folder, exist_ok=True)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            day = dt.date.fromtimestamp(record.created)
            if day != self._day:
                self._open(day)
            if self._full:
                return
            data = (self.format(record) + os.linesep).encode("utf-8", errors="replace")
            if self._size + len(data) > self.max_bytes:
                # 之後到午夜前的紀錄都丟掉；寄信不受影響（走 Notifier，不經過這裡）
                self._full = True
                data = (
                    f"[{dt.datetime.fromtimestamp(record.created):%Y-%m-%d %H:%M:%S}] [WARNING] "
                    f"今天的 log 已達 {self.max_bytes // (1024 * 1024)} MB 上限，到午夜前不再寫入"
                    + os.linesep
                ).encode("utf-8")
            assert self._fh is not None
            self._fh.write(data)
            self._fh.flush()
            self._size += len(data)
        except Exception:
            self.handleError(record)

    def _open(self, day: dt.date) -> None:
        self._close_file()
        path = daily_path(self.log_file, day)
        self._fh = open(path, "ab")
        self._size = self._fh.tell()
        self._full = self._size >= self.max_bytes   # 當天重開時已經滿了就維持不寫
        self._day = day
        self._purge(day)

    def _purge(self, today: dt.date) -> None:
        """刪掉 keep_days 天以前的檔案（含今天共保留 keep_days 天）。"""
        oldest = today - dt.timedelta(days=self.keep_days - 1)
        folder = os.path.dirname(self.log_file) or "."
        stem, ext = os.path.splitext(os.path.basename(self.log_file))
        pattern = re.compile(re.escape(stem) + r"-(\d{4}-\d{2}-\d{2})" + re.escape(ext) + r"\Z")
        for name in os.listdir(folder):
            match = pattern.match(name)
            if not match:
                continue
            try:
                if dt.date.fromisoformat(match.group(1)) < oldest:
                    os.remove(os.path.join(folder, name))
            except (ValueError, OSError):
                continue   # 日期不合法或檔案被佔用：下次換日再試

    def _close_file(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def close(self) -> None:
        self.acquire()
        try:
            self._close_file()
        finally:
            self.release()
        super().close()

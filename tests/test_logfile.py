import datetime as dt
import json
import logging
import os
import tempfile
import unittest

from honeypot.config import ConfigError, load_config
from honeypot.logfile import DailyFileHandler, daily_path


def _record(when: dt.datetime, msg: str) -> logging.LogRecord:
    rec = logging.LogRecord("honeypot", logging.WARNING, __file__, 0, msg, None, None)
    rec.created = when.timestamp()
    return rec


class DailyFileHandlerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)   # 先登記的後執行：handler 關檔之後才刪資料夾（Windows 刪不掉開著的檔）
        self.tmp = tmp.name
        self.log_file = os.path.join(self.tmp, "honeypot.log")

    def _handler(self, keep_days=1827, daily_max_mb=50):
        h = DailyFileHandler(self.log_file, keep_days, daily_max_mb)
        h.setFormatter(logging.Formatter("%(message)s"))
        self.addCleanup(h.close)
        return h

    def _read(self, day):
        with open(daily_path(self.log_file, day), encoding="utf-8") as fh:
            return fh.read()

    def test_daily_path_keeps_extension_last(self):
        self.assertEqual(daily_path("logs/honeypot.log", dt.date(2026, 11, 3)),
                         "logs/honeypot-2026-11-03.log")

    def test_one_file_per_day(self):
        h = self._handler()
        h.emit(_record(dt.datetime(2026, 11, 3, 23, 59), "前一天"))
        h.emit(_record(dt.datetime(2026, 11, 4, 0, 1), "隔天"))
        self.assertIn("前一天", self._read(dt.date(2026, 11, 3)))
        self.assertNotIn("隔天", self._read(dt.date(2026, 11, 3)))
        self.assertIn("隔天", self._read(dt.date(2026, 11, 4)))
        self.assertFalse(os.path.exists(self.log_file))   # 不再有不帶日期的檔

    def test_old_files_purged_by_name_date(self):
        def touch(name):
            open(os.path.join(self.tmp, name), "w").close()
        touch("honeypot-2026-10-31.log")   # 第 4 天前：刪
        touch("honeypot-2026-11-01.log")   # keep_days=3：11-01、11-02、11-03 留
        touch("honeypot.log")               # 舊版檔名：不動
        touch("honeypot.log.1")
        touch("other-2020-01-01.log")       # 別人的檔：不動
        self._handler(keep_days=3).emit(_record(dt.datetime(2026, 11, 3, 12), "x"))
        self.assertEqual(sorted(os.listdir(self.tmp)), [
            "honeypot-2026-11-01.log", "honeypot-2026-11-03.log",
            "honeypot.log", "honeypot.log.1", "other-2020-01-01.log",
        ])

    def test_daily_cap_stops_writing_until_midnight(self):
        h = self._handler(daily_max_mb=0.001)   # 約 1 KB
        day = dt.datetime(2026, 11, 3, 10)
        for i in range(100):
            h.emit(_record(day, f"line {i:03d} " + "x" * 40))
        text = self._read(day.date())
        self.assertLess(len(text.encode("utf-8")), 1100)
        self.assertEqual(text.count("上限"), 1)
        self.assertNotIn("line 099", text)
        h.emit(_record(dt.datetime(2026, 11, 4, 0, 0, 1), "隔天恢復"))
        self.assertIn("隔天恢復", self._read(dt.date(2026, 11, 4)))

    def test_cap_survives_restart(self):
        day = dt.datetime(2026, 11, 3, 10)
        with open(daily_path(self.log_file, day.date()), "wb") as fh:
            fh.write(b"x" * 2000)
        self._handler(daily_max_mb=0.001).emit(_record(day, "重開後"))
        self.assertNotIn("重開後", self._read(day.date()))


class LogRotateConfigTests(unittest.TestCase):
    def _load(self, data):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            return load_config(path)

    def test_defaults_five_years_50mb(self):
        rotate = self._load({})["log_rotate"]
        self.assertEqual(rotate["keep_days"], 1827)
        self.assertEqual(rotate["daily_max_mb"], 50)

    def test_old_keys_from_previous_version_are_tolerated(self):
        cfg = self._load({"log_rotate": {"max_mb": 10, "backups": 5}})
        self.assertEqual(cfg["log_rotate"]["keep_days"], 1827)

    def test_bad_values_rejected(self):
        for bad in ({"keep_days": 0}, {"keep_days": "30"}, {"daily_max_mb": 0}, {"daily_max_mb": True}):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                self._load({"log_rotate": bad})


if __name__ == "__main__":
    unittest.main()

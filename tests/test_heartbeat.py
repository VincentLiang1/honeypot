import datetime as dt
import os
import tempfile
import unittest

from honeypot.heartbeat import STATE_KEY, Heartbeat, load_state, should_send
from tests.helpers import make_cfg, make_notifier, quiet_logging


class ShouldSendTests(unittest.TestCase):
    def test_before_target_time(self):
        self.assertFalse(should_send(dt.datetime(2026, 1, 1, 8, 59), "09:00", None))

    def test_at_or_after_target_time(self):
        self.assertTrue(should_send(dt.datetime(2026, 1, 1, 9, 0), "09:00", None))
        self.assertTrue(should_send(dt.datetime(2026, 1, 1, 15, 30), "09:00", "2025-12-31"))

    def test_already_sent_today(self):
        self.assertFalse(should_send(dt.datetime(2026, 1, 1, 10, 0), "09:00", "2026-01-01"))


class HeartbeatThreadTests(unittest.TestCase):
    def setUp(self):
        quiet_logging()

    def test_tick_sends_once_and_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = os.path.join(tmp, "state.json")
            notifier, cap = make_notifier(make_cfg(
                notify={"email": {"enabled": True, "smtp_server": "x", "to_emails": ["a@b"]}}))
            hb = Heartbeat(notifier, "09:00", state_file)
            now = dt.datetime(2026, 1, 1, 9, 30)
            self.assertTrue(hb.tick(now))
            self.assertFalse(hb.tick(now + dt.timedelta(hours=1)))
            self.assertTrue(hb.tick(now + dt.timedelta(days=1)))
            notifier.close()
            self.assertEqual(load_state(state_file)[STATE_KEY], "2026-01-02")
            self.assertEqual(len(cap.mails), 2)
            self.assertTrue(all("Heartbeat" in s for s, _ in cap.mails))


if __name__ == "__main__":
    unittest.main()

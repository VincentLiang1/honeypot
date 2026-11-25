import datetime as dt
import unittest

from honeypot.notify import Event
from honeypot.services.udp import DnsService
from tests.helpers import make_cfg, make_notifier, quiet_logging, svc_cfg


def _mail_cfg(whitelist: tuple[str, ...] = ("10.0.0.0/8",), **kw) -> dict:
    """寄信開著、冷卻 10 分鐘的設定。"""
    return make_cfg(
        whitelist=list(whitelist),
        notify={"cooldown_minutes": 10, "email": {"enabled": True, "smtp_server": "x", "to_emails": ["a@b"]}},
        **kw,
    )


class NotifyTests(unittest.TestCase):
    def setUp(self):
        quiet_logging()

    def test_mail_sent_for_normal_event(self):
        notifier, cap = make_notifier(_mail_cfg())
        notifier.emit(Event(service="http", message="HTTP GET /", source_ip="1.2.3.4", source_port=5))
        notifier.flush()
        notifier.close()
        self.assertEqual([d for _, d in cap.events], ["sent"])
        self.assertEqual(len(cap.mails), 1)
        self.assertIn("1.2.3.4", cap.mails[0][0])
        self.assertIn("HTTP GET /", cap.mails[0][1])

    def test_whitelisted_ip_logged_but_not_mailed(self):
        notifier, cap = make_notifier(_mail_cfg())
        notifier.emit(Event(service="http", message="x", source_ip="10.9.9.9"))
        notifier.flush()
        notifier.close()
        self.assertEqual([d for _, d in cap.events], ["whitelist"])
        self.assertEqual(cap.mails, [])

    def test_cooldown_suppresses_second_mail_same_ip(self):
        notifier, cap = make_notifier(_mail_cfg())
        t0 = dt.datetime(2026, 1, 1, 12, 0, 0)
        notifier.emit(Event(service="http", message="a", source_ip="1.1.1.1", time=t0))
        notifier.emit(Event(service="http", message="b", source_ip="1.1.1.1", time=t0 + dt.timedelta(minutes=5)))
        notifier.emit(Event(service="http", message="c", source_ip="2.2.2.2", time=t0 + dt.timedelta(minutes=5)))
        notifier.emit(Event(service="http", message="d", source_ip="1.1.1.1", time=t0 + dt.timedelta(minutes=11)))
        notifier.flush()
        notifier.close()
        self.assertEqual([d for _, d in cap.events], ["sent", "cooldown", "sent", "sent"])
        self.assertEqual(len(cap.mails), 3)

    def test_system_event_bypasses_whitelist_and_cooldown(self):
        notifier, cap = make_notifier(_mail_cfg())
        notifier.system("啟動")
        notifier.system("啟動 again")
        notifier.flush()
        notifier.close()
        self.assertEqual([d for _, d in cap.events], ["sent", "sent"])

    def test_mail_disabled(self):
        notifier, cap = make_notifier(make_cfg())
        notifier.emit(Event(service="http", message="x", source_ip="1.2.3.4"))
        notifier.flush()
        notifier.close()
        self.assertEqual([d for _, d in cap.events], ["disabled"])

    def test_mail_failure_does_not_kill_worker(self):
        notifier, cap = make_notifier(_mail_cfg())
        cap.fail_mail = True
        notifier.emit(Event(service="http", message="x", source_ip="1.2.3.4"))
        notifier.flush()
        cap.fail_mail = False
        notifier.emit(Event(service="http", message="y", source_ip="5.6.7.8"))
        notifier.flush()
        notifier.close()
        self.assertEqual([d for _, d in cap.events], ["failed", "sent"])

    def test_close_drains_queue(self):
        notifier, cap = make_notifier(_mail_cfg())
        for i in range(20):
            notifier.emit(Event(service="http", message=str(i), source_ip=f"9.9.9.{i}"))
        notifier.close()
        self.assertEqual(len(cap.events), 20)



class CooldownKeyTests(unittest.TestCase):
    def setUp(self):
        quiet_logging()
        self.notifier, self.cap = make_notifier(_mail_cfg(whitelist=[]))

    def tearDown(self):
        self.notifier.close()

    def test_service_keyed_cooldown_merges_spoofed_sources(self):
        """同一個 cooldown_key、不同來源 IP：第一封寄出，其餘冷卻。"""
        now = dt.datetime(2026, 11, 1, 12, 0, 0)
        for i in range(5):
            self.notifier.emit(Event(service="dns", message="DNS 查詢", source_ip=f"203.0.113.{i}",
                                     time=now + dt.timedelta(seconds=i), cooldown_key="udp:dns"))
        self.cap.wait_events(5)
        decisions = [d for _, d in self.cap.events]
        self.assertEqual(decisions, ["sent"] + ["cooldown"] * 4)
        self.assertEqual(len(self.cap.mails), 1)

    def test_different_keys_do_not_share_cooldown(self):
        now = dt.datetime(2026, 11, 1, 12, 0, 0)
        self.notifier.emit(Event(service="dns", message="a", source_ip="203.0.113.1", time=now, cooldown_key="udp:dns"))
        self.notifier.emit(Event(service="snmp", message="b", source_ip="203.0.113.1", time=now, cooldown_key="udp:snmp"))
        self.notifier.emit(Event(service="http", message="c", source_ip="203.0.113.1", time=now))   # TCP 仍以 IP 為鍵
        self.cap.wait_events(3)
        self.assertEqual([d for _, d in self.cap.events], ["sent", "sent", "sent"])

    def test_udp_service_sets_key(self):
        svc = DnsService(svc_cfg(), self.notifier)
        ev = svc.event(("203.0.113.9", 5353), "x")
        self.assertEqual(ev.cooldown_key, "udp:dns")
        self.assertEqual(ev.cooldown_id, "udp:dns")
        self.assertIsNone(Event(service="http", message="y", source_ip="1.2.3.4").cooldown_key)


if __name__ == "__main__":
    unittest.main()

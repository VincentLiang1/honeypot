"""SmtpMailSender 的 mock 測試：確認 starttls / login / send_message 的呼叫順序與信件欄位。"""

import unittest
from unittest import mock

from honeypot.notify import Event, Notifier, SmtpMailSender


EMAIL_CFG = {
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "use_tls": True,
    "username": "bot@example.com",
    "password": "secret",
    "from_email": "honeypot@example.com",
    "to_emails": ["a@example.com", "b@example.com"],
    "timeout_seconds": 7,
}


class SmtpMailSenderTests(unittest.TestCase):
    @mock.patch("honeypot.notify.smtplib.SMTP")
    def test_sends_with_tls_and_login(self, smtp_cls):
        smtp = smtp_cls.return_value.__enter__.return_value
        SmtpMailSender(EMAIL_CFG)("主旨", "內文\n")

        smtp_cls.assert_called_once_with("smtp.example.com", 587, timeout=7)
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("bot@example.com", "secret")
        smtp.send_message.assert_called_once()
        msg = smtp.send_message.call_args.args[0]
        self.assertEqual(msg["Subject"], "主旨")
        self.assertEqual(msg["From"], "honeypot@example.com")
        self.assertEqual(msg["To"], "a@example.com, b@example.com")
        self.assertEqual(msg.get_content(), "內文\n")

    @mock.patch("honeypot.notify.smtplib.SMTP")
    def test_no_tls_no_login_when_not_configured(self, smtp_cls):
        smtp = smtp_cls.return_value.__enter__.return_value
        cfg = dict(EMAIL_CFG, use_tls=False, username="", password="")
        SmtpMailSender(cfg)("s", "b")
        smtp.starttls.assert_not_called()
        smtp.login.assert_not_called()
        smtp.send_message.assert_called_once()

    @mock.patch("honeypot.notify.smtplib.SMTP")
    def test_notifier_uses_real_sender_by_default(self, smtp_cls):
        """沒注入 mail_sender 時，Notifier 真的會走 smtplib。"""
        smtp = smtp_cls.return_value.__enter__.return_value
        cfg = {"whitelist": [], "notify": {"cooldown_minutes": 0, "email": dict(EMAIL_CFG, enabled=True)}}
        notifier = Notifier(cfg)
        notifier.start()
        notifier.emit(Event(service="http", message="HTTP GET /x", source_ip="1.2.3.4", source_port=9,
                            details={"path": "/x"}))
        notifier.close()
        msg = smtp.send_message.call_args.args[0]
        self.assertIn("1.2.3.4", msg["Subject"])
        self.assertIn("HTTP GET /x", msg["Subject"])
        self.assertIn("path: /x", msg.get_content())


if __name__ == "__main__":
    unittest.main()

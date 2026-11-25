import json
import os
import tempfile
import unittest

from honeypot.config import ConfigError, is_whitelisted, load_config, parse_hhmm


class ConfigTests(unittest.TestCase):
    def test_missing_file_uses_defaults(self):
        cfg = load_config(os.path.join(tempfile.gettempdir(), "no-such-honeypot-config.json"))
        self.assertEqual(cfg["services"]["http"]["port"], 80)
        self.assertFalse(cfg["notify"]["email"]["enabled"])

    def test_partial_file_is_merged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"services": {"http": {"port": 8080}}}, fh)
            cfg = load_config(path)
        self.assertEqual(cfg["services"]["http"]["port"], 8080)
        self.assertEqual(cfg["services"]["http"]["interface"], "0.0.0.0")
        self.assertEqual(cfg["services"]["mssql"]["port"], 1433)

    def test_bad_port_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"services": {"http": {"port": "80"}}}, fh)
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_bad_whitelist_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"whitelist": ["not-an-ip"]}, fh)
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_email_enabled_requires_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"notify": {"email": {"enabled": True, "to_emails": ["a@b"]}}}, fh)
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_env_password_override(self):
        os.environ["HONEYPOT_SMTP_PASSWORD"] = "from-env"
        try:
            cfg = load_config(None)
        finally:
            del os.environ["HONEYPOT_SMTP_PASSWORD"]
        self.assertEqual(cfg["notify"]["email"]["password"], "from-env")

    def test_parse_hhmm(self):
        self.assertEqual(parse_hhmm("09:05"), (9, 5))
        with self.assertRaises(ConfigError):
            parse_hhmm("25:00")
        with self.assertRaises(ConfigError):
            parse_hhmm("nine")

    def test_whitelist_matching(self):
        wl = ["127.0.0.1", "10.5.0.0/16", "::1"]
        self.assertTrue(is_whitelisted("127.0.0.1", wl))
        self.assertTrue(is_whitelisted("10.5.200.7", wl))
        self.assertTrue(is_whitelisted("::1", wl))
        self.assertFalse(is_whitelisted("10.6.0.1", wl))
        self.assertFalse(is_whitelisted("garbage", wl))


if __name__ == "__main__":
    unittest.main()

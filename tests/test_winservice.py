"""Windows 服務介接的測試：沒有管理員權限也能跑的部分。

真正的 sc create / start / stop 要在系統管理員的命令提示字元手動驗證。
"""

import ctypes
import sys
import threading
import unittest

from tests.helpers import quiet_logging

if sys.platform != "win32":
    raise unittest.SkipTest("只在 Windows 上測")

from honeypot import winservice as ws  # noqa: E402


class FakeApi:
    """模擬 SCM：start_dispatcher 直接在另一條執行緒呼叫 service main，像 SCM 那樣。"""

    def __init__(self):
        self.statuses: list[tuple[int, int, int, int]] = []
        self.handler = None

    def start_dispatcher(self, table):
        entry = table[0]
        name = entry.lpServiceName
        proc = entry.lpServiceProc
        t = threading.Thread(target=proc, args=(1, None), name="fake-scm-main")
        t.start()
        t.join(timeout=10)
        assert not t.is_alive(), "service main 沒有結束"
        assert name == ws.SERVICE_NAME

    def register_handler(self, name, handler):
        self.handler = handler
        return 0x1234

    def set_status(self, handle, status):
        assert handle == 0x1234
        self.statuses.append((
            status.dwCurrentState, status.dwControlsAccepted,
            status.dwWin32ExitCode, status.dwServiceSpecificExitCode,
        ))
        return True

    def send(self, control):
        return self.handler(control, 0, None, None)


class StructTests(unittest.TestCase):
    def test_service_status_layout(self):
        self.assertEqual(ctypes.sizeof(ws.SERVICE_STATUS), 28)
        self.assertEqual(ctypes.sizeof(ws.SERVICE_TABLE_ENTRYW), 2 * ctypes.sizeof(ctypes.c_void_p))

    def test_dispatcher_outside_scm_fails_with_1063(self):
        """從一般主控台呼叫真正的 StartServiceCtrlDispatcherW 一定失敗，錯誤碼 1063。"""
        runner = ws.ServiceRunner(ws.SERVICE_NAME, lambda r: 0)
        with self.assertRaises(OSError) as cm:
            runner.run()
        self.assertEqual(cm.exception.errno, ws.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        quiet_logging()
        self.api = FakeApi()

    def test_normal_stop_cycle(self):
        seen = {}

        def body(runner):
            runner.set_running()
            seen["running_reported"] = self.api.statuses[-1][0]
            # 模擬 SCM 在服務跑的時候送 STOP
            rc = self.api.send(ws.SERVICE_CONTROL_STOP)
            seen["handler_rc"] = rc
            self.assertTrue(runner.stop.wait(1))
            seen["shutting_down"] = runner.shutting_down
            return 0

        runner = ws.ServiceRunner(ws.SERVICE_NAME, body, api=self.api)
        self.assertEqual(runner.run(), 0)
        states = [s[0] for s in self.api.statuses]
        self.assertEqual(states, [
            ws.SERVICE_START_PENDING, ws.SERVICE_RUNNING, ws.SERVICE_STOP_PENDING, ws.SERVICE_STOPPED,
        ])
        self.assertEqual(seen["handler_rc"], 0)
        self.assertFalse(seen["shutting_down"])
        # RUNNING 時才接受 STOP / SHUTDOWN
        self.assertEqual(self.api.statuses[1][1], ws.SERVICE_ACCEPT_STOP | ws.SERVICE_ACCEPT_SHUTDOWN)
        self.assertEqual(self.api.statuses[0][1], 0)
        self.assertEqual(self.api.statuses[-1][2:], (0, 0))

    def test_shutdown_sets_flag(self):
        def body(runner):
            runner.set_running()
            self.api.send(ws.SERVICE_CONTROL_SHUTDOWN)
            return 0

        runner = ws.ServiceRunner(ws.SERVICE_NAME, body, api=self.api)
        runner.run()
        self.assertTrue(runner.shutting_down)

    def test_body_failure_reports_specific_exit_code(self):
        runner = ws.ServiceRunner(ws.SERVICE_NAME, lambda r: 2, api=self.api)
        self.assertEqual(runner.run(), 2)
        state, _, win32, specific = self.api.statuses[-1]
        self.assertEqual(state, ws.SERVICE_STOPPED)
        self.assertEqual(win32, ws.ERROR_SERVICE_SPECIFIC_ERROR)
        self.assertEqual(specific, 2)

    def test_body_exception_still_reports_stopped(self):
        def body(runner):
            raise RuntimeError("boom")

        runner = ws.ServiceRunner(ws.SERVICE_NAME, body, api=self.api)
        self.assertEqual(runner.run(), 1)
        self.assertEqual(self.api.statuses[-1][0], ws.SERVICE_STOPPED)
        self.assertEqual(self.api.statuses[-1][3], 1)

    def test_unknown_control_not_implemented(self):
        def body(runner):
            runner.set_running()
            self.assertEqual(self.api.send(99), ws.ERROR_CALL_NOT_IMPLEMENTED)
            self.assertEqual(self.api.send(ws.SERVICE_CONTROL_INTERROGATE), 0)
            self.assertFalse(runner.stop.is_set())
            return 0

        ws.ServiceRunner(ws.SERVICE_NAME, body, api=self.api).run()


class CommandLineTests(unittest.TestCase):
    def test_bin_path_quotes_paths(self):
        line = ws.service_command_line(r"C:\My Dir\main.py", None)
        self.assertEqual(line, f'"{sys.executable}" "C:\\My Dir\\main.py" --service')

    def test_bin_path_with_config(self):
        line = ws.service_command_line("main.py", "cfg.json")
        self.assertTrue(line.endswith('--service -c "' + __import__("os").path.abspath("cfg.json") + '"'))


if __name__ == "__main__":
    unittest.main()

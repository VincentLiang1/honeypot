#!/usr/bin/env python3
"""SimpleHoneypot 入口。

    python main.py                      # 前景執行，用 config.json，沒有就全用預設值
    python main.py -c other.json
    python main.py --ports http=8080,https=8443,mssql=11433 --no-email   # 本機測試
    python main.py --install-service    # 以系統管理員執行：登錄成 Windows 服務（開機自動啟動）
    python main.py --uninstall-service
    python main.py --service            # 給 SCM 用的，不要手動跑

前景模式 Ctrl+C 結束、服務模式 sc stop：都是先停服務、寄關機通知、等佇列送完再離開。
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from typing import Callable

from honeypot import __version__
from honeypot.config import DEFAULTS, ConfigError, load_config
from honeypot.heartbeat import Heartbeat
from honeypot.logfile import DailyFileHandler
from honeypot.notify import Notifier
from honeypot.services import Service, create_service

log = logging.getLogger("honeypot")


def setup_logging(cfg: dict) -> None:
    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger("honeypot")
    root.setLevel(logging.INFO)
    for old in root.handlers[:]:   # 服務模式會呼叫兩次，舊的檔案要關掉
        root.removeHandler(old)
        old.close()

    if sys.stdout is not None:
        # 當服務跑時沒有主控台，sys.stdout 是 None；掛上去的話每次寫 log 都會靜默出錯
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(fmt)
        root.addHandler(console)

    rotate = cfg["log_rotate"]   # 只取新欄位：舊版 config.json 可能還留著 max_mb / backups
    file_handler = DailyFileHandler(cfg["log_file"], rotate["keep_days"], rotate["daily_max_mb"])
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"SimpleHoneypot {__version__}")
    parser.add_argument("-c", "--config", default="config.json", help="設定檔路徑（預設 config.json）")
    parser.add_argument("--ports", default="", help="覆寫 port，例如 http=8080,https=8443,mssql=11433")
    parser.add_argument("--no-email", action="store_true", help="這次不寄信（測試用）")
    parser.add_argument("--no-heartbeat", action="store_true", help="這次不跑 heartbeat（測試用）")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--install-service", action="store_true", help="登錄成 Windows 服務（需系統管理員）")
    mode.add_argument("--uninstall-service", action="store_true", help="移除 Windows 服務（需系統管理員）")
    mode.add_argument("--service", action="store_true", help="由 Windows 服務控制管理員啟動時使用")
    return parser.parse_args(argv)


def apply_port_overrides(cfg: dict, spec: str) -> None:
    for item in filter(None, (s.strip() for s in spec.split(","))):
        try:
            name, port = item.split("=")
            cfg["services"][name]["port"] = int(port)
        except (ValueError, KeyError) as exc:
            raise ConfigError(f"--ports 格式錯誤：{item!r}（{exc}）") from exc


def build_services(cfg: dict, notifier: Notifier) -> list[Service]:
    """依 config 的 services 順序建立有啟用的服務；名稱在 config 驗證時就擋過了。"""
    return [
        create_service(name, svc_cfg, notifier, cfg["http_response"])
        for name, svc_cfg in cfg["services"].items()
        if svc_cfg.get("enabled")
    ]


def main(argv: list[str] | None = None) -> int:
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")   # 路徑或 UA 裡的怪字元不能把程式弄死

    # 相對路徑（config.json、log、state）一律以 main.py 所在資料夾為準。
    # 從服務或排程器啟動時 CWD 是 System32，不這樣做會靜默讀不到設定、把 log 寫到奇怪的地方。
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    args = parse_args(argv)
    if args.install_service or args.uninstall_service or args.service:
        if sys.platform != "win32":
            print("Windows 服務功能只在 Windows 上可用", file=sys.stderr)
            return 2
        from honeypot import winservice
        if args.install_service:
            return winservice.install(__file__, args.config if args.config != "config.json" else None)
        if args.uninstall_service:
            return winservice.uninstall()
        return run_as_service(args)

    return run_console(args)


def _load(args: argparse.Namespace) -> dict:
    cfg = load_config(args.config)
    if args.ports:
        apply_port_overrides(cfg, args.ports)
    if args.no_email:
        cfg["notify"]["email"]["enabled"] = False
    return cfg


def run_console(args: argparse.Namespace) -> int:
    try:
        cfg = _load(args)
    except ConfigError as exc:
        print(f"設定錯誤：{exc}", file=sys.stderr)
        return 2
    setup_logging(cfg)

    stop = threading.Event()
    if sys.platform == "win32":
        # 排程器或 taskkill 送的是 Ctrl+Break；轉成 KeyboardInterrupt 走同一條正常關機路徑
        def _on_break(*_: object) -> None:
            raise KeyboardInterrupt
        signal.signal(signal.SIGBREAK, _on_break)

    notifier = Notifier(cfg)
    notifier.start()
    try:
        return _run(args, cfg, notifier, stop)
    finally:
        # worker 不是 daemon（關機信要送完），所以任何例外都得走到這裡把它收掉，不然程式永遠不會結束
        notifier.close(timeout=60)


def run_as_service(args: argparse.Namespace) -> int:
    from honeypot import winservice

    def body(runner: winservice.ServiceRunner) -> int:
        # 服務模式沒有 stderr 可看：先用預設 log 路徑接住讀設定前的任何錯誤，讀到設定後再換成正式的
        setup_logging(DEFAULTS)
        try:
            cfg = _load(args)
        except ConfigError as exc:
            log.error("設定錯誤：%s", exc)
            return 2
        setup_logging(cfg)
        log.info("以 Windows 服務模式啟動")
        notifier = Notifier(cfg)
        notifier.start()
        try:
            return _run(args, cfg, notifier, runner.stop, on_running=runner.set_running)
        finally:
            timeout = winservice.SHUTDOWN_CLOSE_TIMEOUT if runner.shutting_down else winservice.NORMAL_CLOSE_TIMEOUT
            notifier.close(timeout=timeout)

    runner = winservice.ServiceRunner(winservice.SERVICE_NAME, body)
    try:
        return runner.run()
    except OSError as exc:
        if exc.errno == winservice.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            print("--service 只能由 Windows 服務控制管理員啟動；要登錄服務請用 --install-service", file=sys.stderr)
            return 2
        raise


def _run(
    args: argparse.Namespace,
    cfg: dict,
    notifier: Notifier,
    stop: threading.Event,
    on_running: Callable[[], None] | None = None,
) -> int:
    """啟動服務、等 stop 旗標（或 Ctrl+C）、收尾。前景與服務模式共用。"""
    log.info("SimpleHoneypot %s 啟動，工作目錄 %s", __version__, os.getcwd())
    if os.path.exists(args.config):
        log.info("設定檔 %s", os.path.abspath(args.config))
    else:
        log.warning("設定檔 %s 不存在，全用預設值：寄信未啟用、白名單只有 localhost", args.config)

    services = build_services(cfg, notifier)
    running: list[Service] = []
    failed: list[str] = []
    for svc in services:
        try:
            svc.start()
            running.append(svc)
        except OSError as exc:
            failed.append(f"{svc.name}:{svc.port}")
            log.error("[%s] 無法監聽 %s:%d：%s", svc.name, svc.interface, svc.port, exc)
            notifier.system(f"服務 {svc.name} 無法監聽 port {svc.port}", 錯誤=str(exc))

    if not running:
        notifier.system("蜜罐啟動失敗：沒有任何服務成功監聽", 失敗=", ".join(failed) or "無服務啟用")
        return 1

    listening = ", ".join(f"{s.name}:{s.port}" for s in running)
    notifier.system("蜜罐已啟動", 監聽=listening, 失敗=", ".join(failed) or "無")

    heartbeat: Heartbeat | None = None
    hb_cfg = cfg["heartbeat"]
    if hb_cfg.get("enabled") and not args.no_heartbeat:
        heartbeat = Heartbeat(notifier, hb_cfg["time"], cfg["state_file"])
        heartbeat.start()
        log.info("heartbeat 已排程，每日 %s", hb_cfg["time"])

    if on_running is not None:
        on_running()

    try:
        # Windows 沒有 signal.pause()，而且不帶 timeout 的 wait 吃不到 Ctrl+C
        while not stop.wait(1.0):
            pass
        log.info("收到停止指令，開始關閉")
    except KeyboardInterrupt:
        log.info("收到 Ctrl+C，開始關閉")

    if heartbeat:
        heartbeat.stop()
    for svc in running:
        svc.stop()
    notifier.system("蜜罐已關閉", 原本監聽=listening)
    log.info("等待通知送完後結束")
    return 0


if __name__ == "__main__":
    sys.exit(main())

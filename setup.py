#!/usr/bin/env python3
"""互動式安裝精靈：問幾個問題 → 寫 config.json → 試寄信 → 停掉舊服務 → 檢查 port → 登錄服務 → 啟動。

由 Setup.bat 以系統管理員身分呼叫；也可以手動跑：

    python\\python.exe setup.py               # 完整安裝（需系統管理員）
    python\\python.exe setup.py --config-only # 只做問答寫 config.json，不裝服務（不需管理員）
    python\\python.exe setup.py --uninstall   # 停止並移除服務、刪防火牆規則
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from honeypot.config import DEFAULTS, ConfigError, load_config, parse_hhmm  # noqa: E402
from honeypot.logfile import daily_path  # noqa: E402
from honeypot.notify import SmtpMailSender, hostname  # noqa: E402
from honeypot.services import CATALOG  # noqa: E402
from honeypot.services.base import open_socket  # noqa: E402

CONFIG_FILE = "config.json"
FIREWALL_RULE = "SimpleHoneypot"
BUSY_HINT = "  常見原因：IIS / http.sys 佔 80、443；SQL Server 佔 1433；WinRM 佔 5985；Hyper-V 保留區段。"


# ---- 問答小工具 ----

def ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{hint}：").strip()
    except EOFError:
        answer = ""
    return answer or default


def ask_yes(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        answer = ask(f"{prompt} ({hint})").lower()
        if not answer:
            return default
        if answer in ("y", "yes", "是"):
            return True
        if answer in ("n", "no", "否"):
            return False
        print("  請回答 y 或 n")


def ask_int(prompt: str, default: int, lo: int = 1, hi: int = 65535) -> int:
    while True:
        answer = ask(prompt, str(default))
        try:
            value = int(answer)
            if lo <= value <= hi:
                return value
        except ValueError:
            pass
        print(f"  請輸入 {lo} 到 {hi} 的整數")


def ask_list(prompt: str, default: list[str]) -> list[str]:
    answer = ask(prompt, ", ".join(default))
    return [item.strip() for item in answer.split(",") if item.strip()]


def section(title: str) -> None:
    print()
    print(f"=== {title} ===")


# ---- 步驟 ----

def print_port_table(cfg: dict) -> None:
    for name, svc in cfg["services"].items():
        entry = CATALOG[name]
        print(f"  {svc['port']:>6} {entry.cls.proto:<4} {entry.label}")


def build_config() -> dict:
    """問答後回傳完整設定（以 DEFAULTS 為底）。"""
    cfg = json.loads(json.dumps(DEFAULTS))   # deep copy

    section("監聽 port")
    print("蜜罐預設會開下列所有 port（有人連就記錄、寄信）：")
    print_port_table(cfg)
    print("被佔用的 port（例如 IIS 的 80、本機 SQL Server 的 1433）安裝服務時會自動偵測並關掉。")
    while True:
        answer = ask("不想開的 port（逗號分隔，留空 = 全開）")
        if not answer:
            break
        try:
            skip = {int(x) for x in answer.replace(" ", "").split(",") if x}
        except ValueError:
            print("  請輸入數字，用逗號分隔，例如 22, 3389")
            continue
        known = {svc["port"] for svc in cfg["services"].values()}
        unknown = sorted(skip - known)
        if unknown:
            print(f"  清單裡沒有這些 port：{', '.join(map(str, unknown))}，請重新輸入")
            continue
        for svc in cfg["services"].values():
            if svc["port"] in skip:
                svc["enabled"] = False
        print(f"  已關掉：{', '.join(str(p) for p in sorted(skip))}")
        break

    section("白名單")
    print("名單內的來源（IP 或 CIDR，逗號分隔）照樣寫 log，但不寄信。建議放內部掃描器、監控主機。")
    cfg["whitelist"] = ask_list("白名單", ["127.0.0.1", "::1"])

    section("Email 通知")
    email = cfg["notify"]["email"]
    want_mail = True                   # 第一次預設 Y；填不出 SMTP 回來再問時預設改成 N
    while True:
        email["enabled"] = ask_yes("要寄 Email 通知嗎", want_mail)
        if not email["enabled"]:
            break
        print("DMZ 通常連不到外網，請填內部 mail relay 的 IP（DMZ 不一定有 DNS）。")
        email["smtp_server"] = ask("SMTP 伺服器 IP 或主機名（留空 = 回上一題）")
        if not email["smtp_server"]:
            print("  沒有 SMTP 伺服器就寄不了信，回到上一題。")
            want_mail = False
            continue
        email["smtp_port"] = ask_int("SMTP port（內部 relay 多半是 25，需帳密的多半是 587）", 25)
        email["use_tls"] = ask_yes("要用 STARTTLS 加密嗎", email["smtp_port"] == 587)
        email["username"] = ask("SMTP 帳號（內部 relay 不需要就留空）")
        if email["username"]:
            print("密碼也可以不寫進檔案：之後把它設成「系統」環境變數 HONEYPOT_SMTP_PASSWORD。")
            try:
                email["password"] = getpass.getpass("SMTP 密碼（留空表示用環境變數）：")
            except EOFError:
                email["password"] = ""
        email["from_email"] = ask("寄件者", email["username"] or f"honeypot@{hostname()}")
        email["to_emails"] = ask_list("收件者（逗號分隔；留空 = 回到「要寄 Email 通知嗎」）", [])
        if not email["to_emails"]:
            print("  沒有收件者就寄不了信，回到「要寄 Email 通知嗎」。")
            want_mail = False
            continue
        cfg["notify"]["cooldown_minutes"] = ask_int("同一來源 IP 幾分鐘內只寄一封（0 = 每次都寄）", 10, 0, 1440)
        break

    hb = cfg["heartbeat"]
    if not email["enabled"]:
        hb["enabled"] = False          # 不寄信就沒有 heartbeat 可寄，不必問
        return cfg

    section("每日 heartbeat")
    hb["enabled"] = ask_yes("每天寄一封「蜜罐正常運行」嗎", True)
    if hb["enabled"]:
        while True:
            answer = ask("寄送時間 HH:MM", hb["time"])
            try:
                parse_hhmm(answer)
                hb["time"] = answer
                break
            except ConfigError as exc:
                print(f"  {exc}")
    return cfg


def _dump_config(data: dict) -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def write_config(cfg: dict) -> dict:
    _dump_config(cfg)
    print(f"已寫入 {os.path.abspath(CONFIG_FILE)}")
    return load_config(CONFIG_FILE)   # 走正式的驗證


def disable_in_config(names: list[str]) -> None:
    """只把這幾個服務的 enabled 改成 false 寫回 config.json，檔案其他內容原樣保留。

    不能把 load_config() 合併後的 cfg 整份倒回去：那裡面有 DEFAULTS 補出來的欄位，
    還有從環境變數 HONEYPOT_SMTP_PASSWORD 注入的密碼，使用者刻意不寫進檔案的東西就會落地。
    """
    with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
        raw: dict = json.load(fh)
    services = raw.setdefault("services", {})
    for name in names:
        services.setdefault(name, {})["enabled"] = False
    _dump_config(raw)


def test_mail(cfg: dict) -> bool:
    email = cfg["notify"]["email"]
    if not email.get("enabled"):
        return True
    if not ask_yes("要先寄一封測試信確認 SMTP 通嗎", True):
        return True
    print(f"寄到 {', '.join(email['to_emails'])} 經由 {email['smtp_server']}:{email['smtp_port']} ...")
    try:
        SmtpMailSender(email)(f"[蜜罐] [{hostname()}] 安裝測試信", "SimpleHoneypot 安裝精靈寄出的測試信，收到表示 SMTP 設定正確。\n")
    except Exception as exc:  # noqa: BLE001
        print(f"寄信失敗：{exc}")
        return ask_yes("寄信失敗，仍要繼續安裝嗎", False)
    print("測試信已送出，請確認信箱。")
    return True


def check_ports(cfg: dict) -> bool:
    """逐個試綁；綁不到的在 config.json 關掉並告知，不再一個一個問。

    要在舊服務停掉之後才跑：還在跑的蜜罐自己就占著所有 port，會把每一個都判成「被佔用」。
    """
    section("檢查 port")
    busy: list[str] = []
    for name, svc in cfg["services"].items():
        if not svc.get("enabled"):
            continue
        cls = CATALOG[name].cls
        try:
            open_socket(cls.sock_type, svc["interface"], svc["port"]).close()
        except OSError as exc:
            print(f"  {svc['port']:>6} {cls.proto:<4} {name}：綁不到（{exc.strerror or exc}），已關閉")
            svc["enabled"] = False
            busy.append(name)
    enabled = [str(svc["port"]) for svc in cfg["services"].values() if svc.get("enabled")]
    print(f"  會開的 port：{', '.join(enabled) if enabled else '（沒有）'}")
    if not enabled:
        # 全部關掉寫回去只會讓服務下次開機以「沒有任何服務」失敗、被 SCM 一直重啟；設定檔不動
        print(f"沒有任何 port 可用，不安裝服務；{CONFIG_FILE} 不動。")
        print(BUSY_HINT)
        return False
    if busy:
        disable_in_config(busy)
        print(f"  綁不到的 {', '.join(busy)} 已在 {CONFIG_FILE} 設成 enabled=false。")
        print(BUSY_HINT)
        print("  處理掉佔用程式後把 enabled 改回 true，再按一次 Setup.bat 即可。")
    return True


def _sc_query(name: str) -> subprocess.CompletedProcess:
    """sc query 的結果；returncode 非 0 就是服務不存在。安靜地查，不像 winservice._sc 會印出來。"""
    return subprocess.run(["sc.exe", "query", name], capture_output=True, text=True, errors="replace")


def service_exists(name: str) -> bool:
    return _sc_query(name).returncode == 0


def firewall_rule(python_exe: str) -> None:
    if not ask_yes("要加 Windows 防火牆放行規則嗎（服務不會自己跳出詢問視窗）", True):
        return
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FIREWALL_RULE}"],
                   capture_output=True)
    proc = subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule", f"name={FIREWALL_RULE}",
         "dir=in", "action=allow", f"program={python_exe}", "enable=yes"],
        capture_output=True, text=True, errors="replace",
    )
    print("防火牆規則已加入" if proc.returncode == 0 else f"加防火牆規則失敗：{proc.stdout}{proc.stderr}")


def wait_running(name: str, seconds: int = 15) -> bool:
    for _ in range(seconds):
        out = _sc_query(name).stdout
        if "RUNNING" in out:
            return True
        if "STOPPED" in out:
            return False
        time.sleep(1)
    return False


def wait_stopped(name: str, seconds: int = 90) -> bool:
    """sc stop 之後輪詢到 STOPPED。服務要寄完關機信（notifier.close 最多 60 秒）才會回報 STOPPED，所以給 90 秒。"""
    for _ in range(seconds):
        proc = _sc_query(name)
        if proc.returncode != 0 or "STOPPED" in proc.stdout:
            return True
        time.sleep(1)
    return False


def tail_log(cfg: dict, lines: int = 8) -> None:
    path = daily_path(cfg["log_file"], datetime.date.today())
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh.readlines()[-lines:]:
            print("  " + line.rstrip())


def install(args: argparse.Namespace) -> int:
    from honeypot import winservice

    main_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")
    print(f"SimpleHoneypot 安裝精靈　主機 {hostname()}　資料夾 {os.getcwd()}")
    print(f"Python：{sys.executable}")

    if not args.config_only and not winservice.is_admin():
        print("需要系統管理員權限。請對 Setup.bat 按右鍵「以系統管理員身分執行」。")
        return 3

    cfg = None
    if os.path.exists(CONFIG_FILE):
        section("設定檔")
        if ask_yes(f"已經有 {CONFIG_FILE}，要保留現有設定嗎", True):
            try:
                cfg = load_config(CONFIG_FILE)
            except ConfigError as exc:
                print(f"現有設定檔有錯：{exc}，改用問答重新建立")
    if cfg is None:
        try:
            cfg = write_config(build_config())
        except ConfigError as exc:
            print(f"設定錯誤：{exc}")
            return 2

    if not test_mail(cfg):
        print(f"已停止。修正 {CONFIG_FILE} 的 SMTP 設定後再執行一次 Setup.bat（會問你要不要保留現有設定）。")
        return 1
    if args.config_only:
        print("只寫設定檔，不安裝服務（port 要到安裝服務時才檢查）。")
        return 0

    name = winservice.SERVICE_NAME
    existed = service_exists(name)
    if existed:
        section("既有服務")
        if not ask_yes(f"服務 {name} 已存在，要停掉並重新登錄嗎", True):
            return 1
        # 一定要先停：它自己占著的 port 會被下一步當成「被佔用」關掉。停掉要等它寄完關機信。
        subprocess.run(["sc.exe", "stop", name], capture_output=True)
        print("等待服務停止（要先寄完關機信，最多 90 秒）...")
        if not wait_stopped(name):
            print(f"服務 {name} 沒有在時間內停止，請手動 sc stop {name} 後再執行一次 Setup.bat。")
            return 1

    if not check_ports(cfg):
        if existed:
            print(f"服務 {name} 已停止但仍登錄著，處理好 port 後再按一次 Setup.bat。")
        return 1

    section("登錄 Windows 服務")
    if existed:
        winservice.uninstall(name)      # 已經停了，這裡重點是 delete
    rc = winservice.install(main_py, None, name)
    if rc != 0:
        print("登錄服務失敗，請看上面 sc.exe 的訊息。")
        return rc

    firewall_rule(sys.executable)

    section("啟動服務")
    subprocess.run(["sc.exe", "start", name], capture_output=True)
    if wait_running(name):
        print(f"服務 {name} 已啟動（開機會自動啟動）。最近的 log：")
        tail_log(cfg)
        print()
        print(f"停止：sc stop {name}　　狀態：sc query {name}　　移除：按兩下 Uninstall.bat")
        return 0
    print("服務沒有進入 RUNNING 狀態，請看 log：")
    tail_log(cfg, 20)
    return 1


def uninstall() -> int:
    from honeypot import winservice

    if not winservice.is_admin():
        print("需要系統管理員權限。請對 Uninstall.bat 按右鍵「以系統管理員身分執行」。")
        return 3
    name = winservice.SERVICE_NAME
    if service_exists(name):
        if not ask_yes(f"確定要停止並移除服務 {name} 嗎", False):
            return 1
        winservice.uninstall(name)
    else:
        print(f"服務 {name} 不存在，不必移除。")
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FIREWALL_RULE}"],
                   capture_output=True)
    print("完成。config.json 與 log 都留著沒動。")
    return 0


def main() -> int:
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(description="SimpleHoneypot 安裝精靈")
    parser.add_argument("--config-only", action="store_true", help="只問答寫 config.json，不裝服務")
    parser.add_argument("--uninstall", action="store_true", help="停止並移除服務")
    args = parser.parse_args()
    if args.uninstall:
        return uninstall()
    return install(args)


if __name__ == "__main__":
    sys.exit(main())

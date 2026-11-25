#!/usr/bin/env python3
"""做離線部署包：embeddable Python + 程式碼，複製資料夾到 DMZ 機器就能跑。

    python package.py                         # 從 python.org 下載 embeddable zip（開發機要能上網）
    python package.py --zip python-3.13.13-embed-amd64.zip   # 用已經下載好的 zip

產出 dist/SimpleHoneypot/ 與 dist/SimpleHoneypot-<版本>.zip：

    SimpleHoneypot/
      python/            embeddable Python（含 ssl、smtplib，smtp 的 STARTTLS 要用）
      main.py
      honeypot/
      config.example.json
      README.md

embeddable Python 有 python3xx._pth，sys.path 完全由它決定、不會自動加 script 所在資料夾，
所以要補一行 `..` 讓 `import honeypot` 找得到。打包完會真的用那顆 python 跑一次驗證。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile

import re

DEFAULT_PY_VERSION = "3.13.13"
PACKAGE_NAME = "SimpleHoneypot"
COPY_FILES = ["main.py", "setup.py", "Setup.bat", "Uninstall.bat", "config.example.json", "README.md"]
COPY_DIRS = ["honeypot"]


# 版本號寫在這兩個檔；每次打包 patch +1（2026-11-01 指定），啟動 log 與 zip 檔名都看得出是哪一版
VERSION_FILES = {
    "honeypot/__init__.py": re.compile(r'(__version__ = ")(\d+)\.(\d+)\.(\d+)(")'),
    "pyproject.toml": re.compile(r'(^version = ")(\d+)\.(\d+)\.(\d+)(")', re.MULTILINE),
}


def bump_version(root: str, bump: bool) -> str:
    """回傳這次要用的版本字串；bump 為 True 時先把兩個檔的 patch 版號 +1。"""
    new_version = ""
    for rel, pattern in VERSION_FILES.items():
        path = os.path.join(root, rel)
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        match = pattern.search(text)
        if not match:
            raise SystemExit(f"{rel} 裡找不到版本號")
        major, minor, patch = (int(match.group(i)) for i in (2, 3, 4))
        if bump:
            patch += 1
        version = f"{major}.{minor}.{patch}"
        if new_version and version != new_version:
            raise SystemExit(f"版本號不一致：{rel} 是 {version}，前一個檔是 {new_version}")
        new_version = version
        if bump:
            text = text[:match.start()] + f"{match.group(1)}{version}{match.group(5)}" + text[match.end():]
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
    return new_version


def download(version: str, into: str) -> str:
    name = f"python-{version}-embed-amd64.zip"
    url = f"https://www.python.org/ftp/python/{version}/{name}"
    os.makedirs(into, exist_ok=True)
    target = os.path.join(into, name)
    if os.path.exists(target):
        print(f"已有 {target}，不重新下載")
        return target
    print(f"下載 {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "SimpleHoneypot-packager"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(target, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    return target


def extract_python(zip_path: str, py_dir: str) -> str:
    if os.path.exists(py_dir):
        shutil.rmtree(py_dir)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(py_dir)
    pth_files = [f for f in os.listdir(py_dir) if f.endswith("._pth")]
    if len(pth_files) != 1:
        raise SystemExit(f"{py_dir} 裡找不到唯一的 ._pth 檔：{pth_files}")
    pth = os.path.join(py_dir, pth_files[0])
    with open(pth, "r", encoding="utf-8") as fh:
        lines = [line.rstrip("\n") for line in fh]
    if ".." not in lines:
        lines.append("..")   # 讓 python\python.exe 找得到上一層的 honeypot 套件
    with open(pth, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    return pth


def copy_sources(root: str, out_dir: str) -> None:
    for name in COPY_FILES:
        shutil.copy2(os.path.join(root, name), os.path.join(out_dir, name))
    for name in COPY_DIRS:
        dst = os.path.join(out_dir, name)
        if os.path.exists(dst):
            shutil.rmtree(dst)
        shutil.copytree(
            os.path.join(root, name), dst,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )


def verify(out_dir: str) -> None:
    """用打包好的 python 跑：從別的 CWD 執行 main.py --help、確認 ssl / smtplib 有。"""
    py = os.path.join(out_dir, "python", "python.exe")
    main_py = os.path.join(out_dir, "main.py")
    other_cwd = os.path.dirname(out_dir)
    checks = [
        [py, "-c", "import ssl, smtplib, ctypes, logging.handlers; print('stdlib ok', ssl.OPENSSL_VERSION)"],
        [py, main_py, "--help"],
    ]
    for cmd in checks:
        proc = subprocess.run(cmd, cwd=other_cwd, capture_output=True, text=True, errors="replace")
        if proc.returncode != 0:
            raise SystemExit(f"驗證失敗：{' '.join(cmd)}\n{proc.stdout}{proc.stderr}")
        print("驗證 OK：" + proc.stdout.strip().splitlines()[0])


# 驗證或試跑時在 dist 資料夾裡產生的執行期檔案，不能跟著進 zip
RUNTIME_FILES = ("config.json", "state.json", "state.json.tmp")


def _is_runtime_file(name: str) -> bool:
    return name in RUNTIME_FILES or name.endswith(".log") or name.endswith(".log.1") or ".log." in name


def make_zip(out_dir: str, zip_path: str) -> None:
    if os.path.exists(zip_path):
        os.remove(zip_path)
    base = os.path.dirname(out_dir)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for folder, dirs, files in os.walk(out_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                if _is_runtime_file(name) or name.endswith(".pyc"):
                    continue
                full = os.path.join(folder, name)
                zf.write(full, os.path.relpath(full, base))


def main() -> int:
    parser = argparse.ArgumentParser(description="做 SimpleHoneypot 離線部署包")
    parser.add_argument("--zip", help="已下載的 embeddable Python zip；不給就從 python.org 下載")
    parser.add_argument("--python-version", default=DEFAULT_PY_VERSION, help=f"要下載的版本（預設 {DEFAULT_PY_VERSION}）")
    parser.add_argument("--dist", default="dist", help="輸出資料夾（預設 dist）")
    parser.add_argument("--no-bump", action="store_true", help="這次不要把版本號 +1（重做同一版時用）")
    args = parser.parse_args()

    root = os.path.dirname(os.path.abspath(__file__))
    version = bump_version(root, bump=not args.no_bump)
    print(f"版本 {version}" + ("" if args.no_bump else "（已 +1）"))
    dist = os.path.abspath(args.dist)
    out_dir = os.path.join(dist, PACKAGE_NAME)
    os.makedirs(out_dir, exist_ok=True)

    zip_path = args.zip or download(args.python_version, os.path.join(dist, "_download"))
    pth = extract_python(zip_path, os.path.join(out_dir, "python"))
    print(f"embeddable Python 解到 {os.path.dirname(pth)}，{os.path.basename(pth)} 已加 ..")
    copy_sources(root, out_dir)
    verify(out_dir)

    bundle = os.path.join(dist, f"{PACKAGE_NAME}-{version}.zip")
    make_zip(out_dir, bundle)
    size_mb = os.path.getsize(bundle) / 1024 / 1024
    print(f"部署包：{bundle}（{size_mb:.1f} MB）")
    print("部署：解開後按兩下 Setup.bat")
    return 0


if __name__ == "__main__":
    sys.exit(main())

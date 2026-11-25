# SimpleHoneypot

只用 Python 標準庫的低互動蜜罐。監聽 17 個駭客常掃的 port（HTTP、HTTPS、MSSQL、SSH、RDP、MySQL、
Redis、DNS、SNMP……完整清單見下表），有人連進來就寫 log、寄 Email。
沒有資料庫、沒有管理網頁、沒有第三方套件、不需要憑證。

設計目標：**當 Windows 服務跑在離線的 DMZ 機器上**。部署包自帶 Python，複製資料夾就能跑。

> ⚠️ 蜜罐本身就是給人攻擊的。請只部署在你有權管理的網路，並與正式系統隔離。

## 部署到 DMZ（正式環境）

開發機（要能上網）做部署包：

```bat
python package.py              :: 版本號自動 +1（0.1.1 → 0.1.2），同步改 honeypot/__init__.py 與 pyproject.toml
python package.py --no-bump    :: 重做同一版，不改版本號
```

產出 `dist\SimpleHoneypot-<版本>.zip`，裡面是 embeddable Python 加程式碼。啟動 log 的第一行會印版本，可對照 zip 檔名。帶到 DMZ 機器上：

1. 解壓到固定位置，例如 `C:\SimpleHoneypot`（不要放 Program Files，服務要在這裡寫 log）。
2. **按兩下 `Setup.bat`**。它會要求 UAC 提權，列出預設要開的全部 port 並只問「不想開哪些」，再問白名單、SMTP 伺服器與收件者、
   heartbeat 時間，寫出 `config.json`、寄一封測試信、停掉舊服務（如果有）、自動把綁不到的 port 關掉、登錄成服務、加防火牆規則、
   啟動服務、印出最近的 log。綁不到的 port 只會在 `config.json` 裡被改成 `enabled: false`，檔案其他內容（包括留空的密碼）不動。
3. 之後開機自動啟動。再按一次 `Setup.bat` 可以保留或重做設定並重新登錄（會先停掉正在跑的服務再檢查 port）；
   `Uninstall.bat` 停止並移除服務（設定與 log 留著）。
4. **從 0.1.x 升級**：解壓覆蓋舊資料夾後再按一次 `Setup.bat`、選「保留現有設定」。設定檔沒寫到的服務會用預設值補、預設是開的，
   所以新版多出來的 port 會自動上線，被占用的（例如 RDP 的 3389、WinRM 的 5985）會被關掉並印出來。

不想用精靈也可以手動做，效果相同：

```bat
copy config.example.json config.json
notepad config.json
python\python.exe main.py                    :: 前景試跑，Ctrl+C 結束
python\python.exe main.py --install-service  :: 系統管理員命令提示字元
sc start SimpleHoneypot
```

服務名稱 `SimpleHoneypot`，開機自動啟動、以 LocalSystem 執行、當掉自動重啟（5 秒、5 秒、60 秒）。
`sc stop SimpleHoneypot` 會走正常關機流程：停服務、寄「已關閉」通知、等信寄完。

離線機器注意：

- **SMTP 要走 DMZ 到得了的內部 relay**，`smtp_server` 填 IP，DMZ 不一定有 DNS。
- 服務以 LocalSystem 跑，`HONEYPOT_SMTP_PASSWORD` 要設成**系統**環境變數（不是使用者的），或直接寫在 `config.json`。
- 不需要 openssl、不需要憑證：443 只收 TLS ClientHello 就記錄，不握手（見下方「已知邊界」）。
- 設定檔寫錯時服務會啟動失敗，原因在當天的 `honeypot-YYYY-MM-DD.log`。

Windows 沒有「低 port 要管理員」這回事，綁不上 80 / 443 / 1433 通常是這四個原因：

- **port 已被佔用**：80 / 443 常是 http.sys 或 IIS，1433 是本機 SQL Server。`netstat -ano | findstr :80` 查 PID
- **Hyper-V / WSL 保留了 port 區段**：症狀是 WinError 10013。`netsh int ipv4 show excludedportrange protocol=tcp` 查
- **防火牆沒放行**：服務不會跳出詢問視窗。`netsh advfirewall firewall add rule name="SimpleHoneypot" dir=in action=allow program="C:\SimpleHoneypot\python\python.exe"`
- **設定檔的 interface 寫錯**

綁失敗的服務會寄一封通知並寫 ERROR，其他服務照跑；全部失敗才會以 exit code 1 結束（服務模式下 SCM 會依重啟規則再試）。

## 開發機執行

需要 Python 3.12 以上。

```bat
python main.py --ports http=8080,https=8443,mssql=11433 --no-email --no-heartbeat
python -m unittest discover -s tests -t .
```

所有相對路徑（config.json、log、state）都以 `main.py` 所在資料夾為準，從服務或排程器啟動也不必填「開始位置」。
前景模式 Ctrl+C 結束，和 `sc stop` 一樣先停服務、寄「已關閉」通知、等信寄完才退出。

## 監聽哪些 port

預設全開。`config.json` 的 `services.<名稱>.enabled` 設 false 就不開，`port` 可改。

| 名稱 | Port | 做什麼 | 記到什麼 |
|---|---|---|---|
| `http` | 80 | 回一張靜態頁 | method、path、Host、User-Agent |
| `https` | 443 | 只收 ClientHello，不握手 | SNI、TLS 版本、cipher 數 |
| `winrm` / `winrm_https` | 5985 / 5986 | 同 HTTP / HTTPS | 同上 |
| `mssql` | 1433 | 收第一包 | TDS 封包型別、hex |
| `ssh` | 22 | 送 OpenSSH banner、收第一包 | client 版本字串 |
| `vnc` | 5900 | 送 RFB banner、收第一包 | client 版本 |
| `rdp` | 3389 | 收第一包 | `mstshash=` 後面的帳號 |
| `mysql` | 3306 | 送 MySQL greeting、收第一包 | 帳號、資料庫名、client 名稱 |
| `postgres` | 5432 | 對 SSLRequest 回一個 N、收第一包 | `user=`、`database=` |
| `oracle` | 1521 | 收第一包 | CONNECT_DATA 文字 |
| `redis` / `mongodb` / `ldap` / `ldaps` | 6379 / 27017 / 389 / 636 | 收第一包 | 可列印文字片段、hex |
| `dns` | 53 UDP | 收每個封包 | 查詢名稱與型別 |
| `snmp` | 161 UDP | 收每個封包 | 版本、community string |

沒加的：445 / 139 / 135（Windows 自己占著，放不出來）、21 / 23 / 25 / 587 / 8080 / 8000 / 8443（決定不開）。

## 設定檔

| 區塊 | 欄位 | 說明 |
|---|---|---|
| 頂層 | `log_file`, `state_file` | log 路徑、heartbeat 狀態檔路徑 |
| `log_rotate` | `keep_days`, `daily_max_mb` | 保留天數（預設 1827 = 5 年，更舊的自動刪）與單日上限（預設 50 MB，超過當天不再寫入，寄信不受影響） |
| `services.<name>` | `enabled`, `port`, `interface` | 每個服務各自開關、port、綁定介面（只支援 IPv4）；名稱見上表 |
| `http_response` | `status`, `server_header`, `body` | HTTP 回的靜態頁 |
| `whitelist` | 陣列 | IP 或 CIDR。名單內的來源照樣寫 log，但不寄信 |
| `notify.cooldown_minutes` | 數字 | 同一個來源 IP 在這段時間內只寄一封，後續只寫 log。0 表示不合併 |
| `notify.email` | SMTP 設定 | `enabled` 為 false 時完全不寄信。密碼可改用環境變數 `HONEYPOT_SMTP_PASSWORD` |
| `heartbeat` | `enabled`, `time` | 每天 `HH:MM` 後寄一封「正常運行」；已寄日期存在 `state_file`，不回寫 config |

設定檔缺的欄位會用預設值補。port、白名單、時間格式、log 輪替寫錯會在啟動時直接報錯。

## 會寄哪些信

| 時機 | 主旨 |
|---|---|
| 蜜罐被連（非白名單、非冷卻中） | `[蜜罐] [主機名] http 來自 1.2.3.4：HTTP GET /probe` |
| 程式啟動 | `[蜜罐] [主機名] 蜜罐已啟動` |
| 某服務綁 port 失敗 | `[蜜罐] [主機名] 服務 http 無法監聽 port 80` |
| 所有服務都失敗 | 寄完通知後以 exit code 1 結束，不會空跑 |
| 每日 heartbeat | `[蜜罐] [主機名] Heartbeat：蜜罐正常運行` |
| 正常結束（Ctrl+C 或 sc stop） | `[蜜罐] [主機名] 蜜罐已關閉` |

一條連線只寄一封。TCP 的冷卻以來源 IP 為鍵；UDP（DNS / SNMP）的來源 IP 可以偽造，所以冷卻改以服務為鍵：
`dns` 整個 port 在 `cooldown_minutes` 內只寄一封、`snmp` 另算，每個封包照樣寫 log。
各服務帶的欄位見「監聽哪些 port」。對方送來的文字（DNS 名稱、SNMP community、SNI、path）裡的控制字元會被換成「.」再進 log 與信件。

## log 格式

一天一個檔：`log_file` 設 `honeypot.log` 時，實際檔名是 `honeypot-2026-11-01.log`。清理依檔名的日期判斷，舊版留下的 `honeypot.log`、`honeypot.log.1` 等不會被動到，要自己刪。

```
[2026-11-01 14:03:12] [WARNING] [http] [1.2.3.4:51234] HTTP GET /probe | method='GET' path='/probe' user_agent='curl/8.0' host='x' port=80 (已寄信)
[2026-11-01 14:03:25] [WARNING] [https] [1.2.3.4:51240] TLS ClientHello SNI=www.example.com | bytes=517 record_version='TLS 1.0' hello_version='TLS 1.2' cipher_count=17 sni='www.example.com' versions=['TLS 1.3', 'TLS 1.2'] port=443 (冷卻中，不寄信)
[2026-11-01 14:03:40] [WARNING] [http] [10.0.0.5:4000] HTTP GET / | ... (白名單，不寄信)
[2026-11-01 14:04:01] [WARNING] [mssql] [1.2.3.4:51300] MSSQL TDS Pre-Login | bytes=47 head_hex='12 01 00 2f ...' tds_type='Pre-Login' tds_length=47 port=1433 (冷卻中，不寄信)
```

括號裡是寄信決定：已寄信、未啟用寄信、白名單不寄信、冷卻中不寄信。寄信失敗會另外一行 ERROR。

## 測試

```bat
python -m unittest discover -s tests -t .
```

SMTP 寄信只有 mock 測試，真的能不能寄到要在目標機器上確認：
把 `notify.email.enabled` 改 true 後用高 port 前景啟動，`curl http://127.0.0.1:8080/` 一次，log 那行結尾應該是「已寄信」而不是「寄信失敗」。

Windows 服務的測試只能跑到「沒有管理員也能驗」的部分（狀態機、結構大小、非 SCM 啟動會回 1063）。
真正的 `sc create / start / stop` 要在系統管理員的命令提示字元手動做一次。

## 架構

```
main.py                 CLI、前景與服務兩種模式共用的啟動與收尾流程
setup.py / Setup.bat    安裝精靈：問答產生 config.json、試寄信、檢查 port、登錄並啟動服務
Uninstall.bat           停止並移除服務
package.py              做離線部署包（embeddable Python + 程式碼）
honeypot/
  config.py             預設值、合併、驗證、白名單比對
  notify.py             Event、Notifier（佇列 + worker）、SMTP
  heartbeat.py          每日 heartbeat、state 檔
  winservice.py         ctypes 接 Windows SCM、sc.exe 安裝與移除
  services/base.py      TCP / UDP 監聽、socket 綁定規則（open_socket）、ByteReader、例外兜底
  services/__init__.py  名稱登錄表 CATALOG（名稱 → 說明、類別）、create_service()
  services/http.py      HTTP：解析 request、回靜態頁
  services/tls.py       HTTPS：只解析 ClientHello（SNI、版本），不握手、不需憑證
  services/mssql.py     收第一包、辨識 TDS 型別、斷線
  services/generic.py   SSH / RDP / MySQL / Redis……：profile 表，送 banner、收第一包
  services/udp.py       DNS / SNMP（UDP）
```

服務執行緒只負責 `notifier.emit(event)`，寄信在另一條執行緒排隊送，SMTP 慢不會卡住新連線。

## 已知邊界

- 只綁 IPv4。
- HTTPS 不做 TLS 握手，所以拿得到 SNI 與 TLS 版本，拿不到握手之後才加密送來的 path 與 User-Agent。
- MSSQL 只記第一包，不回 prelogin，所以拿不到帳號。
- UDP（DNS / SNMP）沒有握手，來源 IP 可以偽造，所以冷卻以服務為鍵而不是 IP：冷卻期內同一個 port 不管多少來源都只寄一封，
  代價是第二個真正的來源要等冷卻過了才會收到信（log 裡都有）。`cooldown_minutes` 設 0 會回到每個封包一封，不建議。
- heartbeat 規則是「今天沒寄過且已過設定時間就寄」，所以程式在設定時間之後啟動會補寄當天那封。

## 設計取捨

- 刻意不做：管理網頁、資料庫、第三方套件（Flask / SQLAlchemy / gevent 之類）、自簽憑證
- 每條連線只發一筆告警；寄信走背景佇列，不卡住服務；程式不回寫 config，執行期狀態另存 state 檔
- 功能重點：HTTPS 免憑證記 SNI、同 IP 冷卻合併、啟動失敗即退出、Windows 服務模式、log 輪替、離線部署包

## 授權

MIT，見 [LICENSE](LICENSE)。

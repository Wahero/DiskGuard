# cdisk-guard 規則表

沿用 `windows-disk-cleanup` 技能的三檔分級，並補上通知與刪除動作規則。
改規則只需編輯本檔說明與 `cdiskctl.py` 內的規則常數／`config.json`，不需重新掃描。

## 一、A / B / C 三檔

| 檔 | 定義 | 可否勾選 |
|---|---|---|
| **A** | 暫存檔、快取、更新安裝包、崩潰傾印、縮圖快取、回收站內容。刪除後程式會自動重建 | ✅ 可，且為預設勾選 |
| **B** | 軟體資料、模型快取、自建目錄、個人下載、大型安裝檔。刪了可能要重新下載或重裝 | ✅ 可，但需自行判斷 |
| **C** | 系統元件、使用者設定檔總目錄、個人文件、憑證（`.ssh`、`.aws`、`.git-credentials` 等） | ❌ 鎖定，後端再次拒絕 |

### C 檔黑名單（節錄）
- 根目錄：`Windows`、`Program Files`、`Program Files (x86)`、`ProgramData`、
  `System Volume Information`、`Recovery`、`$WinREAgent`、`PerfLogs`、`Boot`、
  `Config.Msi`、`inetpub`、`MSOCache`、`$Windows.~WS`、`$Windows.~BT`、`Documents and Settings`
- 使用者總目錄：`Users` 本身、`Default`、`Public`、`All Users`、`Default User`、`desktop.ini`
- 使用者子目錄：`Desktop`、`Documents`、`Pictures`、`Videos`、`Music`、`Favorites`、
  `Contacts`、`Links`、`Searches`、`Saved Games`、`OneDrive`、`AppData` 總目錄、
  `.ssh`、`.workbuddy`、`.openclaw`、`.claude`、`.codex`、`.hermes`、`.aws`、`.gnupg`、`.kube`
- 快取類例外：`WindowsInstaller`、`PackageCache` 為 C 檔（刪了軟體無法卸載／修復）

### A 檔垃圾點
`Windows\Temp`、使用者 `AppData\Local\Temp`、`SoftwareDistribution\Download`、
`Prefetch`、Chrome／Edge `Default\Cache`、`INetCache`、`Explorer\thumbcache_*.db`、
`CrashDumps`、NVIDIA Downloader、迅雷更新包、`WER`、`Windows.old`、
`npm-cache`、`*-updater`、`@*-updater`、名稱含 `cache`／`update`／`logs`／`crash`／`gpu` 的 AppData 子目錄。

### 特別標記
- `$Recycle.Bin` 內容屬 A 檔，但**目錄本身不可刪**；後端以 `SHEmptyRecycleBinW` 清空。
- `...\Microsoft\Windows\Explorer` 只刪 `thumbcache_*.db`，保留目錄。
- 含 `tencent`／`kingsoft`／`wechat` 的 AppData 目錄歸 C 檔（含聊天記錄）。
- 使用者指定排除項（目前為 `npm-cache`）即使屬 A 檔也不預設勾選，見 `config.json`。

## 二、通知規則

以 `free / total * 100` 判斷，資料來源固定為 `GetDiskFreeSpaceExW`。

| 剩餘比例 | 規則 |
|---|---|
| `< 2%` | 觸發警示框（A. 去清理磁盤 / B. 人工處理）。每個 `cooldown_sec`（6h）最多一次，直到狀態改變 |
| `2% ~ 10%` | 寫入 `data/notice.md` 與日誌；`notify_on_warn_pct=false` 時不打擾使用者 |
| `>= 10%` | 僅寫日誌 |

週一例行分析：星期一一整天內，當 CPU 使用率 ≦ 25% 時執行一次 `scan` + `report`；
狀態檔記錄日期避免重複。分析完成後再套用上表決定是否通知。

## 三、刪除動作規則

| `delete_method` | 適用 | 做法 |
|---|---|---|
| `direct` | 一般 A 檔快取／暫存 | Python `shutil.rmtree`／逐檔刪除，鎖定檔略過並記數 |
| `thumbcache_only` | `...\Microsoft\Windows\Explorer` | 只刪 `thumbcache_*.db`，保留目錄 |
| `empty_recycle_bin` | `C:\$Recycle.Bin` | `shell32.SHEmptyRecycleBinW`，不碰目錄本身 |
| `denied` | 權限不足的系統快取 | 照常嘗試，失敗記入殘留，不中斷整批 |

### 強制前置條件
1. 剔除 C 檔、鎖定路徑、父子重疊子項（`nested_in`）、設定排除項。
2. 任一路徑不在 `C:\` 允許範圍內、或為磁碟根、或為使用者設定檔總目錄 → 整批拒絕。
3. 寫 manifest → 小項 ZIP 備份 → 每批最多 10 項 → 逐項複核 → 空間對比 → 寫紀錄。
4. 網頁 modal 必須顯示加粗警示並逐項列完整路徑，且使用者需再按一次確認。

## 四、數值口徑

- 遍歷時跳過 reparse point（`st_file_attributes & 0x400`），避免 junction 自引用重複計算。
- 六個維度由**同一次遍歷**聚合，不再出現「178.4 GB vs 137.8 GB」兩套數字。
- `nested_in` 標記讓「帳面選取量」與「實際可釋放量」分開顯示。
- 刪除前後的剩餘空間使用同一函式取值；「觀測淨增」與「目標帳面值」並列，
  差值可能來自其他程式寫入，不冒充精確成果。

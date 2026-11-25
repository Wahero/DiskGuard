---
name: cdisk-guard
description: C 盤空間守護 CLI。背景常駐監控剩餘空間，低於 2% 彈出「磁盤剩餘空間」雙按鈕警示框；按 A 開啟可真刪除的分析網頁（預設勾選 A 檔），按 B 關閉網頁；每週一低 CPU 時背景做一次磁碟分析。全程零 LLM 呼叫。觸發詞：磁碟守護、磁盤空間監控、C盤清理、空間不足警示、cdisk-guard、disk guard。
user_invocable: true
disable_model_invocation: false
---

# cdisk-guard · C 盤空間守護 CLI

把 2026-11-23 那輪「掃描 → 三檔分級 → 人工確認 → 刪除 → 複核」的流程固化成**純本機 Python 程式**。
設計目標：**運行期 0 次模型呼叫、0 積分消耗**。判斷寫在規則表，執行寫在程式，LLM 只在改規則時進場。

## 何時用

- 使用者要求「背景監控 C 盤／空間不足自動警示／定期自動分析／一鍵清理」。
- 使用者要求把先前的 C 盤清理工作做成技能、CLI、排程或常駐服務。
- 需要產生／更新那份「三檔分級＋勾選＋刪除」的獨立網頁。

## 工作目錄（單一來源）

本專案的開發／文件來源目錄：**`C:\AI\@Project\DiskGuard`**

| 子目錄 | 內容 |
|---|---|
| `cdisk-guard\` | CLI 技能原始碼，可直接在該目錄執行（config／data 皆相對於此目錄解析） |
| `cdisk-cleanup\` | 2026-11-23 清理執行產出：報告、manifest、小項備份、三份批次紀錄、產生器 |
| `dist\` | 兩份已交付 zip（清理清單套件、技能包） |
| `sync_to_skill.py` | 把 `cdisk-guard\` **單向**同步到 WorkBuddy 已安裝技能目錄 |

`~\.workbuddy\skills\cdisk-guard\` 是 WorkBuddy 的**已安裝執行副本**，並非來源。
改程式／改規則請改工作目錄，再執行 `python C:\AI\@Project\DiskGuard\sync_to_skill.py`；
直接改執行副本會在下次同步時被覆蓋。同步預設保留已安裝副本的 `data\`（掃描、狀態、日誌），
需要連資料一起覆寫才加 `--with-data`。

## 重要觀念（不要做錯）

1. **不要用 WorkBuddy 排程自動化來跑這個**。排程自動化每次觸發都會喚醒模型、消耗積分。
   正確做法：Windows 工作排程在登入時啟動 `pythonw.exe cdiskctl.py watch`，純 OS 行程。
2. 註冊開機工作／啟動常駐行程屬**系統變更**，必須先取得使用者明確同意才可執行。
   本技能提供 `install_task.ps1` 但**預設不執行**。
3. 網頁要能真刪除，必須有只綁 `127.0.0.1` 的本機後端；`file://` 靜態頁做不到。
4. 刪除一律不可還原時，必須先顯示加粗警示「⚠️ 此操作非常危險，可能導致不可逆的數據丟失！」、
   逐項列出完整路徑、並在 modal 內取得第二次確認。C 檔永遠不得進入刪除清單。

## CLI

所有指令皆在工作目錄的 `cdisk-guard` 根目錄執行
（`cd /d C:\AI\@Project\DiskGuard\cdisk-guard`；已安裝副本亦可），建議使用 WorkBuddy 內建 Python：
`C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\python.exe`

```
python scripts/cdiskctl.py status               # 一次輸出磁碟現況 JSON（最便宜）
python scripts/cdiskctl.py scan                # 單次遍歷掃描 → data/scan.json
python scripts/cdiskctl.py report              # 由 scan.json 產生單檔離線 HTML
python scripts/cdiskctl.py serve               # 啟動 127.0.0.1 後端＋開瀏覽器（可真刪除）
python scripts/cdiskctl.py alert                # 顯示「磁盤剩餘空間」A/B 警示框
python scripts/cdiskctl.py watch               # 背景常駐（工作排程用這個）
python scripts/cdiskctl.py watch --once        # 只跑一輪檢查就結束（測試用）
python scripts/cdiskctl.py delete --dry-run    # 預演刪除流程，不刪任何檔
python scripts/cdiskctl.py selftest            # 全邏輯自測：不彈窗、不刪檔、不啟動服務
```

常用參數：`--config <path>`、`--dry-run`、`--budget <秒>`、`--verbose`。
`watch` 另外接受 `--interval <秒>`；`alert` 接受 `--auto-close <秒>` 供無人值守測試。

## 行為規格

| 條件 | 動作 |
|---|---|
| 剩餘／總量 < `alert.threshold_pct`（2%） | 彈出標題「磁盤剩餘空間」視窗，顯示剩餘、總量、百分比；兩個按鈕 **A. 去清理磁盤** / **B. 人工處理**；`cooldown_sec` 內不重複彈 |
| 按 **A** | 啟動本機後端 → 重新掃描 → 開啟分析網頁（沿用三檔分級版式），**預設勾選所有 A 檔**，排除 `npm-cache` 等設定項；「執行刪除」走本次刪除流程直接刪 |
| 按 **B** | 關閉網頁、停止後端、結束警示，不刪任何檔 |
| 剩餘 ≧ 2%，且為週一、CPU 使用率 ≦ `weekly.cpu_max_pct` | 背景執行一次 `scan` + `report`，當日只做一次 |
| 分析後 2% ≦ 剩餘 < `warn_pct`（10%） | 只寫入通知檔與日誌；`notify_on_warn_pct=true` 才彈提示 |
| 分析後剩餘 ≧ 10% | 僅寫日誌，不通知 |

空間與 CPU 皆以 `ctypes` 直接呼叫 Win32（`GetDiskFreeSpaceExW`／`GetSystemTimes`），
**不開 PowerShell、不起 subprocess、不喚醒模型**，每 5 分鐘一次檢查成本極低。

## 刪除流程（對應本輪實際做法）

1. 驗證：剔除 C 檔、鎖定項（`$Recycle.Bin` 目錄本身）、父子重疊子項、設定排除項；
   任何路徑不在允許根目錄內即整批拒絕。
2. 寫入 `execution_manifest.json`（完整路徑、大小、時間、動作）。
3. `<100 MB` 項目做 ZIP 實體備份，使用中的檔案略過並記數；其餘以 manifest 取代位元備份。
4. 每批最多 10 項，以 Python `shutil`／逐檔刪除（獨立行程，不受 WorkBuddy 大量刪除鉤子影響）。
   特殊動作：`Explorer` 只刪 `thumbcache_*.db`；回收站走 `SHEmptyRecycleBinW`。
5. 逐項 `os.path.exists` 複核、記錄殘留項目數；同資料來源測量刪除前後剩餘空間。
6. 輸出 `execution_log.md` 與 `execution_result.json`，網頁即時顯示結果。

## 安全邊界

- C 檔（系統組件、個人資料、憑證）checkbox 鎖定，後端再次拒絕，雙重防護。
- 後端只綁 `127.0.0.1`、隨機埠、一次性 token；`/api/delete` 需帶 token 與 `confirm`。
- 他人 SID 的回收站殘留只回報、不靜默清除，列為「需人工處理」。
- 觀測淨釋放量與帳面值分開呈現，不把其他程式寫入造成的差值算成成果。

## 檔案

| 檔案 | 用途 |
|---|---|
| `scripts/cdiskctl.py` | 主 CLI：掃描、分級、守護、後端、刪除、紀錄 |
| `scripts/win_dialog.py` | ctypes 原生雙按鈕警示框（無 tkinter／無 .NET） |
| `scripts/page.html` | 沿用本輪深色單檔版式的網頁模板 |
| `config.json` | 門檻、排程、排除項、特殊動作 |
| `references/rules.md` | A/B/C 分級與通知規則 |
| `references/evaluation.md` | 本輪工作評估與技術債對應表 |
| `install_task.ps1` | 註冊登入時背景工作（**需使用者同意才執行**） |
| `uninstall_task.ps1` | 移除背景工作 |
| `data/` | scan.json、網頁、執行紀錄、狀態檔、日誌 |

## 交付

程式碼類產出依使用者慣例打包成 zip 交付。註冊背景工作前須先以 AskUserQuestion 取得同意。

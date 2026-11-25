@echo off
chcp 65001 >nul
REM DiskGuard 桌寵 Phase 1 手動啟動入口（不接開機排程、不刪檔、不起服務）
REM 與既有 start_guard.cmd（watch）互斥：共用 data\watch.lock，同時只會有一個在跑。
REM 首次使用請先確認工作排程 cdisk-guard 已 Stop-ScheduledTask，否則本檔會因鎖衝突退出。

set "PYW=C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe"
set "PET=%~dp0scripts\pet.py"

if not exist "%PYW%" set "PYW=pythonw.exe"
if not exist "%PET%" (
  echo [ERROR] pet.py not found: %PET%
  pause
  exit /b 1
)

start "" "%PYW%" "%PET%"
echo DiskGuard pet launched (manual, no autostart).
echo Use: python scripts\pet.py --health  to inspect.
timeout /t 2 >nul

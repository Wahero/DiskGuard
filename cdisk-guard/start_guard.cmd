@echo off
chcp 65001 >nul
REM DiskGuard 背景守護啟動入口（手動；不寫入開機登錄、不改系統設定）
REM 背景守護沒有視窗，啟動後只會在 data\cdisk-guard.log 留紀錄——這是正常的。
REM 判斷邏輯都在 scripts\launch.py：鎖被佔用時會說明是誰在跑、要不要接手。
setlocal
set "PY=C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" "%~dp0scripts\launch.py" guard
echo.
pause

endlocal

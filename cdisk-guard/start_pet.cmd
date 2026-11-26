@echo off
chcp 65001 >nul
REM DiskGuard 桌寵啟動入口（手動；不寫入開機登錄、不刪檔、不起服務）
REM 判斷邏輯都在 scripts\launch.py：它會說明現在是誰在跑、要不要接手，
REM 失敗時把日誌尾巴印出來。以前這裡直接 start pythonw，一旦行程自己退出
REM （最常見是背景守護正佔著鎖），畫面一閃就沒、什麼訊息都看不到。
setlocal
set "PY=C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" "%~dp0scripts\launch.py" pet
echo.
pause

endlocal

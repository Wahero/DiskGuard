@echo off
chcp 65001 >nul
title DiskGuard - clean A group
cd /d "%~dp0"
set "PY=C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\python.exe"
if not exist "%PY%" set "PY=python"
echo ============================================
echo   DiskGuard - clean default A-class targets
echo   Temp / updater cache / browser cache
echo   Permanent delete (not sent to Recycle Bin)
echo   Manifest + backup saved to cdisk-guard\data
echo ============================================
echo.
echo [Step 1/2] Preview - nothing is deleted yet
echo.
"%PY%" "cdisk-guard\scripts\manual_clean.py" --dry-run
echo.
echo --------------------------------------------
set "GO="
set /p GO=[Step 2/2] Type YES and press Enter to delete: 
if /i not "%GO%"=="YES" (
  echo Cancelled.
  timeout /t 3 >nul
  exit /b 1
)
echo.
"%PY%" "cdisk-guard\scripts\manual_clean.py"
echo.
echo ==== Done. Press any key to close ====
pause >nul

@echo off
REM 手動啟動 cdisk-guard 背景守護（不寫入開機登錄、不改系統設定）
REM 用 pythonw.exe 啟動，完全無主控台視窗。
setlocal
set "PYW=C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe"
set "CTL=%~dp0scripts\cdiskctl.py"
if not exist "%PYW%" (
  echo [ERROR] pythonw.exe not found: %PYW%
  exit /b 1
)
start "" "%PYW%" "%CTL%" watch
echo cdisk-guard watch started. Log: %~dp0data\cdisk-guard.log
endlocal

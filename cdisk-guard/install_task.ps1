# cdisk-guard 背景常駐登錄腳本
# ⚠️ 這會建立 Windows 工作排程（系統變更）。必須先取得使用者明確同意才可執行。
# 預設（Phase 3 起）：登入時啟動 pythonw.exe scripts\pet.py（托盤＋桌寵）。
# 回退：-Mode watch 可恢復舊的 cdiskctl.py watch（無桌寵 UI）。
# 兩者皆為純本機行程、零 LLM 呼叫；共用 watch.lock，同時只會跑一個。
#
#   powershell -ExecutionPolicy Bypass -File install_task.ps1                 # 桌寵（預設）
#   powershell -ExecutionPolicy Bypass -File install_task.ps1 -Mode watch     # 回退
#   powershell -ExecutionPolicy Bypass -File install_task.ps1 -Remove         # 移除

param([switch]$Remove, [ValidateSet('pet', 'watch')][string]$Mode = 'pet')

$ErrorActionPreference = 'Stop'
$TaskName = 'cdisk-guard'
$Root     = Split-Path -Parent $MyInvocation.MyCommand.Path
$Ctl      = Join-Path $Root 'scripts\cdiskctl.py'
$Pet      = Join-Path $Root 'scripts\pet.py'
$Pythonw  = 'C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe'

if (-not (Test-Path -LiteralPath $Pythonw)) { throw "找不到 pythonw.exe：$Pythonw" }
if (-not (Test-Path -LiteralPath $Pet))     { throw "找不到 pet.py：$Pet" }
if ($Mode -eq 'watch' -and -not (Test-Path -LiteralPath $Ctl)) { throw "找不到 cdiskctl.py：$Ctl" }

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Output "已移除舊工作：$TaskName"
}
if ($Remove) {
    Write-Output '完成移除，未建立新工作。'
    exit 0
}

if ($Mode -eq 'pet') {
    $Entry = $Pet
    $Args  = '"' + $Pet + '"'
} else {
    $Entry = $Ctl
    $Args  = '"' + $Ctl + '" watch'
}
$action  = New-ScheduledTaskAction -Execute $Pythonw `
           -Argument $Args -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
$set     = New-ScheduledTaskSettingsSet `
           -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
           -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) `
           -RestartCount 3 -RestartInterval ([TimeSpan]::FromMinutes(5)) `
           -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal `
           -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
           -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $set -Principal $principal `
    -Description 'C 盤剩餘空間守護：托盤＋桌寵常駐；低於 2% 桌寵現身並背景分析、按需開本機網頁；週一低 CPU 時背景分析。純本機 Python，零模型呼叫。' |
    Out-Null
Write-Output "已登錄：$TaskName（登入時啟動）"
Write-Output "程式：$Pythonw"
Write-Output "模式：$Mode"
Write-Output "參數：$Args"
Write-Output "紀錄：$(Join-Path $Root 'data\cdisk-guard.log')"
Write-Output ''
Write-Output '立即啟動（不等下次登入）：Start-ScheduledTask -TaskName cdisk-guard'
Write-Output '停止：Stop-ScheduledTask -TaskName cdisk-guard'
Write-Output '回退成 watch：powershell -ExecutionPolicy Bypass -File install_task.ps1 -Mode watch'
Write-Output '移除：powershell -ExecutionPolicy Bypass -File install_task.ps1 -Remove'

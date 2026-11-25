# 移除 cdisk-guard 背景工作（不刪除任何掃描資料或清理紀錄）
$ErrorActionPreference = 'SilentlyContinue'
$TaskName = 'cdisk-guard'
$t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($t) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Output "已移除工作：$TaskName"
} else {
    Write-Output "找不到工作：$TaskName（可能尚未登錄）"
}
Write-Output 'data/ 內的掃描、報告與執行紀錄皆保留。'

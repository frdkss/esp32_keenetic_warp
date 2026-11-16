#Requires -Version 5.1
param([string]$WorkRoot, [string]$Vault, [string]$PythonPath, [string]$IdfPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = Split-Path $PSScriptRoot -Parent
foreach ($name in @('Common', 'Validation', 'Keys', 'Generation')) {
    Import-Module (Join-Path $source "scripts/service/$name.psm1") -Force -DisableNameChecking
}
# Synthetic hidden-input provider; no real credential or passphrase is requested.
function global:Read-ServicePassword { return 'SYNTHETIC-backup-passphrase-2026' }
$project = Join-Path $WorkRoot 'project'
[void][IO.Directory]::CreateDirectory((Join-Path $project 'scripts'))
[void][IO.Directory]::CreateDirectory((Join-Path $project 'include'))
foreach ($file in @('security_store.py', 'service_nvs.py')) {
    Copy-Item -LiteralPath (Join-Path $source "scripts/$file") -Destination (Join-Path $project "scripts/$file")
}
Copy-Item -LiteralPath (Join-Path $source 'partitions.csv') -Destination (Join-Path $project 'partitions.csv')
$tools = Resolve-ServiceTools $project $PythonPath $IdfPath
$backup = Join-Path $WorkRoot 'ps-backup.warpbackup'
$restored = Join-Path $WorkRoot 'restored'
Invoke-ServiceSecurityTool $project $tools @('backup', '--vault', $Vault, '--backup', $backup) -WithPassphrase -ConfirmPassphrase
Invoke-ServiceSecurityTool $project $tools @('restore', '--vault', $restored, '--backup', $backup) -WithPassphrase
$inputData = [ordered]@{
    WifiSsid = 'SYNTHETIC-private-SSID'; WifiPassword = 'SYNTHETIC-private-WiFi'
    RouterLogin = 'SYNTHETIC-login'; RouterPassword = 'SYNTHETIC-private-router'
    RouterAddress = '192.0.2.1'; RouterHttpsName = 'router.example.invalid'; RouterPort = '443'
    WarpInterface = 'Wireguard7'; TargetUrls = @('https://target.example.invalid/')
    ControlUrls = @('https://control.example.invalid/'); Timezone = 'MSK-3'
    ScheduleTime = '05:00'; ScheduleDay = '4'; CheckIntervalSeconds = '60'
    ConnectTimeoutSeconds = '5'; ReadTimeoutSeconds = '5'; DisablePauseSeconds = '2'
    WarmupSeconds = '30'; CooldownSeconds = '300'; EnableAutoRecovery = '1'
    EnableWeeklyRestart = '0'; OledEnabled = '0'
}
$configuration = ConvertTo-ServiceConfiguration $inputData
Write-ServiceConfigurationFromVault $project $configuration $tools $restored
if (-not (Test-Path -LiteralPath (Join-Path $project '.local/service/nvs.encrypted.bin'))) { throw 'Missing encrypted NVS' }
if (@(Get-ChildItem -LiteralPath (Join-Path $project '.local/service') -Directory -Force).Count -ne 0) { throw 'Raw key transaction retained' }
# Confirm-passphrase mismatch must fail before producing a backup.
$script:count = 0
function global:Read-ServicePassword {
    $script:count++
    if ($script:count -eq 1) { return 'SYNTHETIC-passphrase-number-one' }
    return 'SYNTHETIC-passphrase-number-two'
}
$bad = Join-Path $WorkRoot 'must-not-exist.warpbackup'
$rejected = $false
try { Invoke-ServiceSecurityTool $project $tools @('backup', '--vault', $Vault, '--backup', $bad) -WithPassphrase -ConfirmPassphrase }
catch { $rejected = $true }
if (-not $rejected -or (Test-Path -LiteralPath $bad)) { throw 'Passphrase mismatch was accepted' }
Write-Host 'PASS bound configuration and backup lifecycle'

#Requires -Version 5.1
param([string]$WorkRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
foreach ($name in @('Common','Workflow')) {
    Import-Module (Join-Path $root "scripts/service/$name.psm1") -Force -DisableNameChecking
}
& (Get-Module Workflow) {
    param($work)
    $project = Join-Path $work 'project'
    [void][IO.Directory]::CreateDirectory((Join-Path $project '.local/service'))
    $backup = Join-Path $work 'fake-backup'
    [IO.File]::WriteAllText($backup, 'fake')
    $script:mac = '020000000001'
    $script:identityReads = 0
    $script:provisionCalls = 0
    $script:changeDevice = $false
    function script:Clear-ServiceScreen { }
    function script:ConvertTo-ServiceConfiguration {
        return [pscustomobject]@{ OledEnabled=0; TargetUrls=@(); ControlUrls=@(); ConnectTimeoutSeconds=1; ReadTimeoutSeconds=1 }
    }
    function script:Get-ServiceSelectedDevice {
        $script:identityReads++
        if ($script:changeDevice -and $script:identityReads -gt 1) { return '020000000002' }
        return $script:mac
    }
    function script:Save-ServiceState { }
    function script:Resolve-ServiceTools { return [pscustomobject]@{ Python='unused'; Idf='unused' } }
    function script:Write-ServiceConfigurationFromVault { }
    function script:Invoke-ServiceProcess { return [pscustomobject]@{ ExitCode=0 } }
    function script:Invoke-ServiceUpdate { }
    function script:Invoke-ServiceEventTool { return [pscustomobject]@{ running=$false } }
    function script:Write-ServiceProgress([string]$Status, [int]$Percent, [int]$StepsDone, [int]$StepsTotal) { }
    function script:Read-ServiceBackupRequest { return 'unused-request' }
    function script:Read-ServiceConsoleText { throw 'Unexpected manual input during MAC selection' }
    function script:Show-ServiceNotice { }
    function script:Invoke-ServiceProvisioning($Package, $Root, $Tools, $Vault, $Backup, $Port, $Request, $Confirmation, $Timeout) {
        if ($Confirmation -cne $script:mac) { throw 'Wrong automatic MAC' }
        if ($Port -cne 'COM999') { throw 'Wrong selected port' }
        $script:provisionCalls++
    }
    $state = [ordered]@{ Port='COM999'; Configuration=@{}; SelectedMac=''; Devices=@{} }
    $state.Devices[$script:mac] = [ordered]@{ Vault='unused-vault'; Backup=$backup }
    $paths = [pscustomobject]@{ ServicePython='unused'; Idf='unused'; BuildPython='unused' }
    Invoke-ServiceMenuFlash $project $state $paths
    if ($script:identityReads -ne 2 -or $script:provisionCalls -ne 1) { throw 'MAC must be checked again immediately before provisioning' }
    $script:changeDevice = $true
    $script:identityReads = 0
    $script:provisionCalls = 0
    $blocked = $false
    try { Invoke-ServiceMenuFlash $project $state $paths }
    catch { $blocked = $_.Exception.Data.Contains('ServiceSafe') }
    if (-not $blocked -or $script:provisionCalls -ne 0) { throw 'Changed device must be rejected before writing' }
    # An interrupted protection attempt may only verify the existing device.
    $vault = Join-Path $work 'fake-vault'
    [void][IO.Directory]::CreateDirectory($vault)
    [IO.File]::WriteAllText((Join-Path $vault 'provision-receipt.json'), '{"result":"started","phase":"secure-download"}')
    $state.Devices[$script:mac].Vault = $vault
    $script:changeDevice = $false
    $script:verificationCalls = 0
    function script:Invoke-ServiceProvisionVerification { $script:verificationCalls++ }
    function script:Invoke-ServiceProcess { throw 'Verification must not build or write a device' }
    function script:Write-ServiceConfigurationFromVault { throw 'Verification must not replace configuration' }
    Invoke-ServiceMenuFlash $project $state $paths
    if ($script:verificationCalls -ne 1 -or $script:provisionCalls -ne 0) { throw 'Interrupted attempt was not limited to verification' }
    [IO.File]::WriteAllText((Join-Path $vault 'provision-receipt.json'), '{"result":"unverified","phase":"boot-verification","authenticated_image_and_configuration":true}')
    $script:verificationCalls = 0; $script:updateCalls = 0
    function script:Invoke-ServiceProcess { return [pscustomobject]@{ ExitCode=0 } }
    function script:Write-ServiceConfigurationFromVault { }
    function script:Invoke-ServiceEventTool { return [pscustomobject]@{ running=$true } }
    function script:Invoke-ServiceUpdate($Root, $Tools, $Vault, $Package, $Port, $Timeout, [switch]$Prepare, [switch]$ApplyConfiguration) {
        if (-not $Prepare) { $script:updateCalls++ }
    }
    Invoke-ServiceMenuFlash $project $state $paths
    if ($script:verificationCalls -ne 0 -or $script:updateCalls -ne 1 -or $script:provisionCalls -ne 0) {
        throw 'Authenticated firmware with unhealthy monitoring must use protected update to apply corrected CFG'
    }
} $WorkRoot
Write-Host 'PASS automatic MAC and changed device guard'

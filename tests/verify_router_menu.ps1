#Requires -Version 5.1
param([string]$WorkRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
foreach ($name in @('Common', 'Validation', 'State', 'Console', 'Processes', 'Router', 'Menu')) {
    Import-Module (Join-Path $root "scripts/service/$name.psm1") -Force -DisableNameChecking
}
function Assert([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
$previousAppData = $env:LOCALAPPDATA
$env:LOCALAPPDATA = Join-Path $WorkRoot 'appdata'
try {
    $state = Read-ServiceState
    Set-ServiceDraftValues $state @{ RouterLogin = 'SYNTHETIC_LOGIN'; RouterPassword = 'SYNTHETIC_PASSWORD'; RouterAddress = '192.0.2.1' }
    Set-ServiceDraftValues $state @{ RouterHttpsName = 'old.example.invalid'; WarpInterface = 'Wireguard0' }

    # Exercise the real private request-file adapter; only its child is mocked.
    & (Get-Module Router) {
        param($state)
        $script:fail = $false
        function script:Invoke-ServiceEventTool($Python, $Arguments, $Stage, $TimeoutSeconds) {
            if (($Arguments -join ' ').Contains('SYNTHETIC')) { throw 'Secret in child arguments' }
            $path = $Arguments[2]
            $request = ConvertFrom-Json ([IO.File]::ReadAllText($path))
            if ($request.login -cne 'SYNTHETIC_LOGIN' -or $request.password -cne 'SYNTHETIC_PASSWORD') { throw 'Request credential preservation' }
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
            foreach ($item in @($path, (Split-Path $path -Parent))) {
                $acl = Get-Acl -LiteralPath $item
                if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $identity) { throw 'Request owner/ACL' }
                foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                    if ($rule.IdentityReference -ne $identity) { throw 'Private request readable by another identity' }
                }
            }
            if ($script:fail) { Stop-ServiceOperation 'Synthetic router failure' }
            return [pscustomobject]@{ https_name = 'router.example.invalid'; tls_verified = $true; interfaces = @() }
        }
        [void](Get-ServiceRouterInformation $state.Configuration -Interfaces)
        $script:fail = $true
        $failed = $false
        try { [void](Get-ServiceRouterInformation $state.Configuration -Interfaces) }
        catch { $failed = $_.Exception.Message -eq 'Synthetic router failure' }
        if (-not $failed) { throw 'Child error was not preserved' }
        if (@(Get-ChildItem -LiteralPath (Get-ServiceHome) -Filter '.router-*' -Force).Count -ne 0) { throw 'Private request retained after child completion' }
    } $state

    # Drive the real network editor and picker, retaining real validation/DPAPI.
    & (Get-Module Menu) {
        param($state)
        function script:Show-ServiceNetworkScreen { }
        function script:Show-ServiceWarpScreen { }
        function script:Show-ServiceNotice($Message) { $script:notice = $Message }
        $script:notice = ''
        $script:fail = $false
        $script:calls = 0
        function script:Get-ServiceRouterInformation($Configuration, [switch]$Interfaces) {
            $script:calls++
            if ($script:fail) { Stop-ServiceOperation 'Synthetic router failure' }
            $name = if ($Configuration.RouterAddress -eq '192.0.2.2') { 'second.example.invalid' } else { 'router.example.invalid' }
            if ($Configuration.RouterPort -eq 8443) { $name = 'port8443.example.invalid' }
            return [pscustomobject]@{ https_name = $name; tls_verified = $true; interfaces = @(
                [pscustomobject]@{ id = 'Wireguard0'; description = 'VPN'; enabled = $false; connected = $false }
                [pscustomobject]@{ id = 'Wireguard1'; description = 'WARP'; enabled = $true; connected = $true }
                [pscustomobject]@{ id = 'Wireguard10'; description = 'Other VPN'; enabled = $true; connected = $false }
            ) }
        }
        $script:keys = [Collections.Generic.Queue[ConsoleKeyInfo]]::new()
        function script:Add-Keys([string[]]$Names) {
            foreach ($name in $Names) { $script:keys.Enqueue([ConsoleKeyInfo]::new([char]0, [ConsoleKey]::$name, $false, $false, $false)) }
        }
        function script:Read-ServiceKey([scriptblock]$OnResize) {
            if ($OnResize) { & $OnResize }
            if (-not $script:keys.Count) { throw 'Unexpected key read' }
            return $script:keys.Dequeue()
        }
        Add-Keys @('Escape')
        [void](Invoke-ServiceNetworkMenu $state)
        if ($state.Configuration.RouterHttpsName -cne 'router.example.invalid' -or $script:calls -ne 1) { throw 'Automatic HTTPS name on entry' }
        if ((Read-ServiceState).Configuration.RouterHttpsName -cne 'router.example.invalid') { throw 'Automatic name not persisted' }

        Add-Keys ((@('DownArrow') * 12) + @('Enter', 'DownArrow', 'Enter', 'Escape'))
        [void](Invoke-ServiceNetworkMenu $state)
        if ($state.Configuration.WarpInterface -cne 'Wireguard1' -or (Read-ServiceState).Configuration.WarpInterface -cne 'Wireguard1') { throw 'Arrow picker did not save selected ID' }
        Add-Keys ((@('DownArrow') * 12) + @('Enter', 'DownArrow', 'Escape', 'Escape'))
        [void](Invoke-ServiceNetworkMenu $state)
        if ($state.Configuration.WarpInterface -cne 'Wireguard1') { throw 'Esc changed selected interface' }
        Add-Keys @('UpArrow', 'Enter')
        $choice = Select-ServiceWarpInterface @(
            [pscustomobject]@{ id = 'Wireguard0' }, [pscustomobject]@{ id = 'Wireguard1' }
        ) 'Wireguard0'
        if ($choice.Interface -cne 'Wireguard1') { throw 'Arrow wrap failed' }

        function script:Read-ServiceConsoleText { return '192.0.2.2' }
        Add-Keys ((@('DownArrow') * 9) + @('Enter', 'Escape'))
        [void](Invoke-ServiceNetworkMenu $state)
        if ($state.Configuration.RouterHttpsName -cne 'second.example.invalid' -or $state.Configuration.WarpInterface) { throw 'Router change did not refresh name/reset interface' }
        Set-ServiceDraftValues $state @{ WarpInterface = 'Wireguard1' }
        function script:Read-ServiceConsoleText { return '8443' }
        Add-Keys ((@('DownArrow') * 11) + @('Enter', 'Escape'))
        [void](Invoke-ServiceNetworkMenu $state)
        if ($state.Configuration.RouterHttpsName -cne 'port8443.example.invalid' -or $state.Configuration.WarpInterface -cne 'Wireguard1') { throw 'Port change discovery failed' }
        function script:Read-ServiceConsoleText { throw 'Manual HTTPS/interface input must not be used' }
        Add-Keys ((@('DownArrow') * 10) + @('Enter', 'R', 'Escape'))
        [void](Invoke-ServiceNetworkMenu $state)

        $script:fail = $true
        $path = Join-Path (Get-ServiceHome) 'state/state.dpapi'
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        Add-Keys ((@('DownArrow') * 12) + @('Enter', 'Escape'))
        [void](Invoke-ServiceNetworkMenu $state)
        if ($before -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) { throw 'Failed discovery overwrote saved settings' }
        if ($script:notice -cne 'Synthetic router failure') { throw 'Discovery error not shown' }
        $failed = $false
        try { [void](Select-ServiceWarpInterface @() '') } catch { $failed = $_.Exception.Data.Contains('ServiceSafe') }
        if (-not $failed) { throw 'Empty router list invented an interface' }
        if ($script:keys.Count) { throw 'Unconsumed editor keys' }
    } $state

    # A failed discovery on a newly selected endpoint cannot leave old identity.
    Set-ServiceDraftValues $state @{ RouterAddress = '192.0.2.3' }
    $loaded = Read-ServiceState
    Assert (-not $loaded.Configuration.RouterHttpsName -and -not $loaded.Configuration.WarpInterface) 'Stale endpoint identity retained'
    Assert ($loaded.Configuration.RouterLogin -ceq 'SYNTHETIC_LOGIN') 'Connection edits changed credentials'
    Write-Host 'PASS router discovery/menu'
}
finally { $env:LOCALAPPDATA = $previousAppData }

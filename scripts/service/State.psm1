Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security

function Get-ServiceHome { return Join-Path $env:LOCALAPPDATA 'KeeneticWarp' }

function New-ServiceDraft {
    return [ordered]@{
        WifiSsid = ''; WifiPassword = ''; RouterLogin = ''; RouterPassword = ''
        RouterAddress = ''; RouterHttpsName = ''; RouterPort = 443; WarpInterface = ''
        TargetUrls = @(); ControlUrls = @(); CheckIntervalSeconds = 60
        ConnectTimeoutSeconds = 5; ReadTimeoutSeconds = 5; DisablePauseSeconds = 2
        WarmupSeconds = 30; CooldownSeconds = 300; FailureThreshold = 5; TargetFailurePolicy = 2
        ScheduleDay = 4; ScheduleTime = '05:00'; Timezone = 'MSK-3'
        EnableAutoRecovery = 1; EnableWeeklyRestart = 1; OledEnabled = 1
    }
}

function ConvertTo-ServiceMap($Value) {
    if ($null -eq $Value) { return $null }
    # Pipeline-wrapped strings from ConvertFrom-Json can also satisfy the
    # PSCustomObject test in Windows PowerShell 5.1. Keep scalar values first.
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [array]) {
        $items = @(foreach ($item in $Value) { ConvertTo-ServiceMap $item })
        return ,$items
    }
    if ($Value -is [pscustomobject]) {
        $map = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) { $map[$property.Name] = ConvertTo-ServiceMap $property.Value }
        return $map
    }
    return $Value
}

function Assert-ServiceDomainLists($Configuration) {
    foreach ($field in @('TargetUrls', 'ControlUrls')) {
        if ($Configuration[$field] -isnot [array]) { Stop-ServiceOperation 'Список доменов должен быть массивом строк. Перезапустите SERVICE для повторного чтения CFG.' }
        foreach ($item in $Configuration[$field]) {
            if ($item -isnot [string]) { Stop-ServiceOperation 'В списке доменов обнаружен объект вместо адреса. Сохранение остановлено; перезапустите SERVICE.' }
        }
    }
}

function Read-ServiceState([string]$HomeDirectory = (Get-ServiceHome)) {
    $state = [ordered]@{ Schema = 1; Configuration = New-ServiceDraft; Port = ''; UsbId = ''; SelectedMac = ''; Devices = [ordered]@{} }
    $path = Join-Path $HomeDirectory 'state/state.dpapi'
    Assert-ServicePlainPath $path
    if (-not (Test-Path -LiteralPath $path)) { return $state }
    $plain = $null
    try {
        if ((Get-Item -LiteralPath $path).Length -gt 1048576) { throw 'Too large' }
        $plain = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($path), [Text.Encoding]::UTF8.GetBytes('KeeneticWarp service state v1'), 'CurrentUser')
        $loaded = ConvertTo-ServiceMap (ConvertFrom-Json ([Text.Encoding]::UTF8.GetString($plain)))
        if ($loaded.Schema -ne 1 -or $loaded.Configuration -isnot [Collections.IDictionary] -or $loaded.Devices -isnot [Collections.IDictionary]) { throw 'Invalid state' }
        foreach ($key in $loaded.Configuration.Keys) {
            if (-not $state.Configuration.Contains($key)) { throw 'Unknown setting' }
            $state.Configuration[$key] = $loaded.Configuration[$key]
        }
        Assert-ServiceDomainLists $state.Configuration
        $state.Port = [string]$loaded.Port
        $state.UsbId = [string]$loaded.UsbId
        if ($loaded.Contains('SelectedMac')) { $state.SelectedMac = [string]$loaded.SelectedMac }
        $state.Devices = $loaded.Devices
        return $state
    }
    catch {
        if ($_.Exception.Data.Contains('ServiceSafe')) { throw }
        Stop-ServiceOperation 'Saved SERVICE configuration cannot be decrypted or is invalid. Existing state was preserved.'
    }
    finally { if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) } }
}

function Save-ServiceState($State, [string]$HomeDirectory = (Get-ServiceHome)) {
    Assert-ServiceDomainLists $State.Configuration
    $directory = Join-Path $HomeDirectory 'state'
    Assert-ServicePlainPath $directory
    [void][IO.Directory]::CreateDirectory($HomeDirectory)
    if (-not [IO.Directory]::Exists($directory)) { New-ServicePrivateDirectory $directory }
    $path = Join-Path $directory 'state.dpapi'
    Assert-ServicePlainPath $path
    $temporary = Join-Path $directory ('.pending-' + [Guid]::NewGuid().ToString('N'))
    $plain = $null
    try {
        $plain = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $State -Depth 12 -Compress))
        $encrypted = [Security.Cryptography.ProtectedData]::Protect($plain, [Text.Encoding]::UTF8.GetBytes('KeeneticWarp service state v1'), 'CurrentUser')
        $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
        try { Set-ServicePrivateFile $temporary; $stream.Write($encrypted, 0, $encrypted.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        if ([IO.File]::Exists($path)) { [IO.File]::Replace($temporary, $path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $path) }
        Set-ServicePrivateFile $path
    }
    finally {
        if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Get-ServicePorts {
    $details = @{}
    try {
        foreach ($entry in @(Get-CimInstance Win32_SerialPort -ErrorAction Stop)) {
            $details[$entry.DeviceID] = @{ Name = [string]$entry.Name; UsbId = [string]$entry.PNPDeviceID }
        }
    } catch { }
    foreach ($port in @([IO.Ports.SerialPort]::GetPortNames() | Sort-Object { [int]($_ -replace '\D', '') })) {
        $name = $port; $usbId = ''
        if ($details.ContainsKey($port)) { $name = $details[$port].Name; $usbId = $details[$port].UsbId }
        [pscustomobject]@{ Port = $port; Name = ($name -replace '[\x00-\x1f\x7f]', ''); UsbId = $usbId }
    }
}

function Test-ServiceDraft($Configuration) {
    try { [void](ConvertTo-ServiceConfiguration $Configuration); return $true } catch { return $false }
}

function Set-ServiceDraftValues($State, [Collections.IDictionary]$Values) {
    $candidate = [ordered]@{}
    foreach ($key in $State.Configuration.Keys) { $candidate[$key] = $State.Configuration[$key] }
    foreach ($key in $Values.Keys) {
        if (-not $candidate.Contains($key)) { Stop-ServiceOperation 'Unknown configuration field.' }
        $candidate[$key] = $Values[$key]
    }
    # Discovery belongs to one endpoint. A different router must not inherit
    # another router's certificate name or selected VPN interface.
    $reset = @()
    if ($Values.Contains('RouterAddress') -and $candidate.RouterAddress -cne $State.Configuration.RouterAddress) {
        $reset = @('RouterHttpsName', 'WarpInterface')
    } elseif ($Values.Contains('RouterPort') -and [string]$candidate.RouterPort -cne [string]$State.Configuration.RouterPort) {
        $reset = @('RouterHttpsName')
    }
    $reset = @($reset | Where-Object { -not $Values.Contains($_) })
    foreach ($key in $reset) { $candidate[$key] = '' }
    if ($Values.Contains('RouterAddress')) {
        $address = $null
        if (-not [Net.IPAddress]::TryParse([string]$Values.RouterAddress, [ref]$address) -or
            $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -cne $Values.RouterAddress) {
            Stop-ServiceOperation 'Для Keenetic нужен IPv4-адрес из четырёх чисел, например 192.168.1.1.'
        }
    }
    if ($Values.Contains('RouterHttpsName') -and [string]$Values.RouterHttpsName -match ':') {
        Stop-ServiceOperation 'Введите HTTPS-имя сертификата без схемы и порта.'
    }
    if ($Values.Contains('WarpInterface') -and [string]$Values.WarpInterface -cnotmatch '^Wireguard[0-9]+$') {
        Stop-ServiceOperation 'Нужно имя WARP-интерфейса вида Wireguard7.'
    }
    # Validate a partial draft without inventing persisted connection details.
    $placeholders = @{
        WifiSsid = 'validation'; RouterLogin = 'validation'; RouterPassword = 'validation'
        RouterAddress = '192.0.2.1'; RouterHttpsName = 'router.example.invalid'; WarpInterface = 'Wireguard0'
        TargetUrls = @('https://target.example.invalid/'); ControlUrls = @('https://control.example.invalid/')
    }
    foreach ($key in $placeholders.Keys) {
        if (-not $Values.Contains($key) -and (-not $candidate[$key] -or @($candidate[$key]).Count -eq 0)) { $candidate[$key] = $placeholders[$key] }
    }
    $validated = ConvertTo-ServiceConfiguration $candidate
    $previous = [ordered]@{}
    foreach ($key in (@($Values.Keys) + $reset)) {
        $previous[$key] = $State.Configuration[$key]
        if ($key -in $reset) { $State.Configuration[$key] = '' }
        else { $State.Configuration[$key] = $validated[$key] }
    }
    try { Save-ServiceState $State }
    catch { foreach ($key in $previous.Keys) { $State.Configuration[$key] = $previous[$key] }; throw }
}

function Write-ServiceOperationLog([string]$Operation, [bool]$Success) {
    if ($Operation -notin @('dependencies', 'keys', 'flash')) { return }
    try {
        $directory = Join-Path (Get-ServiceHome) 'logs'
        Assert-ServicePlainPath $directory
        if (-not (Test-Path -LiteralPath $directory)) { New-ServicePrivateDirectory $directory }
        $path = Join-Path $directory 'operations.jsonl'
        Assert-ServicePlainPath $path
        $entry = @{ utc = [DateTime]::UtcNow.ToString('o'); operation = $Operation; success = $Success } | ConvertTo-Json -Compress
        [IO.File]::AppendAllText($path, ($entry + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
        Set-ServicePrivateFile $path
    } catch { }
}

Export-ModuleMember -Function Get-ServiceHome, New-ServiceDraft, Read-ServiceState, Save-ServiceState, Get-ServicePorts, Test-ServiceDraft, Set-ServiceDraftValues, Write-ServiceOperationLog

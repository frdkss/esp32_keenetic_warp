Set-StrictMode -Version Latest

function Read-ServiceField([string]$Prompt, [string]$Default = '') {
    if ($Default) { $Prompt += " [$Default]" }
    $value = Read-Host $Prompt
    if ($null -eq $value -or $value -ceq ':cancel') { throw [OperationCanceledException]::new() }
    if ($value -ceq '' -and $Default) { return $Default }
    return $value
}

function Read-ServicePassword([string]$Prompt) {
    $secure = Read-Host "$Prompt (hidden, :cancel to cancel)" -AsSecureString
    if ($null -eq $secure) { throw [OperationCanceledException]::new() }
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        if ($plain -ceq ':cancel') { throw [OperationCanceledException]::new() }
        return $plain
    }
    finally {
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        $secure.Dispose()
    }
}

function Read-ServiceConfiguration {
    Write-Host 'No site list is supplied. Enter your URLs separated by spaces; :cancel cancels input.'
    return [ordered]@{
        WifiSsid = Read-ServiceField 'Wi-Fi SSID'
        WifiPassword = Read-ServicePassword 'Wi-Fi password (empty for open Wi-Fi)'
        RouterAddress = Read-ServiceField 'Router LAN IP or DNS address (without scheme/port)'
        RouterHttpsName = Read-ServiceField 'Router certificate HTTPS hostname (without scheme/port)'
        RouterPort = Read-ServiceField 'Router HTTPS port' '443'
        RouterLogin = Read-ServiceField 'Keenetic login'
        RouterPassword = Read-ServicePassword 'Keenetic password'
        WarpInterface = Read-ServiceField 'WARP interface (from router inspection)'
        TargetUrls = (Read-ServiceField 'Target HTTP/HTTPS URLs') -split '\s+'
        ControlUrls = (Read-ServiceField 'Control HTTP/HTTPS URLs routed without WARP') -split '\s+'
        CheckIntervalSeconds = Read-ServiceField 'Check interval, seconds' '60'
        ConnectTimeoutSeconds = Read-ServiceField 'Connect timeout, seconds' '5'
        ReadTimeoutSeconds = Read-ServiceField 'Read timeout, seconds' '5'
        DisablePauseSeconds = Read-ServiceField 'WARP disable/enable pause, seconds' '2'
        WarmupSeconds = Read-ServiceField 'Wait after WARP enable, seconds' '30'
        CooldownSeconds = Read-ServiceField 'Recovery cooldown, seconds' '300'
        ScheduleDay = Read-ServiceField 'Weekly day (0=Sunday ... 4=Thursday ... 6=Saturday)' '4'
        ScheduleTime = Read-ServiceField 'Weekly time (HH:mm)' '05:00'
        Timezone = Read-ServiceField 'POSIX timezone (default Moscow UTC+3, confirm or change)' 'MSK-3'
        EnableAutoRecovery = Read-ServiceField 'Enable automatic recovery (0/1)' '1'
        EnableWeeklyRestart = Read-ServiceField 'Enable weekly restart (0/1)' '1'
        OledEnabled = Read-ServiceField 'Enable OLED at runtime (0/1; requires OLED build and confirmed pins)' '0'
        FailureThreshold = Read-ServiceField 'Consecutive failed cycles before recovery (1..1000)' '5'
        TargetFailurePolicy = Read-ServiceField 'Target failure policy (0=any, 1=half, 2=majority, 3=all)' '2'
    }
}

Export-ModuleMember -Function Read-ServiceField, Read-ServicePassword, Read-ServiceConfiguration

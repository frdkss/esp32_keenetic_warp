Set-StrictMode -Version Latest

function Assert-ServiceText([object]$Value, [string]$Field, [int]$Maximum, [switch]$AllowEmpty) {
    if ($Value -isnot [string] -or $Value -match '[\x00-\x1f\x7f]' -or
        (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($Value))) {
        Stop-ServiceOperation "Invalid $Field (text required, no control characters)."
    }
    try { $size = [Text.UTF8Encoding]::new($false, $true).GetByteCount($Value) }
    catch { Stop-ServiceOperation "Invalid UTF-8 in $Field." }
    if ($size -gt $Maximum) { Stop-ServiceOperation "Invalid $Field (UTF-8 length exceeds $Maximum bytes)." }
}

function ConvertTo-ServiceInteger([object]$Value, [string]$Field, [int]$Minimum, [int]$Maximum) {
    $number = 0
    if ([string]$Value -notmatch '^[0-9]+$' -or -not [int]::TryParse([string]$Value, [ref]$number) -or
        $number -lt $Minimum -or $number -gt $Maximum) {
        Stop-ServiceOperation "Invalid $Field (integer $Minimum..$Maximum required)."
    }
    return $number
}

function ConvertTo-ServiceUrls([object]$Values, [string]$Field) {
    if ($Values -is [string] -or $null -eq $Values) { Stop-ServiceOperation "Invalid $Field (URL list required)." }
    $result = [Collections.Generic.List[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in $Values) {
        Assert-ServiceText $value $Field 512
        $uri = $null
        if ($value -ne $value.Trim() -or $value -match '[\s\\]' -or
            -not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -notin @('http', 'https') -or -not $uri.Host -or
            $uri.UserInfo -or $value -match '#' -or $uri.HostNameType -eq [UriHostNameType]::Unknown) {
            Stop-ServiceOperation "Invalid $Field (absolute HTTP/HTTPS URLs, no credentials or fragments)."
        }
        # URI canonicalizes scheme/host/default port; preserve case-sensitive path/query.
        $builder = [UriBuilder]::new($uri)
        $builder.Host = $uri.IdnHost.ToLowerInvariant()
        $canonical = $builder.Uri.AbsoluteUri
        Assert-ServiceText $canonical $Field 512
        if ($seen.Add($canonical)) { $result.Add($canonical) }
    }
    if ($result.Count -lt 1 -or $result.Count -gt 8) { Stop-ServiceOperation "Invalid $Field (1..8 unique URLs required)." }
    if ([Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $result.ToArray() -Compress)) -gt 3500) {
        Stop-ServiceOperation "Invalid $Field (URL list exceeds NVS string budget)."
    }
    return ,$result.ToArray()
}

function ConvertTo-ServiceConfiguration([System.Collections.IDictionary]$InputData) {
    $fields = @('WifiSsid', 'WifiPassword', 'RouterAddress', 'RouterHttpsName', 'RouterPort', 'RouterLogin',
        'RouterPassword', 'WarpInterface', 'TargetUrls', 'ControlUrls', 'CheckIntervalSeconds',
        'ConnectTimeoutSeconds', 'ReadTimeoutSeconds', 'DisablePauseSeconds', 'WarmupSeconds', 'CooldownSeconds',
        'ScheduleDay', 'ScheduleTime', 'Timezone', 'EnableAutoRecovery', 'EnableWeeklyRestart', 'OledEnabled')
    $optional = @('FailureThreshold', 'TargetFailurePolicy')
    if ($null -eq $InputData) { Stop-ServiceOperation 'Configuration fields are incomplete or unknown.' }
    foreach ($name in $InputData.Keys) {
        if ($name -notin $fields -and $name -notin $optional) { Stop-ServiceOperation 'Configuration fields are incomplete or unknown.' }
    }
    foreach ($field in $fields) {
        if (-not $InputData.Contains($field)) { Stop-ServiceOperation "Missing configuration field: $field." }
    }
    $out = [ordered]@{}
    foreach ($spec in @(@('WifiSsid',32), @('WifiPassword',64), @('RouterLogin',128), @('RouterPassword',256),
        @('RouterAddress',253), @('RouterHttpsName',253), @('WarpInterface',32), @('Timezone',128), @('ScheduleTime',5))) {
        $field = $spec[0]
        Assert-ServiceText $InputData[$field] $field $spec[1] -AllowEmpty:($field -eq 'WifiPassword')
        $out[$field] = $InputData[$field]
    }
    $wifiLength = [Text.Encoding]::UTF8.GetByteCount($out.WifiPassword)
    if ($wifiLength -ne 0 -and ($wifiLength -lt 8 -or
        ($wifiLength -eq 64 -and $out.WifiPassword -notmatch '^[0-9a-fA-F]{64}$'))) {
        Stop-ServiceOperation 'Invalid WifiPassword (empty, 8..63 UTF-8 bytes, or 64 hex digits required).'
    }
    foreach ($hostField in @('RouterAddress', 'RouterHttpsName')) {
        $hostValue = $out[$hostField]
        if ($hostValue -ne $hostValue.Trim() -or $hostValue -match '[^a-zA-Z0-9.:-]' -or
            [Uri]::CheckHostName($hostValue) -eq [UriHostNameType]::Unknown) {
            Stop-ServiceOperation "Invalid $hostField (IP or ASCII/punycode hostname required)."
        }
    }
    if ($out.WarpInterface -notmatch '^[a-zA-Z][a-zA-Z0-9_-]{0,31}$') { Stop-ServiceOperation 'Invalid WarpInterface.' }
    if ($out.ScheduleTime -notmatch '^(?:[01][0-9]|2[0-3]):[0-5][0-9]$') { Stop-ServiceOperation 'Invalid ScheduleTime (HH:mm required).' }
    # Validate the POSIX TZ grammar supported by ESP-IDF/newlib, including DST rules.
    $tzName = '(?:[A-Za-z]{3,}|<[A-Za-z0-9+\-]{3,}>)'
    $tzOffset = '[+\-]?(?:[0-9]|1[0-9]|2[0-4])(?::[0-5][0-9](?::[0-5][0-9])?)?'
    $tzRule = '(?:M(?:[1-9]|1[0-2])\.[1-5]\.[0-6]|J(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|3[0-5][0-9]|36[0-5])|(?:[0-9]|[1-9][0-9]|[12][0-9]{2}|3[0-5][0-9]|36[0-5]))(?:/(?:[0-9]|1[0-9]|2[0-4])(?::[0-5][0-9](?::[0-5][0-9])?)?)?'
    if ($out.Timezone -cnotmatch "^$tzName$tzOffset(?:$tzName(?:$tzOffset)?,$tzRule,$tzRule)?`$") {
        Stop-ServiceOperation 'Invalid Timezone (POSIX TZ required, for example MSK-3).'
    }
    $out.RouterPort = ConvertTo-ServiceInteger $InputData.RouterPort 'RouterPort' 1 65535
    $out.ScheduleDay = ConvertTo-ServiceInteger $InputData.ScheduleDay 'ScheduleDay' 0 6
    foreach ($field in @('CheckIntervalSeconds', 'CooldownSeconds')) {
        $out[$field] = ConvertTo-ServiceInteger $InputData[$field] $field 1 86400
    }
    foreach ($field in @('ConnectTimeoutSeconds', 'ReadTimeoutSeconds')) {
        $out[$field] = ConvertTo-ServiceInteger $InputData[$field] $field 1 60
    }
    foreach ($field in @('DisablePauseSeconds', 'WarmupSeconds')) {
        $out[$field] = ConvertTo-ServiceInteger $InputData[$field] $field 1 3600
    }
    foreach ($field in @('EnableAutoRecovery', 'EnableWeeklyRestart', 'OledEnabled')) {
        $out[$field] = ConvertTo-ServiceInteger $InputData[$field] $field 0 1
    }
    $out.TargetUrls = ConvertTo-ServiceUrls $InputData.TargetUrls 'TargetUrls'
    $out.ControlUrls = ConvertTo-ServiceUrls $InputData.ControlUrls 'ControlUrls'
    foreach ($url in $out.TargetUrls) {
        if ($out.ControlUrls -ccontains $url) { Stop-ServiceOperation 'TargetUrls and ControlUrls must not overlap.' }
    }
    $out.FailureThreshold = if ($InputData.Contains('FailureThreshold')) {
        ConvertTo-ServiceInteger $InputData.FailureThreshold 'FailureThreshold' 1 1000
    } else { 5 }
    $out.TargetFailurePolicy = if ($InputData.Contains('TargetFailurePolicy')) {
        ConvertTo-ServiceInteger $InputData.TargetFailurePolicy 'TargetFailurePolicy' 0 3
    } else { 2 }
    return $out
}

Export-ModuleMember -Function ConvertTo-ServiceConfiguration

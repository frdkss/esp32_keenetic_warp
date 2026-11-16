Set-StrictMode -Version Latest

function ConvertTo-ServiceCppString([string]$Value) {
    # Fixed-width octal UTF-8 bytes avoid greedy \x escapes and source code injection.
    $builder = [Text.StringBuilder]::new('"')
    foreach ($byte in [Text.UTF8Encoding]::new($false, $true).GetBytes($Value)) {
        if ($byte -eq 34) { [void]$builder.Append('\"') }
        elseif ($byte -eq 92) { [void]$builder.Append('\\') }
        elseif ($byte -ge 32 -and $byte -le 126) { [void]$builder.Append([char]$byte) }
        else { [void]$builder.Append('\' + [Convert]::ToString($byte, 8).PadLeft(3, '0')) }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Get-ServiceConfigHeader($Configuration) {
    $lines = [Collections.Generic.List[string]]::new()
    $lines.AddRange([string[]]@('#pragma once', '// Generated public settings. Contains no Wi-Fi/router credentials.',
        '#include <array>', '#include <cstdint>', 'namespace warp::config {', 'inline constexpr std::uint32_t schemaVersion = 2;'))
    foreach ($field in @('RouterAddress', 'RouterHttpsName', 'WarpInterface', 'Timezone', 'ScheduleTime')) {
        $name = $field.Substring(0, 1).ToLowerInvariant() + $field.Substring(1)
        $lines.Add("inline constexpr char ${name}[] = $(ConvertTo-ServiceCppString $Configuration[$field]);")
    }
    foreach ($field in @('RouterPort', 'ScheduleDay', 'FailureThreshold', 'TargetFailurePolicy', 'CheckIntervalSeconds',
        'ConnectTimeoutSeconds', 'ReadTimeoutSeconds', 'DisablePauseSeconds', 'WarmupSeconds', 'CooldownSeconds')) {
        $name = $field.Substring(0, 1).ToLowerInvariant() + $field.Substring(1)
        $lines.Add("inline constexpr std::uint32_t $name = $($Configuration[$field]);")
    }
    foreach ($field in @('EnableAutoRecovery', 'EnableWeeklyRestart', 'OledEnabled')) {
        $name = $field.Substring(0, 1).ToLowerInvariant() + $field.Substring(1)
        $value = if ($Configuration[$field]) { 'true' } else { 'false' }
        $lines.Add("inline constexpr bool $name = $value;")
    }
    foreach ($field in @('TargetUrls', 'ControlUrls')) {
        $name = $field.Substring(0, 1).ToLowerInvariant() + $field.Substring(1)
        $items = @($Configuration[$field] | ForEach-Object { ConvertTo-ServiceCppString $_ }) -join ', '
        $lines.Add("inline constexpr std::array<const char*, $($Configuration[$field].Count)> $name = {{$items}};")
    }
    $lines.Add('}  // namespace warp::config')
    return ($lines -join "`n") + "`n"
}

function Get-ServiceSecretsHeader($Configuration) {
    $lines = [Collections.Generic.List[string]]::new()
    $lines.AddRange([string[]]@('#pragma once', '// LOCAL PROVISIONING INPUT. Never include in ordinary firmware.',
        '#if !defined(WARP_PROVISIONING_SECRETS) || WARP_PROVISIONING_SECRETS != 1',
        '#error service_secrets.h is only for an explicitly selected provisioning tool', '#endif',
        'namespace warp::provisioning {'))
    foreach ($field in @('WifiSsid', 'WifiPassword', 'RouterLogin', 'RouterPassword')) {
        $name = $field.Substring(0, 1).ToLowerInvariant() + $field.Substring(1)
        $lines.Add("inline constexpr char ${name}[] = $(ConvertTo-ServiceCppString $Configuration[$field]);")
    }
    $lines.Add('}  // namespace warp::provisioning')
    return ($lines -join "`n") + "`n"
}

function Install-ServiceArtifact([string]$Source, [string]$Destination, [string]$Backup) {
    if ([IO.File]::Exists($Destination)) { [IO.File]::Replace($Source, $Destination, $Backup) }
    else { [IO.File]::Move($Source, $Destination) }
}

function Write-ServiceArtifacts([string]$Root, $Configuration, $Tools, [string]$NvsKeyFile) {
    # Revalidate at this public mutation boundary before creating or replacing files.
    $raw = [ordered]@{}
    foreach ($field in $Configuration.Keys) {
        $raw[$field] = $Configuration[$field]
    }
    $checked = ConvertTo-ServiceConfiguration $raw
    $base = Join-Path $Root '.local/service'
    $include = Join-Path $Root 'include'
    Assert-ServicePlainPath $base
    foreach ($path in @((Join-Path $base 'configure.lock'), (Join-Path $base 'nvs.encrypted.bin'),
        (Join-Path $include 'config.h'), (Join-Path $include 'service_secrets.h'))) {
        Assert-ServicePlainPath $path
    }
    [void][IO.Directory]::CreateDirectory($base)
    $lock = $null
    $stage = $null
    $installed = [Collections.Generic.List[object]]::new()
    try {
        try { $lock = [IO.File]::Open((Join-Path $base 'configure.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
        catch { Stop-ServiceOperation 'Another configuration operation is running, or the service directory is not writable.' }
        $stage = Join-Path $base ('.pending-' + [Guid]::NewGuid().ToString('N'))
        New-ServicePrivateDirectory $stage
        Write-ServiceUtf8 (Join-Path $stage 'config.h') (Get-ServiceConfigHeader $checked)
        Write-ServiceUtf8 (Join-Path $stage 'service_secrets.h') (Get-ServiceSecretsHeader $checked)
        $request = Join-Path $stage 'request.json'
        Write-ServiceUtf8 $request (ConvertTo-Json -InputObject $checked -Depth 5 -Compress)
        Invoke-ServicePython $Tools.Python @($Tools.Helper, 'encrypt', '--idf-path', $Tools.Idf,
            '--request', $request, '--key', $NvsKeyFile, '--output', (Join-Path $stage 'nvs.encrypted.bin'),
            '--partitions', (Join-Path $Root 'partitions.csv'))
        [IO.File]::Delete($request)
        [void][IO.Directory]::CreateDirectory($include)
        foreach ($item in @(@('config.h', $include), @('service_secrets.h', $include), @('nvs.encrypted.bin', $base))) {
            $destination = Join-Path $item[1] $item[0]
            $backup = Join-Path $stage ($item[0] + '.backup')
            $existed = [IO.File]::Exists($destination)
            $originalAcl = if ($existed) { [IO.File]::GetAccessControl($destination) } else { $null }
            Install-ServiceArtifact (Join-Path $stage $item[0]) $destination $backup
            $installed.Add([pscustomobject]@{ Path = $destination; Backup = $backup; Existed = $existed; Acl = $originalAcl })
            if ($item[0] -ne 'config.h') { Set-ServicePrivateFile $destination }
        }
    }
    catch {
        # Recover all already replaced files, including when the last replacement fails.
        $rollbackFailed = $false
        for ($index = $installed.Count - 1; $index -ge 0; $index--) {
            $item = $installed[$index]
            try {
                if ($item.Existed) {
                    [IO.File]::Replace($item.Backup, $item.Path, [NullString]::Value)
                    [IO.File]::SetAccessControl($item.Path, $item.Acl)
                }
                else { [IO.File]::Delete($item.Path) }
            }
            catch { $rollbackFailed = $true }
        }
        if ($rollbackFailed) {
            # Retain private backups for manual recovery; never remove the only copy.
            $stage = $null
            Stop-ServiceOperation 'File rollback failed. Private backups were retained in .local/service/.pending-*; recover them before continuing.'
        }
        throw
    }
    finally {
        try {
            if ($stage -and [IO.Directory]::Exists($stage)) {
                # Delete only the verified, task-created directory inside this root.
                $full = [IO.Path]::GetFullPath($stage)
                $prefix = [IO.Path]::GetFullPath($base).TrimEnd('\') + '\.pending-'
                if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid staging cleanup path' }
                Remove-Item -LiteralPath $full -Recurse -Force
            }
        }
        finally {
            if ($null -ne $lock) { $lock.Dispose() }
            $checked = $null
        }
    }
}

Export-ModuleMember -Function Write-ServiceArtifacts

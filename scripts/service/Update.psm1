Set-StrictMode -Version Latest

function Invoke-ServiceUpdate([string]$Root, $Tools, [string]$KeyStore, [string]$PackageDirectory,
                             [string]$Port, [int]$TimeoutSeconds = 180, [switch]$Prepare, [switch]$ApplyConfiguration) {
    if (-not $KeyStore -or -not $PackageDirectory) {
        Stop-ServiceOperation 'PrepareUpdate/Update require -KeyStore and -PackageDirectory. No device operation was attempted.'
    }
    if (-not $Prepare -and $Port -notmatch '^COM[1-9][0-9]*$') {
        Stop-ServiceOperation 'Update requires -Port COM<number> for the running protected application.'
    }
    $mode = 'update'
    if ($Prepare) { $mode = 'prepare' }
    $nativeArguments = @((Join-Path $Root 'scripts/secure_update.py'), $mode,
        '--vault', $KeyStore, '--package', $PackageDirectory, '--idf-path', $Tools.Idf,
        '--timeout', $TimeoutSeconds.ToString())
    if ($Prepare) { $nativeArguments += @('--environment', $Tools.Environment) }
    else { $nativeArguments += @('--port', $Port) }
    if ($Prepare -and $ApplyConfiguration) { $nativeArguments += @('--nvs', (Join-Path $Root '.local/service/nvs.encrypted.bin')) }
    $stage = if ($Prepare) { 'Подготовка пакета прошивки' } else { 'Защищённое обновление' }
    $result = Invoke-ServiceEventTool $Tools.Python $nativeArguments $stage ([Math]::Max(300, $TimeoutSeconds * 3))
    if (-not (Test-ServiceProgressUI)) { Write-Host (ConvertTo-Json -InputObject $result -Compress) }
}

Export-ModuleMember -Function Invoke-ServiceUpdate

Set-StrictMode -Version Latest

function Invoke-ServiceProvisioning([string]$PackageDirectory, [string]$Root, $Tools,
    [string]$KeyStore, [string]$BackupFile, [string]$Port, [string]$RequestFile,
    [string]$Confirmation, [int]$TimeoutSeconds = 180) {
    if (-not $PackageDirectory) {
        Stop-ServiceOperation 'stage 4: PrepareProvision and explicit device confirmation are required. No flash/eFuse operation was attempted.'
    }
    Assert-ServicePlainPath $PackageDirectory
    $path = Join-Path $PackageDirectory 'plan.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Stop-ServiceOperation 'No protection plan found. Run PrepareProvision first.' }
    if (-not $Root -or -not $Tools -or -not $KeyStore -or -not $BackupFile -or -not $Port -or -not $RequestFile -or -not $Confirmation) {
        Stop-ServiceOperation 'Initial protection requires live device identity, matching keys and recovered backup. No flash/eFuse operation was attempted.'
    }
    $arguments = @((Join-Path $Root 'scripts/secure_provision.py'), '--package', $PackageDirectory,
        '--vault', $KeyStore, '--backup', $BackupFile, '--request', $RequestFile, '--port', $Port,
        '--confirm-device', $Confirmation, '--idf-path', $Tools.Idf, '--timeout', $TimeoutSeconds.ToString())
    return Invoke-ServiceEventTool $Tools.Python $arguments 'Первичная защищённая прошивка' 3600
}

function Invoke-ServiceProvisionVerification([string]$Root, $Tools, [string]$KeyStore, [string]$Port, [int]$TimeoutSeconds = 300) {
    return Invoke-ServiceEventTool $Tools.Python @((Join-Path $Root 'scripts/secure_provision.py'),
        '--verify-existing', '--vault', $KeyStore, '--port', $Port, '--idf-path', $Tools.Idf,
        '--timeout', $TimeoutSeconds.ToString()) 'Проверка уже записанной прошивки' ([Math]::Max(300, $TimeoutSeconds * 2))
}

Export-ModuleMember -Function Invoke-ServiceProvisioning, Invoke-ServiceProvisionVerification

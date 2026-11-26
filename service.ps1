#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Configure', 'Inspect', 'InspectProtection', 'NewNvsKey', 'NewDeviceKeys', 'BackupKeys', 'RestoreKeys', 'PrepareProvision', 'Provision', 'VerifyProvision', 'PrepareUpdate', 'Update', 'DiscoverWifi', 'WifiUpdate', 'Help')]
    [string]$Action = 'Menu',
    [string]$Port,
    [string]$NvsKeyFile,
    [string]$KeyStore,
    [string]$BackupFile,
    [string]$EvidenceFile,
    [string]$PackageDirectory,
    [ValidateSet('c3-production-no-oled', 'c3-production-oled')]
    [string]$Environment = 'c3-production-no-oled',
    [string]$PythonPath,
    [string]$IdfPath,
    [switch]$ApplyConfiguration,
    [string]$ConfirmDevice,
    [ValidateRange(15, 900)] [int]$TimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
foreach ($module in @('Common', 'Input', 'Validation', 'Keys', 'Generation', 'Device', 'Processes', 'State', 'Console', 'Dependencies', 'Router', 'Provisioning', 'Update', 'Workflow', 'Menu')) {
    Import-Module (Join-Path $PSScriptRoot "scripts/service/$module.psm1") -Force -DisableNameChecking
}

try {
    switch ($Action) {
        'Menu' { Assert-ServiceConsole; [void](Invoke-ServiceElevation $PSCommandPath); Start-ServiceMenu $PSScriptRoot }
        'Help' { Show-ServiceHelp }
        'Configure' {
            $inputData = Read-ServiceConfiguration
            $configuration = ConvertTo-ServiceConfiguration $inputData
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            if ($KeyStore -and $NvsKeyFile) { Stop-ServiceOperation 'Select either -KeyStore or the legacy -NvsKeyFile.' }
            if ($KeyStore) { Write-ServiceConfigurationFromVault $PSScriptRoot $configuration $tools $KeyStore }
            else {
                if (-not $NvsKeyFile) { $NvsKeyFile = Read-ServiceField 'Existing NVS key file (outside repository)' }
                $key = Resolve-ServiceNvsKey $PSScriptRoot $NvsKeyFile
                Write-ServiceArtifacts $PSScriptRoot $configuration $tools $key
            }
            Write-Host 'Generated include/config.h, include/service_secrets.h and .local/service/nvs.encrypted.bin.'
        }
        'Inspect' {
            if (-not $Port) { $Port = Read-ServiceField 'Serial port, for example COM4 (inspection resets the board)' }
            Invoke-ServiceInspection $PSScriptRoot $Port $PythonPath
        }
        'NewNvsKey' {
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            if (-not $NvsKeyFile) { $NvsKeyFile = Read-ServiceField 'New NVS key file (outside repository)' }
            New-ServiceNvsKey $PSScriptRoot $NvsKeyFile $tools
            Write-Host 'Created a standalone NVS key. For a bound protected device use NewDeviceKeys and Configure -KeyStore.'
        }
        'InspectProtection' {
            if (-not $Port -or -not $EvidenceFile) { Stop-ServiceOperation 'InspectProtection requires -Port and a new -EvidenceFile. Inspection resets into ROM download mode.' }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            Invoke-ServicePython $tools.Python @((Join-Path $PSScriptRoot 'scripts/security_device.py'), '--port', $Port, '--output', $EvidenceFile)
            Write-Host 'Read-only protection evidence saved. Device remains in ROM download mode; press RESET to resume its existing application.'
        }
        'NewDeviceKeys' {
            if (-not $KeyStore -or -not $EvidenceFile) { Stop-ServiceOperation 'NewDeviceKeys requires a new -KeyStore directory outside the repository and -EvidenceFile from InspectProtection.' }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            Invoke-ServiceSecurityTool $PSScriptRoot $tools @('new', '--vault', $KeyStore, '--evidence', $EvidenceFile)
            Write-Host 'Created device-bound Flash/NVS keys and a separate RSA-3072 signing key in a CurrentUser DPAPI vault.'
            Write-Host 'Loss of the Flash or signing key can prevent further USB updates. Create and restore a portable backup before preparation.'
        }
        'BackupKeys' {
            if (-not $KeyStore -or -not $BackupFile) { Stop-ServiceOperation 'BackupKeys requires -KeyStore and a new -BackupFile outside the repository and vault.' }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            Invoke-ServiceSecurityTool $PSScriptRoot $tools @('backup', '--vault', $KeyStore, '--backup', $BackupFile) -WithPassphrase -ConfirmPassphrase
            Write-Host 'Encrypted portable backup created and decrypted for comparison. Keep it on an independent protected medium and retain its passphrase separately.'
        }
        'RestoreKeys' {
            if (-not $KeyStore -or -not $BackupFile) { Stop-ServiceOperation 'RestoreKeys requires a new -KeyStore outside the repository and an existing -BackupFile.' }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            Invoke-ServiceSecurityTool $PSScriptRoot $tools @('restore', '--vault', $KeyStore, '--backup', $BackupFile) -WithPassphrase
            Write-Host 'Backup restored into a new CurrentUser DPAPI vault. Existing vaults are never overwritten.'
        }
        'PrepareProvision' {
            if (-not $KeyStore -or -not $BackupFile -or -not $EvidenceFile -or -not $PackageDirectory) {
                Stop-ServiceOperation 'PrepareProvision requires -KeyStore, -BackupFile, -EvidenceFile and a new -PackageDirectory. Build the selected production environment and Configure -KeyStore first.'
            }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            Invoke-ServiceSecurityTool $PSScriptRoot $tools @('prepare', '--vault', $KeyStore, '--backup', $BackupFile,
                '--evidence', $EvidenceFile, '--output', $PackageDirectory, '--environment', $Environment) -WithPassphrase
            Write-Host 'Recovered backup keys, verified signatures and encryption roundtrips. Signed package prepared; live checks and explicit device confirmation are required for Provision.'
        }
        'Provision' {
            if (-not $KeyStore -or -not $BackupFile -or -not $Port) { Invoke-ServiceProvisioning $PackageDirectory }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            $base = Join-Path $PSScriptRoot '.local/service'
            Assert-ServicePlainPath $base
            [void][IO.Directory]::CreateDirectory($base)
            $stage = Join-Path $base ('.provision-cli-' + [Guid]::NewGuid().ToString('N'))
            New-ServicePrivateDirectory $stage
            try {
                $passphrase = Read-ServicePassword 'Portable backup passphrase'
                $request = Join-Path $stage 'request.secrets.json'
                Write-ServiceUtf8 $request (ConvertTo-Json -InputObject @{ passphrase = $passphrase } -Compress)
                if (-not $ConfirmDevice) { $ConfirmDevice = Read-ServiceField 'Type the exact device MAC from the package plan to authorize irreversible initial protection' }
                $result = Invoke-ServiceProvisioning $PackageDirectory $PSScriptRoot $tools $KeyStore $BackupFile $Port $request $ConfirmDevice $TimeoutSeconds
                Write-Host (ConvertTo-Json -InputObject $result -Compress)
            }
            finally {
                $passphrase = $null
                Assert-ServicePlainPath $stage
                if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($stage)) -cne [IO.Path]::GetFullPath($base)) { Stop-ServiceOperation 'Invalid CLI staging cleanup path.' }
                Remove-Item -LiteralPath $stage -Recurse -Force
            }
        }
        'VerifyProvision' {
            if (-not $KeyStore -or -not $Port) { Stop-ServiceOperation 'VerifyProvision requires -KeyStore and -Port. No flash/eFuse write is performed.' }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            [void](Invoke-ServiceProvisionVerification $PSScriptRoot $tools $KeyStore $Port $TimeoutSeconds)
            Write-Host 'Existing protection, firmware, configuration and monitoring verified. No flash/eFuse writes performed.'
        }
        'PrepareUpdate' {
            if (-not $KeyStore -or -not $PackageDirectory) { Stop-ServiceOperation 'PrepareUpdate requires -KeyStore and a new -PackageDirectory. Build the selected production environment first.' }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            $tools | Add-Member -NotePropertyName Environment -NotePropertyValue $Environment
            Invoke-ServiceUpdate $PSScriptRoot $tools $KeyStore $PackageDirectory -Prepare -ApplyConfiguration:$ApplyConfiguration
        }
        'Update' {
            if (-not $KeyStore -or -not $PackageDirectory -or -not $Port) { Stop-ServiceOperation 'Update requires -KeyStore, -PackageDirectory and -Port. No device operation was attempted.' }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            Invoke-ServiceUpdate $PSScriptRoot $tools $KeyStore $PackageDirectory $Port $TimeoutSeconds
        }
        'DiscoverWifi' {
            if (-not $KeyStore) { Stop-ServiceOperation 'DiscoverWifi requires -KeyStore. No network request was sent.' }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            $found = Invoke-ServiceWifiDiscover $PSScriptRoot $tools $KeyStore 15
            Write-Host (ConvertTo-Json -InputObject $found -Depth 5 -Compress)
        }
        'WifiUpdate' {
            if (-not $KeyStore -or -not $PackageDirectory) { Stop-ServiceOperation 'WifiUpdate requires -KeyStore and -PackageDirectory. No network operation was attempted.' }
            $tools = Resolve-ServiceTools $PSScriptRoot $PythonPath $IdfPath
            [void](Invoke-ServiceWifiUpdate $PSScriptRoot $tools $KeyStore $PackageDirectory $TimeoutSeconds)
            Write-Host 'Wi-Fi update staged and the new slot was verified by authenticated discovery.'
        }
    }
}
catch [System.OperationCanceledException] {
    Write-Host 'Cancelled. Configuration files were not changed.'
    exit 2
}
catch {
    # Never render ErrorRecord/InvocationInfo: they may contain input or source text.
    $safeMessage = Get-ServiceSafeError $_.Exception
    [Console]::Error.WriteLine($safeMessage)
    exit 1
}
finally {
    $inputData = $null
    $configuration = $null
}

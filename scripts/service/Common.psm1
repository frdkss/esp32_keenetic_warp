Set-StrictMode -Version Latest

function Stop-ServiceOperation([string]$Message) {
    $error = [System.InvalidOperationException]::new($Message)
    $error.Data['ServiceSafe'] = $true
    throw $error
}

function Get-ServiceSafeError([Exception]$Exception) {
    if ($Exception.Data.Contains('ServiceSafe')) { return $Exception.Message }
    return 'Service operation failed. No sensitive diagnostics are printed.'
}

function New-ServicePrivateDirectory([string]$Path) {
    # Windows only (PowerShell 5.1). Set ACL at creation, before writing secrets.
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    if ([IO.Directory]::Exists($Path)) {
        # Do not silently tighten permissions of an existing owner key directory.
        Stop-ServiceOperation 'Private staging directory already exists.'
    }
    [void][IO.Directory]::CreateDirectory($Path, $acl)
}

function Assert-ServicePlainPath([string]$Path) {
    $part = [IO.Path]::GetFullPath($Path)
    while ($part) {
        if (Test-Path -LiteralPath $part) {
            if ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                Stop-ServiceOperation 'Reparse points are not supported in service output and key paths.'
            }
        }
        $part = [IO.Path]::GetDirectoryName($part)
    }
}

function Write-ServiceUtf8([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false, $true))
}

function Set-ServicePrivateFile([string]$Path) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'Allow'))
    [IO.File]::SetAccessControl($Path, $acl)
}

function Invoke-ServicePython([string]$Python, [string[]]$Arguments) {
    # Only file paths and fixed options cross the process boundary. Never passwords.
    try {
        & $Python @Arguments 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Native tool failed' }
    }
    catch { Stop-ServiceOperation 'Python tool failed. Check the pinned service dependencies, SDK and input files.' }
}

function Resolve-ServiceTools([string]$Root, [string]$PythonPath, [string]$IdfPath) {
    if (-not $PythonPath) { $PythonPath = Join-Path $Root '.local/service-tools/Scripts/python.exe' }
    if (-not $IdfPath) {
        $pioRoot = $env:PLATFORMIO_CORE_DIR
        if (-not $pioRoot) { $pioRoot = Join-Path $env:USERPROFILE '.platformio' }
        $IdfPath = Join-Path $pioRoot 'packages/framework-espidf'
    }
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        Stop-ServiceOperation 'Service Python is missing. Create .local/service-tools and install scripts/service-requirements.txt.'
    }
    $versionFile = Join-Path $IdfPath 'version.txt'
    if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf) -or
        [IO.File]::ReadAllText($versionFile).Trim() -ne '5.5.5') {
        Stop-ServiceOperation 'Service requires the pinned ESP-IDF 5.5.5 package.'
    }
    $generator = Join-Path $IdfPath 'components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py'
    if (-not (Test-Path -LiteralPath $generator -PathType Leaf)) { Stop-ServiceOperation 'ESP-IDF NVS generator is missing.' }
    $helper = Join-Path $Root 'scripts/service_nvs.py'
    Invoke-ServicePython $PythonPath @($helper, 'check', '--idf-path', $IdfPath)
    return [pscustomobject]@{ Python = $PythonPath; Idf = $IdfPath; Helper = $helper }
}

function Show-ServiceHelp {
    Write-Host @'
PowerShell 5.1+ service actions:
  .\service.ps1
    Interactive SERVICE menu; restarts as administrator (Windows UAC applies).
  .\service.ps1 -Action Configure -NvsKeyFile <existing-private-file>
    Interactive settings, two headers and encrypted NVS. No device access.
    Enter :cancel at any prompt, or press Ctrl+C, to cancel input.
  .\service.ps1 -Action NewNvsKey -NvsKeyFile <new-file-outside-repository>
    Create only an NVS XTS key partition with the official ESP-IDF tool.
  .\service.ps1 -Action Inspect -Port COM4 [-PythonPath <diagnostics-python>]
    Read identity/security flags with scripts/inspect_board.py; resets the board.
  .\service.ps1 -Action InspectProtection -Port COM4 -EvidenceFile <new-json>
    Read measured identity, security flags and emptiness of key blocks 0/1.
    Resets into ROM download mode, no flash/eFuse writes. RESET resumes app.
  .\service.ps1 -Action NewDeviceKeys -KeyStore <new-external-directory> -EvidenceFile <json>
    Unique Flash/NVS keys and separate RSA-3072 signing key; CurrentUser DPAPI.
  .\service.ps1 -Action BackupKeys -KeyStore <directory> -BackupFile <new-external-file>
    Portable scrypt/AES-GCM backup; hidden passphrase, no overwrite.
  .\service.ps1 -Action RestoreKeys -KeyStore <new-external-directory> -BackupFile <file>
    Restore onto this Windows account. Keep backup on independent media.
  .\service.ps1 -Action Configure -KeyStore <directory>
    Generate encrypted Wi-Fi/router settings with this device's NVS key.
  .\service.ps1 -Action PrepareProvision -KeyStore <directory> -BackupFile <file> -EvidenceFile <json> -PackageDirectory <new-directory>
    Offline signature/encryption rehearsal with RECOVERED keys; creates plan.
    Optional -Environment c3-production-oled; default c3-production-no-oled.
  .\service.ps1 -Action Provision -PackageDirectory <directory> -KeyStore <directory> -BackupFile <file> -Port COM4
    Explicit initial protection; hidden backup passphrase and typed device MAC.
    Requires pristine supported hardware, signed package and recovered keys.
    A failed initial attempt is recorded and is never automatically resumed.
    Without all required inputs no flash/eFuse operation is attempted.
  .\service.ps1 -Action VerifyProvision -KeyStore <directory> -Port COM4
    Verify an interrupted Secure Download/boot confirmation using its signed
    initial package and existing receipt. Resets the existing app; no flash/eFuse writes.
  .\service.ps1 -Action PrepareUpdate -KeyStore <directory> -PackageDirectory <new-directory>
    Offline: validate production build, sign v2, then encrypt for this device.
    Optional -Environment c3-production-oled. No device access.
    -ApplyConfiguration includes the current encrypted NVS in the signed package.
  .\service.ps1 -Action Update -KeyStore <directory> -PackageDirectory <directory> -Port COM4
    Requires a RUNNING protected app with the stage 9 USB probe. Authenticates
    identity/keys and enters secure ROM. Default packages write only the application slot
    the device reports (ota_0 or ota_1); the OTA selector is left unchanged.
    Packages prepared with -ApplyConfiguration also apply encrypted NVS settings
    after authenticated maintenance lock, preserving the consumed schedule date.
    Keys/bootloader/table preserved. No eFuse writes or whole-chip erase.
    Verifies exact running image and a completed monitoring cycle afterwards.
    Optional -TimeoutSeconds 180 (15..900). On BOOT/RESET failure no retry:
    release BOOT and press RESET; never use a generic forced upload.
  .\service.ps1 -Action DiscoverWifi -KeyStore <directory>
    Broadcasts a signed LAN discovery request and lists authenticated devices
    (MAC, slot, app digest). Sends no firmware and writes nothing to the device.
  .\service.ps1 -Action WifiUpdate -KeyStore <directory> -PackageDirectory <directory>
    Pushes a PrepareUpdate package to the device's inactive OTA slot over pinned HTTPS,
    then requires authenticated discovery to report the new slot running. Packages
    with configuration/migration are rejected here; use -Action Update over USB.
    Optional -TimeoutSeconds 180 (15..900). Devices built before the OTA layout must
    first be migrated once over USB.

Configure/NewNvsKey use .local/service-tools/Scripts/python.exe by default.
Bootstrap: python -m venv .local/service-tools
  .local/service-tools/Scripts/python.exe -m pip install -r scripts/service-requirements.txt
Security actions additionally require scripts/security-requirements.txt.
Override tool locations with -PythonPath and -IdfPath (ESP-IDF 5.5.5).
Generated headers/NVS are local provisioning inputs. Ordinary updates preserve
settings; Configure only prepares a separate NVS artifact and never writes it.
Update cannot initialize protection or recover a non-running protected app.
Physical protected USB/BOOT/RESET acceptance is still required.
'@
}

Export-ModuleMember -Function Stop-ServiceOperation, Get-ServiceSafeError, New-ServicePrivateDirectory, Assert-ServicePlainPath, Set-ServicePrivateFile, Write-ServiceUtf8, Invoke-ServicePython, Resolve-ServiceTools, Show-ServiceHelp

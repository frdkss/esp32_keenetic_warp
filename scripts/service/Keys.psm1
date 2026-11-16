Set-StrictMode -Version Latest

function Get-ServiceExternalKeyPath([string]$Root, [string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^(?:[a-zA-Z]:[\\/]|\\\\[^\\]+\\[^\\]+\\)') {
        Stop-ServiceOperation 'An absolute NVS key path outside the repository is required.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::GetExtension($full) -ine '.bin') { Stop-ServiceOperation 'NVS key file must have a .bin extension.' }
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if ($full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        Stop-ServiceOperation 'NVS keys must be stored outside the repository.'
    }
    Assert-ServicePlainPath $full
    return $full
}

function Resolve-ServiceNvsKey([string]$Root, [string]$Path) {
    $full = Get-ServiceExternalKeyPath $Root $Path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf) -or (Get-Item -LiteralPath $full).Length -ne 4096) {
        Stop-ServiceOperation 'An existing 4096-byte ESP-IDF NVS key partition is required. Use NewNvsKey separately.'
    }
    return $full
}

function New-ServiceNvsKey([string]$Root, [string]$Path, $Tools) {
    $full = Get-ServiceExternalKeyPath $Root $Path
    if (Test-Path -LiteralPath $full) { Stop-ServiceOperation 'NVS key already exists; it will not be overwritten.' }
    $parent = [IO.Path]::GetDirectoryName($full)
    if (-not [IO.Directory]::Exists($parent)) { Stop-ServiceOperation 'Create the owner key directory outside the repository first.' }
    $stage = Join-Path $parent ('.nvs-key-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-ServicePrivateDirectory $stage
        $temporary = Join-Path $stage 'nvs-key.bin'
        Invoke-ServicePython $Tools.Python @($Tools.Helper, 'key', '--idf-path', $Tools.Idf, '--key', $temporary)
        Set-ServicePrivateFile $temporary
        # Same-volume move preserves the private staging ACL; Move never overwrites.
        [IO.File]::Move($temporary, $full)
    }
    finally {
        $prefix = [IO.Path]::GetFullPath($parent).TrimEnd('\') + '\.nvs-key-'
        if ([IO.Directory]::Exists($stage) -and $stage.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
    }
}

function Invoke-ServiceSecurityTool([string]$Root, $Tools, [string[]]$Arguments, [switch]$WithPassphrase, [switch]$ConfirmPassphrase) {
    $base = Join-Path $Root '.local/service'
    Assert-ServicePlainPath $base
    [void][IO.Directory]::CreateDirectory($base)
    $stage = Join-Path $base ('.security-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-ServicePrivateDirectory $stage
        $nativeArguments = @((Join-Path $Root 'scripts/security_store.py')) + $Arguments + @('--idf-path', $Tools.Idf)
        if ($WithPassphrase) {
            $passphrase = Read-ServicePassword 'Portable backup passphrase (at least 16 UTF-8 bytes)'
            if ($ConfirmPassphrase) {
                $confirmation = Read-ServicePassword 'Repeat backup passphrase'
                if ($passphrase -cne $confirmation) { Stop-ServiceOperation 'Backup passphrases do not match.' }
            }
            $request = Join-Path $stage 'request.secrets.json'
            Write-ServiceUtf8 $request (@{ passphrase = $passphrase } | ConvertTo-Json -Compress)
            $nativeArguments += @('--request', $request)
        }
        Invoke-ServicePython $Tools.Python $nativeArguments
    }
    finally {
        $passphrase = $null
        $confirmation = $null
        Assert-ServicePlainPath $stage
        $absoluteStage = [IO.Path]::GetFullPath($stage)
        $expectedParent = [IO.Path]::GetFullPath($base).TrimEnd('\', '/')
        if ([IO.Path]::GetDirectoryName($absoluteStage) -cne $expectedParent -or
            -not [IO.Path]::GetFileName($absoluteStage).StartsWith('.security-')) {
            Stop-ServiceOperation 'Security transaction cleanup is outside the expected directory.'
        }
        if ([IO.Directory]::Exists($absoluteStage)) { Remove-Item -LiteralPath $absoluteStage -Recurse -Force }
    }
}

function Write-ServiceConfigurationFromVault([string]$Root, $Configuration, $Tools, [string]$KeyStore) {
    $base = Join-Path $Root '.local/service'
    Assert-ServicePlainPath $base
    [void][IO.Directory]::CreateDirectory($base)
    $stage = Join-Path $base ('.bound-nvs-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-ServicePrivateDirectory $stage
        $key = Join-Path $stage 'nvs.bin'
        Invoke-ServiceSecurityTool $Root $Tools @('nvs-key', '--vault', $KeyStore, '--output', $key)
        Write-ServiceArtifacts $Root $Configuration $Tools $key
    }
    finally {
        Assert-ServicePlainPath $stage
        $absoluteStage = [IO.Path]::GetFullPath($stage)
        $expectedParent = [IO.Path]::GetFullPath($base).TrimEnd('\', '/')
        if ([IO.Path]::GetDirectoryName($absoluteStage) -cne $expectedParent -or
            -not [IO.Path]::GetFileName($absoluteStage).StartsWith('.bound-nvs-')) {
            Stop-ServiceOperation 'Bound-key transaction cleanup is outside the expected directory.'
        }
        if ([IO.Directory]::Exists($absoluteStage)) { Remove-Item -LiteralPath $absoluteStage -Recurse -Force }
    }
}

Export-ModuleMember -Function Resolve-ServiceNvsKey, New-ServiceNvsKey, Invoke-ServiceSecurityTool, Write-ServiceConfigurationFromVault

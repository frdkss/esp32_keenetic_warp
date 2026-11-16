#Requires -Version 5.1
param(
    [ValidateSet('Validation', 'Input', 'Generate', 'GeneratorFailure', 'Rollback', 'InvalidInput')][string]$Case,
    [Parameter(Mandatory = $true)][string]$WorkRoot,
    [Parameter(Mandatory = $true)][string]$PythonPath,
    [Parameter(Mandatory = $true)][string]$IdfPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Acceptance requires Windows PowerShell 5.1'
}
$sourceRoot = Split-Path $PSScriptRoot -Parent
foreach ($name in @('Common', 'Input', 'Validation', 'Keys', 'Generation')) {
    Import-Module (Join-Path $sourceRoot "scripts/service/$name.psm1") -Force -DisableNameChecking
}
$script:assertions = 0
function Assert-True([bool]$Value, [string]$Message) {
    if (-not $Value) { throw "Assertion failed: $Message" }
    $script:assertions++
}
function Assert-Rejected([scriptblock]$Code) {
    $rejected = $false
    try { & $Code | Out-Null } catch { $rejected = $true }
    Assert-True $rejected 'invalid input must be rejected'
}
function Assert-PrivateFile([string]$Path) {
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = [IO.File]::GetAccessControl($Path)
    Assert-True $acl.AreAccessRulesProtected 'secret file inheritance disabled'
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        Assert-True ($rule.IdentityReference.Value -ceq $owner) 'secret file readable only by current owner'
    }
}
function Get-Fixture {
    $cyrillic = [string][char]0x0436 + [char]0x044F
    return [ordered]@{
        WifiSsid = 'TEST-SSID-' + $cyrillic
        WifiPassword = '  wifi"\,$`' + $cyrillic + '  '
        RouterAddress = '192.0.2.1'
        RouterHttpsName = 'router.example.invalid'
        RouterPort = '443'
        RouterLogin = 'TEST-login"\,' + $cyrillic
        RouterPassword = '  TEST-password"\,$`' + $cyrillic + '  '
        WarpInterface = 'Wireguard7'
        TargetUrls = @('HTTPS://TARGET.example.invalid:443', 'https://target.example.invalid/', 'https://target.example.invalid/Case?q=A')
        ControlUrls = @('https://control.example.invalid')
        CheckIntervalSeconds = '60'
        ConnectTimeoutSeconds = '5'
        ReadTimeoutSeconds = '5'
        DisablePauseSeconds = '2'
        WarmupSeconds = '30'
        CooldownSeconds = '300'
        ScheduleDay = '4'
        ScheduleTime = '05:00'
        Timezone = 'MSK-3'
        EnableAutoRecovery = '1'
        EnableWeeklyRestart = '0'
        OledEnabled = '0'
    }
}

switch ($Case) {
    'Validation' {
        $fixture = Get-Fixture
        $checked = ConvertTo-ServiceConfiguration $fixture
        Assert-True ($checked.TargetUrls.Count -eq 2) 'canonical duplicates removed'
        Assert-True ($checked.ControlUrls.Count -eq 1) 'singleton remains array'
        Assert-True ($checked.WifiPassword -ceq $fixture.WifiPassword) 'secret spaces and special characters preserved'
        Assert-True ($checked.FailureThreshold -eq 5) 'agreed threshold fixed'
        foreach ($field in $fixture.Keys) {
            $broken = Get-Fixture
            $broken.Remove($field)
            Assert-Rejected { ConvertTo-ServiceConfiguration $broken }
        }
        foreach ($bad in @('', 'http://', 'ftp://site.invalid/', 'https://u:p@site.invalid/',
            'https://site.invalid/#', 'https://site.invalid/a b', 'https://site.invalid\a')) {
            $broken = Get-Fixture
            $broken.TargetUrls = @($bad)
            Assert-Rejected { ConvertTo-ServiceConfiguration $broken }
        }
        $broken = Get-Fixture
        $broken.TargetUrls = @()
        Assert-Rejected { ConvertTo-ServiceConfiguration $broken }
        $broken.TargetUrls = @('https://control.example.invalid/')
        Assert-Rejected { ConvertTo-ServiceConfiguration $broken }
        foreach ($spec in @(@('RouterPort','0'), @('CheckIntervalSeconds','-1'), @('CheckIntervalSeconds','2147483648'),
            @('ConnectTimeoutSeconds','61'), @('ReadTimeoutSeconds','x'), @('ScheduleDay','7'),
            @('ScheduleTime','24:00'), @('ScheduleTime','5:00'), @('EnableAutoRecovery','yes'),
            @('Timezone','Europe/Moscow'), @('WarpInterface','Wireguard0/../'), @('RouterHttpsName','https://router.invalid'),
            @('RouterPassword',"bad`ninput"), @('WifiPassword','short'), @('WifiPassword',('z' * 64)))) {
            $broken = Get-Fixture
            $broken[$spec[0]] = $spec[1]
            Assert-Rejected { ConvertTo-ServiceConfiguration $broken }
        }
        foreach ($tz in @('UTC0', 'MSK-3', 'CET-1CEST,M3.5.0/2,M10.5.0/3', '<+03>-3')) {
            $valid = Get-Fixture
            $valid.Timezone = $tz
            Assert-True ((ConvertTo-ServiceConfiguration $valid).Timezone -ceq $tz) 'POSIX timezone accepted'
        }
        foreach ($password in @('', ('a' * 64))) {
            $valid = Get-Fixture
            $valid.WifiPassword = $password
            Assert-True ((ConvertTo-ServiceConfiguration $valid).WifiPassword -ceq $password) 'open Wi-Fi/raw PSK accepted'
        }
    }
    'Input' {
        # Module-scoped mocks: verify hidden input and cancellation without a terminal.
        & (Get-Module Input) {
            $script:secureCalls = 0
            function script:Read-Host {
                param($Prompt, [switch]$AsSecureString)
                if (-not $AsSecureString) { throw 'Password was not hidden' }
                $script:secureCalls++
                return ConvertTo-SecureString '  synthetic"\secret  ' -AsPlainText -Force
            }
        }
        $password = Read-ServicePassword 'Password'
        Assert-True ($password -ceq '  synthetic"\secret  ') 'hidden password preserved'
        & (Get-Module Input) {
            function script:Read-Host { param($Prompt, [switch]$AsSecureString)
                if ($AsSecureString) { return ConvertTo-SecureString ':cancel' -AsPlainText -Force }
                return ':cancel'
            }
        }
        Assert-Rejected { Read-ServicePassword 'Password' }
        Assert-Rejected { Read-ServiceField 'Field' }
        & (Get-Module Input) { function script:Read-Host { param($Prompt) return '' } }
        Assert-True ((Read-ServiceField 'Field' '60') -ceq '60') 'blank selects explicit default'
    }
    default {
        $project = Join-Path $WorkRoot 'project'
        [void][IO.Directory]::CreateDirectory((Join-Path $project 'include'))
        Copy-Item -LiteralPath (Join-Path $sourceRoot 'partitions.csv') -Destination $project
        $tools = Resolve-ServiceTools $sourceRoot $PythonPath $IdfPath
        $key = Join-Path $WorkRoot 'nvs-key.bin'
        New-ServiceNvsKey $project $key $tools
        Assert-True ((Get-Item -LiteralPath $key).Length -eq 4096) 'official key partition created'
        Assert-PrivateFile $key
        Assert-Rejected { New-ServiceNvsKey $project $key $tools }
        Assert-Rejected { Resolve-ServiceNvsKey $project (Join-Path $project 'key.bin') }
        $checked = ConvertTo-ServiceConfiguration (Get-Fixture)
        # The helper location is the source project; destination is a disposable project.
        if ($Case -eq 'Generate') {
            Write-ServiceArtifacts $project $checked $tools (Resolve-ServiceNvsKey $project $key)
            Write-ServiceArtifacts $project $checked $tools $key # Exercise replacement of existing outputs.
            Assert-True ((Get-Item (Join-Path $project '.local/service/nvs.encrypted.bin')).Length -eq 24576) 'NVS partition size'
            Assert-PrivateFile (Join-Path $project 'include/service_secrets.h')
            Assert-PrivateFile (Join-Path $project '.local/service/nvs.encrypted.bin')
            # Concurrent configuration is rejected while the exclusive file lock is held.
            $lock = [IO.File]::Open((Join-Path $project '.local/service/configure.lock'), 'Open', 'ReadWrite', 'None')
            try { Assert-Rejected { Write-ServiceArtifacts $project $checked $tools $key } }
            finally { $lock.Dispose() }
        }
        else {
            foreach ($name in @('config.h', 'service_secrets.h')) {
                Write-ServiceUtf8 (Join-Path $project "include/$name") "ORIGINAL-$name"
            }
            [void][IO.Directory]::CreateDirectory((Join-Path $project '.local/service'))
            Write-ServiceUtf8 (Join-Path $project '.local/service/nvs.encrypted.bin') 'ORIGINAL-NVS'
            if ($Case -eq 'GeneratorFailure') {
                # A corrupt key must fail before replacing any header.
                [IO.File]::WriteAllBytes($key, [byte[]]::new(4096))
            }
            elseif ($Case -eq 'Rollback') {
                & (Get-Module Generation) {
                    $script:originalInstall = ${function:Install-ServiceArtifact}
                    $script:installCalls = 0
                    function script:Install-ServiceArtifact {
                        param($Source, $Destination, $Backup)
                        $script:installCalls++
                        if ($script:installCalls -eq 3) { throw 'Injected replacement failure' }
                        & $script:originalInstall $Source $Destination $Backup
                    }
                }
            }
            else { $checked.RouterPassword = "INVALID-SECRET`nINPUT" }
            Assert-Rejected { Write-ServiceArtifacts $project $checked $tools $key }
            foreach ($name in @('config.h', 'service_secrets.h')) {
                Assert-True ([IO.File]::ReadAllText((Join-Path $project "include/$name")) -ceq "ORIGINAL-$name") 'old header restored'
            }
            Assert-True ([IO.File]::ReadAllText((Join-Path $project '.local/service/nvs.encrypted.bin')) -ceq 'ORIGINAL-NVS') 'old NVS preserved'
            # Invalid input is rejected before even invoking a tool.
            $checked.CheckIntervalSeconds = 'bad'
            Assert-Rejected { Write-ServiceArtifacts $project $checked $tools $key }
        }
        Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $project '.local/service') -Filter '.pending-*' -Force).Count -eq 0) 'private temporary files cleaned'
        Assert-True (@(Get-ChildItem -LiteralPath $WorkRoot -Filter '.nvs-key-*' -Force).Count -eq 0) 'key staging cleaned'
    }
}
Write-Output "PASS $Case ($script:assertions assertions)"

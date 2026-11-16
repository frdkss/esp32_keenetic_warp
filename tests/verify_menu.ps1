#Requires -Version 5.1
param([string]$WorkRoot, [string]$PythonPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
foreach ($name in @('Common', 'Validation', 'State', 'Console', 'Processes', 'Menu')) {
    Import-Module (Join-Path $root "scripts/service/$name.psm1") -Force -DisableNameChecking
}
function Assert([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
$previousAppData = $env:LOCALAPPDATA
$env:LOCALAPPDATA = Join-Path $WorkRoot 'appdata'
try {
    $progress = Get-ServiceProgressText 'Writing' 50 100 0
    Assert ($progress.StartsWith('[' + ('#' * 20) + ('_' * 20) + '] 50% Writing')) 'Progress uses byte percentage'
    Assert ((Get-ServiceProgressText 'Verified' 100 100 0).StartsWith('[' + ('#' * 40) + '] 100%')) 'Verified progress is full'
    $unknown = Get-ServiceProgressText 'Building' -1 80 2
    Assert ($unknown.Contains('###') -and -not $unknown.Contains('%')) 'Build progress does not invent a percentage'
    $narrow = Get-ServiceProgressText 'A long operation status' 25 24 0
    Assert ($narrow.Length -eq 24 -and $narrow.EndsWith('…')) 'Progress remains within narrow terminal'
    $counted = Get-ServiceProgressText 'Secure Download' 85 100 0 23 27
    Assert ($counted.Contains('85% этапы 23/27 | Secure Download')) 'Overall percentage and completed stage count are visible together'
    Assert ($counted.StartsWith('[' + ('#' * 20) + ('_' * 4) + ']')) 'Counted bar leaves room for stage status'
    & (Get-Module Console) {
        $original = (Get-Command Update-ServiceProgressConsole).ScriptBlock
        try {
            function script:Update-ServiceProgressConsole { throw [ArgumentOutOfRangeException]::new('console resize') }
            Refresh-ServiceProgress -Force
            function script:Update-ServiceProgressConsole { throw [IO.IOException]::new('console detached') }
            Refresh-ServiceProgress -Force
            function script:Update-ServiceProgressConsole { throw [InvalidOperationException]::new('console unavailable') }
            Refresh-ServiceProgress -Force
        }
        finally { Set-Item Function:script:Update-ServiceProgressConsole $original }
    }
    $state = Read-ServiceState
    Assert ($state.Configuration.FailureThreshold -eq 5 -and $state.Configuration.TargetFailurePolicy -eq 2) 'Defaults'
    Assert ($state.Configuration.ScheduleDay -eq 4 -and $state.Configuration.ScheduleTime -eq '05:00') 'Schedule defaults'
    Assert ($state.Configuration.TargetUrls.Count -eq 0 -and $state.Configuration.WifiSsid -eq '') 'No invented connection values'
    Set-ServiceDraftValues $state @{ RouterLogin = 'SYNTHETIC_LOGIN'; RouterPassword = 'SYNTHETIC-private-password' }
    Set-ServiceDraftValues $state @{ TargetUrls = @('https://target.example.invalid/') }
    $loaded = Read-ServiceState
    Assert ($loaded.Configuration.RouterPassword -ceq 'SYNTHETIC-private-password') 'DPAPI roundtrip'
    Assert ($loaded.Configuration.TargetUrls -is [array] -and $loaded.Configuration.TargetUrls.Count -eq 1) 'Singleton array'
    Assert ($loaded.Configuration.TargetUrls[0] -is [string] -and $loaded.Configuration.TargetUrls[0] -ceq 'https://target.example.invalid/') 'Singleton address preserved as text'
    Assert ($loaded.Configuration.ControlUrls -is [array] -and $loaded.Configuration.ControlUrls.Count -eq 0) 'Empty URL array preserved'
    $expectedTargets = @('https://one.example.invalid/', 'https://two.example.invalid/path?q=1', 'https://three.example.invalid/', 'https://four.example.invalid/')
    $expectedControls = @('https://control-one.example.invalid/', 'https://control-two.example.invalid/', 'https://control-three.example.invalid/')
    Set-ServiceDraftValues $state @{ TargetUrls = $expectedTargets; ControlUrls = $expectedControls }
    $state.Devices['synthetic-device'] = [ordered]@{ Vault = 'C:\synthetic\owner'; Backup = ''; Evidence = ''; Port = 'COM999' }
    Save-ServiceState $state
    for ($round = 0; $round -lt 3; $round++) {
        $loaded = Read-ServiceState
        foreach ($field in @('TargetUrls','ControlUrls')) {
            $expected = if ($field -eq 'TargetUrls') { $expectedTargets } else { $expectedControls }
            Assert ($loaded.Configuration[$field] -is [array] -and $loaded.Configuration[$field].Count -eq $expected.Count) 'URL array count preserved'
            for ($index = 0; $index -lt $expected.Count; $index++) {
                Assert ($loaded.Configuration[$field][$index] -is [string] -and $loaded.Configuration[$field][$index] -ceq $expected[$index]) 'Every URL survives reload as text'
            }
            $rendered = & (Get-Module Menu) { param($config,$field) Get-ServiceNetworkValue $config @{ Key=$field; Type='urls' } } $loaded.Configuration $field
            Assert ($rendered -ceq ($expected -join ', ')) 'Editor displays addresses after reload'
        }
        Assert ($loaded.Configuration.CheckIntervalSeconds -is [int] -and $loaded.Configuration.CheckIntervalSeconds -eq 60) 'Numeric scalar preserved'
        Assert ($loaded.Devices['synthetic-device'].Vault -ceq 'C:\synthetic\owner') 'Nested device map preserved'
        Set-ServiceDraftValues $loaded @{ CheckIntervalSeconds = 60 }
    }
    $state = Read-ServiceState
    $path = Join-Path (Get-ServiceHome) 'state/state.dpapi'
    $original = [IO.File]::ReadAllBytes($path)
    Assert (-not [Text.Encoding]::UTF8.GetString($original).Contains('SYNTHETIC')) 'No plaintext on disk'
    $rejected = $false
    try { Set-ServiceDraftValues $state @{ FailureThreshold = 0 } } catch { $rejected = $true }
    Assert $rejected 'Invalid cycles rejected'
    Assert ([Convert]::ToBase64String($original) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) 'Invalid edit preserves state'
    $rejected = $false
    try { Set-ServiceDraftValues $state @{ ControlUrls = @($expectedTargets[0]) } } catch { $rejected = $true }
    Assert $rejected 'Cross-list duplication rejected'
    $invalid = Read-ServiceState
    $invalid.Configuration.TargetUrls = @([ordered]@{ Length = 10 })
    $rejected = $false
    try { Save-ServiceState $invalid } catch { $rejected = $true }
    Assert $rejected 'Object values cannot overwrite saved domains'
    Assert ([Convert]::ToBase64String($original) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) 'Rejected object preserves encrypted state'
    $domains = ConvertTo-ServiceDomainList 'one.example.invalid, https://two.example.invalid/path'
    Assert ($domains.Count -eq 2 -and $domains[0] -eq 'https://one.example.invalid') 'Domain input'
    # Real editor state machine; only console rendering/key source is synthetic.
    & (Get-Module Menu) {
        param($state)
        function script:Show-ServiceNetworkScreen { }
        function script:Clear-ServiceScreen { }
        $script:keys = [Collections.Generic.Queue[ConsoleKeyInfo]]::new()
        foreach ($key in @('DownArrow','DownArrow','DownArrow','DownArrow','DownArrow','Enter','RightArrow','Enter','Escape')) {
            $script:keys.Enqueue([ConsoleKeyInfo]::new([char]0, [ConsoleKey]::$key, $false, $false, $false))
        }
        function script:Read-ServiceKey([scriptblock]$OnResize) { if ($OnResize) { & $OnResize }; return $script:keys.Dequeue() }
        $exit = Invoke-ServiceNetworkMenu $state
        if ($exit -or $state.Configuration.TargetFailurePolicy -ne 3) { throw 'Arrow edit/commit failed' }
        foreach ($key in @('DownArrow','DownArrow','DownArrow','DownArrow','DownArrow','DownArrow','DownArrow','DownArrow',
            'Enter','DownArrow','RightArrow','DownArrow','RightArrow','DownArrow','RightArrow','DownArrow','Enter','Escape')) {
            $script:keys.Enqueue([ConsoleKeyInfo]::new([char]0, [ConsoleKey]::$key, $false, $false, $false))
        }
        $exit = Invoke-ServiceNetworkMenu $state
        if ($exit -or $state.Configuration.EnableWeeklyRestart -ne 0 -or $state.Configuration.ScheduleDay -ne 5 -or
            $state.Configuration.ScheduleTime -ne '06:01') { throw 'Schedule component edit failed' }
        $script:keys.Enqueue([ConsoleKeyInfo]::new([char]'0', [ConsoleKey]::D0, $false, $false, $false))
        function script:Read-ServiceConsoleText { return '00' }
        if (-not (Invoke-ServiceNetworkMenu $state)) { throw '00 did not exit' }
    } $state
    # Exercise Windows argument quoting through a real child process.
    $arguments = @('', 'two words', 'quote"inside', 'C:\space folder\', 'кириллица', ('$literal' + [char]96 + 'value'))
    $result = Invoke-ServiceProcess $PythonPath (@('-c', 'import json,sys;print(json.dumps(sys.argv[1:]))') + $arguments) 'Argument test' 30
    $returned = ConvertFrom-Json $result.Lines[-1]
    Assert ($returned.Count -eq $arguments.Count) 'Argument count'
    for ($index = 0; $index -lt $arguments.Count; $index++) { Assert ($returned[$index] -ceq $arguments[$index]) 'Argument preservation' }
    $result = Invoke-ServiceProcess $PythonPath @('-c', 'import sys;[(print(i),print(i,file=sys.stderr)) for i in range(2000)]') 'Pipe test' 15
    Assert ($result.ExitCode -eq 0 -and $result.Lines.Count -le 64) 'Concurrent pipe drain and bounded output'
    $rejected = $false
    try {
        [void](Invoke-ServiceProcess $PythonPath @('-c', 'import sys,time;sys.stdout.close();sys.stderr.close();time.sleep(20)') 'Timeout test' 1)
    } catch { $rejected = $_.Exception.Message.Contains('timed out') }
    Assert $rejected 'Timeout remains active after output pipes close'
    $eventCode = 'import json;print(json.dumps({"event":"result","result":{"result":"verified"}}));[print("native trailing line") for _ in range(200)]'
    $eventResult = Invoke-ServiceEventTool $PythonPath @('-c', $eventCode) 'Streaming result test' 15
    Assert ($eventResult.result -eq 'verified') 'Result is retained beyond the bounded native output tail'
    $rejected = $false
    try {
        $errorCode = 'import json,sys;print(json.dumps({"event":"error","message":"fixed structured failure"}));[print("native trailing line") for _ in range(200)];sys.exit(1)'
        [void](Invoke-ServiceEventTool $PythonPath @('-c', $errorCode) 'Streaming error test' 15)
    } catch { $rejected = $_.Exception.Message -eq 'fixed structured failure' }
    Assert $rejected 'Structured error is retained beyond the bounded native output tail'
    $rejected = $false
    try { [void](Invoke-ServiceEventTool $PythonPath @('-c', 'pass') 'Empty result test' 15) }
    catch { $rejected = $_.Exception.Data.Contains('ServiceSafe') }
    Assert $rejected 'Exit zero without a result cannot report success'
    [IO.File]::WriteAllBytes($path, [byte[]](1,2,3))
    $rejected = $false
    try { [void](Read-ServiceState) } catch { $rejected = $true }
    Assert $rejected 'Corrupt DPAPI state rejected'
    Assert (([IO.File]::ReadAllBytes($path)).Length -eq 3) 'Corrupt state preserved'
    Write-Host 'PASS menu/state/process'
}
finally { $env:LOCALAPPDATA = $previousAppData }

Set-StrictMode -Version Latest

function ConvertTo-ServiceNativeArgument([string]$Value) {
    if ($Value -and $Value -notmatch '[\s"]') { return $Value }
    $builder = [Text.StringBuilder]::new('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1))); [void]$builder.Append('"')
        } else {
            [void]$builder.Append(('\' * $slashes)); [void]$builder.Append($character)
        }
        $slashes = 0
    }
    [void]$builder.Append(('\' * (2 * $slashes))); [void]$builder.Append('"')
    return $builder.ToString()
}

function Stop-ServiceProcessTree([Diagnostics.Process]$Process) {
    if ($Process.HasExited) { return }
    $killer = [Diagnostics.Process]::new()
    try {
        $killer.StartInfo = [Diagnostics.ProcessStartInfo]::new()
        $killer.StartInfo.FileName = Join-Path $env:SystemRoot 'System32/taskkill.exe'
        $killer.StartInfo.Arguments = '/PID ' + $Process.Id.ToString() + ' /T /F'
        $killer.StartInfo.UseShellExecute = $false
        $killer.StartInfo.CreateNoWindow = $true
        $killer.StartInfo.RedirectStandardOutput = $true
        $killer.StartInfo.RedirectStandardError = $true
        [void]$killer.Start()
        $discardOutput = $killer.StandardOutput.ReadToEndAsync()
        $discardError = $killer.StandardError.ReadToEndAsync()
        if (-not $killer.WaitForExit(5000)) { $killer.Kill() }
    } catch { if (-not $Process.HasExited) { $Process.Kill() } }
    finally { $killer.Dispose() }
}

function Invoke-ServiceProcess([string]$Executable, [string[]]$Arguments, [string]$Stage = 'SERVICE',
    [int]$TimeoutSeconds = 1800, [switch]$AllowFailure, [scriptblock]$OnLine) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.Arguments = (@($Arguments | ForEach-Object { ConvertTo-ServiceNativeArgument $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $info.EnvironmentVariables['PYTHONUTF8'] = '1'
    $info.EnvironmentVariables['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
    $info.EnvironmentVariables['PLATFORMIO_SETTING_ENABLE_TELEMETRY'] = 'false'
    $info.EnvironmentVariables['IDF_COMPONENT_CHECK_NEW_VERSION'] = '0'
    $info.EnvironmentVariables['IDF_COMPONENT_API_TIMEOUT'] = '30'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $lines = [Collections.Generic.Queue[string]]::new()
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $started = $false
    $succeeded = $false
    $progressWriter = $null; $progressRefresh = $null; $progressComplete = $null
    $progressUI = Get-Command Test-ServiceProgressUI -ErrorAction SilentlyContinue
    if ($progressUI -and (& $progressUI)) {
        $progressWriter = Get-Command Write-ServiceProgress
        $progressRefresh = Get-Command Refresh-ServiceProgress
        $progressComplete = Get-Command Complete-ServiceProgress
    }
    try {
        if ($progressWriter) { & $progressWriter $Stage }
        [void]$process.Start()
        $started = $true
        $process.StandardInput.Close()
        $readers = @($process.StandardOutput, $process.StandardError)
        $pending = @($readers[0].ReadLineAsync(), $readers[1].ReadLineAsync())
        while (-not $process.HasExited -or $null -ne $pending[0] -or $null -ne $pending[1]) {
            if ($clock.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                Stop-ServiceProcessTree $process
                Stop-ServiceOperation ($Stage + ': operation timed out.')
            }
            for ($index = 0; $index -lt 2; $index++) {
                $drained = 0
                while ($null -ne $pending[$index] -and $pending[$index].IsCompleted -and $drained -lt 128) {
                    $line = $pending[$index].GetAwaiter().GetResult()
                    if ($null -eq $line) { $pending[$index] = $null; break }
                    if ($lines.Count -ge 64) { [void]$lines.Dequeue() }
                    $lines.Enqueue($line)
                    if ($OnLine) { & $OnLine $line ($index -eq 0) }
                    $pending[$index] = $readers[$index].ReadLineAsync()
                    $drained++
                }
            }
            if ($progressRefresh) { & $progressRefresh }
            elseif (-not $OnLine) { Write-Progress -Id 1 -Activity $Stage -Status 'Выполняется...' }
            [Threading.Thread]::Sleep(30)
        }
        $process.WaitForExit()
        $result = [pscustomobject]@{ ExitCode = $process.ExitCode; Lines = $lines.ToArray() }
        $succeeded = $result.ExitCode -eq 0
        if ($result.ExitCode -ne 0 -and -not $AllowFailure) { Stop-ServiceOperation ($Stage + ': operation failed. No sensitive tool output is printed.') }
        return $result
    }
    finally {
        if ($started -and -not $process.HasExited) { Stop-ServiceProcessTree $process }
        $process.Dispose()
        if ($progressComplete) { & $progressComplete -Failed:(-not $succeeded) -Verified:($succeeded -and -not $OnLine) }
        else { Write-Progress -Id 1 -Activity $Stage -Completed }
    }
}

function Invoke-ServiceEventTool([string]$Python, [string[]]$Arguments, [string]$Stage, [int]$TimeoutSeconds = 1800) {
    $progressWriter = $null
    $progressUI = Get-Command Test-ServiceProgressUI -ErrorAction SilentlyContinue
    if ($progressUI -and (& $progressUI)) { $progressWriter = Get-Command Write-ServiceProgress }
    $state = [pscustomobject]@{ Result = $null; ResultCount = 0; ErrorMessage = ''; LastPhase = $Stage }
    $handler = {
        param($line, $IsStandardOutput)
        if (-not $IsStandardOutput) { return }
        try {
            $event = ConvertFrom-Json $line -ErrorAction Stop
            if ($event.event -in @('progress', 'phase')) {
                $state.LastPhase = [string]$event.phase
                $percent = -1
                $steps = @{}
                if ($event.PSObject.Properties['overall_percent']) { $percent = [Math]::Min(99, [Math]::Max(0, [int]$event.overall_percent)) }
                elseif ($event.event -eq 'progress') { $percent = [Math]::Min(99, [int](100.0 * $event.current / [Math]::Max(1, $event.total))) }
                if ($event.PSObject.Properties['steps_done'] -and $event.PSObject.Properties['steps_total']) {
                    $steps = @{ StepsDone = [int]$event.steps_done; StepsTotal = [int]$event.steps_total }
                }
                if ($progressWriter) { & $progressWriter $state.LastPhase $percent @steps }
                else {
                    $status = $state.LastPhase
                    if ($steps.Count) { $status = 'этапы ' + $steps.StepsDone + '/' + $steps.StepsTotal + ' | ' + $status }
                    Write-Progress -Id 1 -Activity $Stage -Status $status -PercentComplete $percent
                }
            } elseif ($event.event -eq 'error' -and $event.message -is [string]) {
                $state.ErrorMessage = $event.message
            } elseif ($event.event -eq 'result') {
                $state.Result = $event.result
                $state.ResultCount++
            }
        } catch { }
    }.GetNewClosure()
    $result = Invoke-ServiceProcess $Python ($Arguments + @('--events')) $Stage $TimeoutSeconds -AllowFailure -OnLine $handler
    if ($state.ErrorMessage) { Stop-ServiceOperation $state.ErrorMessage }
    if ($result.ExitCode -ne 0) { Stop-ServiceOperation ($Stage + ': operation failed (exit ' + $result.ExitCode + ').') }
    if ($state.ResultCount -eq 1 -and $null -ne $state.Result) {
        if ($state.Result.PSObject.Properties['result'] -and $state.Result.result -eq 'verified') {
            if ($progressWriter) { & $progressWriter 'Запуск подтверждён' 100 -Completed }
            else { Write-Progress -Id 1 -Activity $Stage -Status 'Запуск подтверждён' -PercentComplete 100 }
        }
        return $state.Result
    }
    if ($state.ResultCount -gt 1) { Stop-ServiceOperation ($Stage + ': tool returned multiple results; success was not confirmed.') }
    Stop-ServiceOperation ($Stage + ': процесс завершился без итогового подтверждения. Последний этап: ' + $state.LastPhase + '. Проверьте журнал; запись автоматически не повторяется.')
}

Export-ModuleMember -Function ConvertTo-ServiceNativeArgument, Invoke-ServiceProcess, Invoke-ServiceEventTool

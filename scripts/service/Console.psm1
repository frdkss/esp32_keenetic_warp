Set-StrictMode -Version Latest

$script:VirtualColor = $false
$script:ColorInitialized = $false
$script:ProgressUI = $false
$script:Progress = @{ Visible = $false; Active = $false; Status = ''; Percent = -1; Failed = $false; StepsDone = 0; StepsTotal = 0 }
$script:ProgressClock = [Diagnostics.Stopwatch]::StartNew()
$script:ProgressLastDraw = -1000
$script:ProgressWidth = 0
$script:ProgressHeight = 0

function Enable-ServiceProgressUI {
    Assert-ServiceConsole
    $script:ProgressUI = $true
}

function Test-ServiceProgressUI { return $script:ProgressUI }

function Get-ServiceProgressText([string]$Status, [int]$Percent = -1, [int]$Width = 80, [int]$Pulse = 0,
    [int]$StepsDone = 0, [int]$StepsTotal = 0) {
    $Width = [Math]::Max(8, $Width)
    $barWidth = [Math]::Min(40, [Math]::Max(3, [int][Math]::Floor(($Width - 4) / 2)))
    if ($StepsTotal -gt 0) { $barWidth = [Math]::Min(24, $barWidth) }
    $bar = '_' * $barWidth
    if ($Percent -ge 0) {
        $Percent = [Math]::Min(100, $Percent)
        $filled = [int][Math]::Floor($barWidth * $Percent / 100.0)
        $bar = ('#' * $filled) + ('_' * ($barWidth - $filled))
    } else {
        # An animated marker denotes work with no measurable percentage.
        $position = [Math]::Abs($Pulse) % ($barWidth - 2)
        $bar = $bar.Remove($position, 3).Insert($position, '###')
    }
    $label = $Status -replace '[\x00-\x1f\x7f]', ' '
    if ($StepsTotal -gt 0) { $label = 'этапы ' + [Math]::Min($StepsTotal, [Math]::Max(0, $StepsDone)) + '/' + $StepsTotal + ' | ' + $label }
    if ($Percent -ge 0) { $label = $Percent.ToString() + '% ' + $label }
    $text = '[' + $bar + '] ' + $label
    if ($text.Length -gt $Width) { $text = $text.Substring(0, $Width - 1) + '…' }
    return $text.PadRight($Width)
}

function Update-ServiceProgressConsole([switch]$Force) {
    if (-not $script:ProgressUI -or -not $script:Progress.Visible) { return }
    $width = [Console]::WindowWidth
    $height = [Console]::WindowHeight
    if ($width -lt 10 -or $height -lt 3) { return }
    if (-not $Force -and $width -eq $script:ProgressWidth -and $height -eq $script:ProgressHeight -and
        $script:ProgressClock.ElapsedMilliseconds - $script:ProgressLastDraw -lt 100) { return }
    $script:ProgressWidth = $width; $script:ProgressHeight = $height
    $script:ProgressLastDraw = $script:ProgressClock.ElapsedMilliseconds
    $pulse = if ($script:Progress.Active) { [int]($script:ProgressClock.ElapsedMilliseconds / 150) } else { 0 }
    $text = Get-ServiceProgressText $script:Progress.Status $script:Progress.Percent ($width - 1) $pulse $script:Progress.StepsDone $script:Progress.StepsTotal
    $left = [Console]::CursorLeft; $top = [Console]::CursorTop
    $foreground = [Console]::ForegroundColor; $background = [Console]::BackgroundColor
    $visible = [Console]::CursorVisible
    try {
        $progressRow = [Console]::WindowTop + $height - 2
        [Console]::CursorVisible = $false
        [Console]::SetCursorPosition(0, $progressRow)
        [Console]::ForegroundColor = if ($script:Progress.Failed) { 'Red' } elseif ($script:Progress.Percent -eq 100) { 'Green' } else { 'Cyan' }
        [Console]::Write($text)
        [Console]::ForegroundColor = $foreground
        [Console]::SetCursorPosition(0, $progressRow + 1)
        [Console]::Write(': '.PadRight($width - 1))
        if ($top -ge $progressRow) { $left = 2; $top = $progressRow + 1 }
    }
    finally {
        [Console]::ForegroundColor = $foreground; [Console]::BackgroundColor = $background
        [Console]::SetCursorPosition([Math]::Min($left, [Console]::BufferWidth - 1), [Math]::Min($top, [Console]::BufferHeight - 1))
        [Console]::CursorVisible = $visible
    }
}

function Refresh-ServiceProgress([switch]$Force) {
    # A console resize/disconnection must never abort a firmware writer.
    try { Update-ServiceProgressConsole -Force:$Force }
    catch [ArgumentOutOfRangeException] { }
    catch [IO.IOException] { }
    catch [InvalidOperationException] { }
}

function Write-ServiceProgress([string]$Status, [int]$Percent = -1, [switch]$Completed, [switch]$Failed,
    [int]$StepsDone = -1, [int]$StepsTotal = -1) {
    if (-not $script:ProgressUI) { return }
    if ($StepsTotal -ge 0) {
        $script:Progress.StepsTotal = $StepsTotal
        $script:Progress.StepsDone = [Math]::Min($StepsTotal, [Math]::Max(0, $StepsDone))
    }
    if ($Percent -lt 0 -and $script:Progress.StepsTotal -gt 0) {
        $Percent = [int][Math]::Floor(100.0 * $script:Progress.StepsDone / $script:Progress.StepsTotal)
    }
    $script:Progress.Visible = $true
    $script:Progress.Status = $Status
    $script:Progress.Percent = [Math]::Max(-1, [Math]::Min(100, $Percent))
    $script:Progress.Active = -not $Completed
    $script:Progress.Failed = $Failed.IsPresent
    Refresh-ServiceProgress -Force
}

function Complete-ServiceProgress([switch]$Failed, [switch]$Verified) {
    if (-not $script:ProgressUI) { return }
    $script:Progress.Active = $false
    $script:Progress.Failed = $Failed.IsPresent
    if ($Verified -and $script:Progress.StepsTotal -eq 0) { $script:Progress.Percent = 100 }
    Refresh-ServiceProgress -Force
}

function Initialize-ServiceColor {
    if ($script:ColorInitialized) { return }
    $script:ColorInitialized = $true
    try {
        if (-not ('WarpService.ConsoleMode' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace WarpService {
    public static class ConsoleMode {
        [DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int id);
        [DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr handle, out uint mode);
        [DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr handle, uint mode);
    }
}
'@
        }
        $handle = [WarpService.ConsoleMode]::GetStdHandle(-11)
        $mode = [uint32]0
        if ([WarpService.ConsoleMode]::GetConsoleMode($handle, [ref]$mode)) {
            $script:VirtualColor = [WarpService.ConsoleMode]::SetConsoleMode($handle, ($mode -bor 4))
        }
    } catch { }
}

function Assert-ServiceConsole {
    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected -or $Host.Name -eq 'Windows PowerShell ISE Host') {
        Stop-ServiceOperation 'The menu requires an interactive Windows console. Use -Action Help for command-line actions.'
    }
}

function Clear-ServiceScreen([string]$Title) {
    Initialize-ServiceColor
    [Console]::ResetColor()
    [Console]::Clear()
    [Console]::CursorVisible = $true
    Write-Host $Title
    Write-ServiceProgress 'Ожидание ввода' 0 -Completed -StepsDone 0 -StepsTotal 0
}

function Write-ServiceOption([string]$Text, [string]$Color = 'Gray') {
    if ($Color -eq 'DarkYellow' -and $script:VirtualColor) {
        [Console]::WriteLine(([char]27 + '[38;2;255;165;0m' + $Text + [char]27 + '[0m'))
        return
    }
    Write-Host $Text -ForegroundColor $Color
}

function Read-ServiceKey([scriptblock]$OnResize) {
    $width = [Console]::WindowWidth; $height = [Console]::WindowHeight
    while (-not [Console]::KeyAvailable) {
        if ($width -ne [Console]::WindowWidth -or $height -ne [Console]::WindowHeight) {
            $width = [Console]::WindowWidth; $height = [Console]::WindowHeight
            if ($OnResize) { & $OnResize }
        }
        [Threading.Thread]::Sleep(40)
    }
    return [Console]::ReadKey($true)
}

function Write-ServiceStatus([string]$Prefix, [string]$Value, [bool]$Enabled) {
    Write-Host $Prefix -NoNewline
    Write-Host '[' -NoNewline
    $color = if ($Enabled) { 'Green' } else { 'Red' }
    Write-Host $Value -NoNewline -ForegroundColor $color
    Write-Host ']'
}

function Set-ServiceInputLine([string]$Prompt, [string]$Text, [int]$Position, [bool]$Secret, [int]$Row = -1) {
    if ($Row -lt 0) { $Row = [Console]::WindowTop + [Console]::WindowHeight - 1 }
    $Row = [Math]::Min($Row, [Console]::BufferHeight - 1)
    $width = [Math]::Max(10, [Console]::WindowWidth - 1)
    $display = if ($Secret) { '*' * $Text.Length } else { $Text }
    $room = [Math]::Max(1, $width - $Prompt.Length)
    $start = [Math]::Max(0, $Position - $room + 1)
    $tail = $display.Substring($start)
    if ($tail.Length -gt $room) { $tail = $tail.Substring(0, $room) }
    [Console]::SetCursorPosition(0, $Row)
    [Console]::Write(($Prompt + $tail).PadRight($width).Substring(0, $width))
    [Console]::SetCursorPosition([Math]::Min($width - 1, $Prompt.Length + $Position - $start), $Row)
}

function Read-ServiceConsoleText([string]$Prompt = ': ', [string]$Initial = '', [switch]$Secret, [int]$Row = -1, [scriptblock]$OnResize) {
    $value = $Initial
    $position = $value.Length
    $drawInput = Get-Command Set-ServiceInputLine
    [Console]::CursorVisible = $true
    try {
        while ($true) {
            Set-ServiceInputLine $Prompt $value $position $Secret.IsPresent $Row
            $redraw = {
                if ($OnResize) { & $OnResize }
                Refresh-ServiceProgress -Force
                & $drawInput $Prompt $value $position $Secret.IsPresent $Row
            }.GetNewClosure()
            $key = Read-ServiceKey -OnResize $redraw
            switch ($key.Key) {
                'Enter' { return $value }
                'Escape' { throw [OperationCanceledException]::new() }
                'Backspace' { if ($position -gt 0) { $value = $value.Remove($position - 1, 1); $position-- } }
                'Delete' { if ($position -lt $value.Length) { $value = $value.Remove($position, 1) } }
                'LeftArrow' { $position = [Math]::Max(0, $position - 1) }
                'RightArrow' { $position = [Math]::Min($value.Length, $position + 1) }
                'Home' { $position = 0 }
                'End' { $position = $value.Length }
                default {
                    if (-not [char]::IsControl($key.KeyChar) -and $value.Length -lt 8192) {
                        $value = $value.Insert($position, [string]$key.KeyChar)
                        $position++
                    }
                }
            }
        }
    }
    finally { $value = $null; [Console]::ResetColor() }
}

function Read-ServiceChoice([scriptblock]$OnResize) {
    try { return Read-ServiceConsoleText -OnResize $OnResize }
    catch [OperationCanceledException] { return '0' }
}

function Show-ServiceNotice([string]$Message, [string]$Color = 'Yellow') {
    $previousPercent = $script:Progress.Percent
    $previousStatus = $script:Progress.Status
    $previousStepsDone = $script:Progress.StepsDone; $previousStepsTotal = $script:Progress.StepsTotal
    Clear-ServiceScreen 'SERVICE'
    Write-Host $Message -ForegroundColor $Color
    if ($Color -eq 'Red') { Write-ServiceProgress ('Операция остановлена: ' + $previousStatus) $previousPercent -Completed -Failed -StepsDone $previousStepsDone -StepsTotal $previousStepsTotal }
    elseif ($Color -eq 'Green') { Write-ServiceProgress 'Завершено' 100 -Completed -StepsDone $previousStepsTotal -StepsTotal $previousStepsTotal }
    try { [void](Read-ServiceConsoleText ': Enter для продолжения ') }
    catch [OperationCanceledException] { }
}

function Invoke-ServiceElevation([string]$ScriptPath) {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    $executable = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    if (-not (Test-Path -LiteralPath $executable)) { Stop-ServiceOperation 'Windows PowerShell 5.1 is required for Windows DPAPI/ACL service operations.' }
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            & $executable -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -Action Menu
            exit $LASTEXITCODE
        }
        return $true
    }
    # Only the menu is relaunched. No credentials or arbitrary command text is forwarded.
    if ($ScriptPath.Contains('"')) { Stop-ServiceOperation 'Invalid service script path.' }
    try {
        $child = Start-Process -FilePath $executable -Verb RunAs -WorkingDirectory ([IO.Path]::GetDirectoryName($ScriptPath)) -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $ScriptPath + '"'), '-Action', 'Menu') -Wait -PassThru
        exit $child.ExitCode
    }
    catch [ComponentModel.Win32Exception] {
        if ($_.Exception.NativeErrorCode -eq 1223) { throw [OperationCanceledException]::new() }
        Stop-ServiceOperation 'Could not restart SERVICE as administrator.'
    }
}

Export-ModuleMember -Function Assert-ServiceConsole, Clear-ServiceScreen, Write-ServiceOption, Write-ServiceStatus, Read-ServiceConsoleText, Read-ServiceChoice, Show-ServiceNotice, Invoke-ServiceElevation, Read-ServiceKey, Enable-ServiceProgressUI, Test-ServiceProgressUI, Get-ServiceProgressText, Write-ServiceProgress, Refresh-ServiceProgress, Complete-ServiceProgress

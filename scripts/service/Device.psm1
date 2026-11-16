Set-StrictMode -Version Latest

function Invoke-ServiceInspection([string]$Root, [string]$Port, [string]$PythonPath) {
    if ($Port -notmatch '^COM[1-9][0-9]*$') { Stop-ServiceOperation 'Inspection requires a Windows COM port.' }
    if (-not $PythonPath) { $PythonPath = Join-Path $Root '.local/diagnostics/Scripts/python.exe' }
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        Stop-ServiceOperation 'Pass -PythonPath for an environment with scripts/diagnostics-requirements.txt installed.'
    }
    # This existing helper only reads identity and selected eFuse flags, never keys.
    & $PythonPath (Join-Path $Root 'scripts/inspect_board.py') --port $Port
    if ($LASTEXITCODE -ne 0) { Stop-ServiceOperation 'Read-only inspection failed.' }
}

Export-ModuleMember -Function Invoke-ServiceInspection

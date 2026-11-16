Set-StrictMode -Version Latest

function Get-ServiceToolPaths([string]$Root) {
    $pioRoot = $env:PLATFORMIO_CORE_DIR
    if (-not $pioRoot) { $pioRoot = Join-Path $env:USERPROFILE '.platformio' }
    $buildPython = Join-Path $Root '.local/build-tools/Scripts/python.exe'
    $existingBuild = Join-Path $pioRoot 'penv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $buildPython) -and (Test-Path -LiteralPath $existingBuild)) { $buildPython = $existingBuild }
    return [pscustomobject]@{
        BuildPython = $buildPython
        ServicePython = Join-Path $Root '.local/service-tools/Scripts/python.exe'
        Idf = Join-Path $pioRoot 'packages/framework-espidf'
        PioRoot = $pioRoot
    }
}

function Test-ServiceDependencies([string]$Root) {
    $paths = Get-ServiceToolPaths $Root
    $missing = [Collections.Generic.List[string]]::new()
    foreach ($kind in @('build', 'service')) {
        $python = if ($kind -eq 'build') { $paths.BuildPython } else { $paths.ServicePython }
        if (-not (Test-Path -LiteralPath $python)) { $missing.Add($kind + ': Python'); continue }
        try {
            $result = Invoke-ServiceProcess $python @((Join-Path $Root 'scripts/service_dependencies.py'), '--kind', $kind, '--root', $Root, '--pio-root', $paths.PioRoot) 'Проверка зависимостей' 45 -AllowFailure
            if ($result.ExitCode -ne 0) { $missing.Add($kind + ': packages or SDK') }
        } catch { $missing.Add($kind + ': unavailable') }
    }
    return [pscustomobject]@{ Ready = ($missing.Count -eq 0); Missing = $missing.ToArray(); Paths = $paths }
}

function Add-ServiceUserPath([string[]]$Directories) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = [Collections.Generic.List[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($part in @($Directories) + @($userPath -split ';')) {
        if ($part -and $seen.Add($part.TrimEnd('\'))) { $parts.Add($part) }
    }
    $newPath = $parts -join ';'
    if ($newPath.Length -gt 32760) { Stop-ServiceOperation 'User PATH is too long.' }
    if ($newPath -cne $userPath) { [Environment]::SetEnvironmentVariable('Path', $newPath, 'User') }
    foreach ($directory in $Directories) {
        if (@($env:Path -split ';') -notcontains $directory) { $env:Path = $directory + ';' + $env:Path }
    }
}

function Install-ServiceDependencies([string]$Root) {
    $status = Test-ServiceDependencies $Root
    if ($status.Ready) {
        Add-ServiceUserPath @([IO.Path]::GetDirectoryName($status.Paths.BuildPython))
        return $status
    }
    $bootstrap = ''
    $candidates = @($status.Paths.ServicePython, $status.Paths.BuildPython, (Join-Path (Get-ServiceHome) 'tools/python313/python.exe'))
    foreach ($command in @(Get-Command python.exe -ErrorAction SilentlyContinue)) { $candidates += $command.Source }
    foreach ($python in $candidates) {
        if (-not (Test-Path -LiteralPath $python) -or $python -match '\\Microsoft\\WindowsApps\\') { continue }
        $check = Invoke-ServiceProcess $python @('-c', 'import sys,venv;sys.exit(0 if (3,10)<=sys.version_info[:2]<(3,14) else 1)') 'Проверка Python' 30 -AllowFailure
        if ($check.ExitCode -eq 0) { $bootstrap = $python; break }
    }
    if (-not $bootstrap) {
        $tools = Join-Path (Get-ServiceHome) 'tools'
        [void][IO.Directory]::CreateDirectory($tools)
        $installer = Join-Path $tools 'python-3.13.17-amd64.exe'
        $target = Join-Path $tools 'python313'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Progress -Id 1 -Activity 'Установка Python' -Status 'Загрузка с python.org'
        Invoke-WebRequest -UseBasicParsing -Uri 'https://www.python.org/ftp/python/3.13.17/python-3.13.17-amd64.exe' -OutFile $installer -TimeoutSec 180
        $signature = Get-AuthenticodeSignature -LiteralPath $installer
        if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
            Stop-ServiceOperation 'Python installer signature verification failed.'
        }
        [void](Invoke-ServiceProcess $installer @('/quiet', 'InstallAllUsers=0', 'PrependPath=0', 'Include_launcher=0', 'Include_test=0', ('TargetDir=' + $target)) 'Установка Python' 900)
        $bootstrap = Join-Path $target 'python.exe'
        Add-ServiceUserPath @($target, (Join-Path $target 'Scripts'))
    }
    $paths = Get-ServiceToolPaths $Root
    foreach ($kind in @('build', 'service')) {
        $python = if ($kind -eq 'build') { $paths.BuildPython } else { $paths.ServicePython }
        if (Test-Path -LiteralPath $python) {
            $check = Invoke-ServiceProcess $python @('-c', 'import sys,venv;sys.exit(0 if (3,10)<=sys.version_info[:2]<(3,14) else 1)') 'Проверка окружения' 30 -AllowFailure
            if ($check.ExitCode -ne 0) {
                $localBase = [IO.Path]::GetFullPath((Join-Path $Root '.local')).TrimEnd('\') + '\'
                $environment = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($python)))
                if ($kind -eq 'build' -and -not $environment.StartsWith($localBase, [StringComparison]::OrdinalIgnoreCase)) {
                    $python = Join-Path $Root '.local/build-tools/Scripts/python.exe'
                    $paths.BuildPython = $python
                    $environment = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($python)))
                }
                if (-not $environment.StartsWith($localBase, [StringComparison]::OrdinalIgnoreCase)) { Stop-ServiceOperation 'Refusing to replace an external Python environment.' }
                Assert-ServicePlainPath $environment
                if (Test-Path -LiteralPath $environment) {
                    $retired = $environment + '.retired-' + [Guid]::NewGuid().ToString('N')
                    if (-not [IO.Path]::GetFullPath($retired).StartsWith($localBase, [StringComparison]::OrdinalIgnoreCase)) { Stop-ServiceOperation 'Invalid retired environment path.' }
                    Move-Item -LiteralPath $environment -Destination $retired
                }
            }
        }
        if (-not (Test-Path -LiteralPath $python)) {
            $environment = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($python))
            [void](Invoke-ServiceProcess $bootstrap @('-m', 'venv', $environment) 'Создание окружения Python' 180)
        }
        [void](Invoke-ServiceProcess $python @('-m', 'pip', 'install', '--no-input', '--retries', '2', '--timeout', '30', 'pip==25.1.1', 'setuptools==80.9.0', 'wheel==0.45.1') 'Подготовка pip' 900)
        $requirements = if ($kind -eq 'build') { 'scripts/build-requirements.txt' } else { 'scripts/security-requirements.txt' }
        [void](Invoke-ServiceProcess $python @('-m', 'pip', 'install', '--no-input', '--retries', '2', '--timeout', '30', '-r', (Join-Path $Root $requirements)) 'Установка библиотек' 1800)
    }
    foreach ($environment in @('c3-test-no-oled', 'c3-test-oled', 'c3-production-no-oled', 'c3-production-oled')) {
        [void](Invoke-ServiceProcess $paths.BuildPython @('-m', 'platformio', 'run', '--project-dir', $Root, '-e', $environment) ('Подготовка SDK: ' + $environment) 3600)
    }
    Add-ServiceUserPath @([IO.Path]::GetDirectoryName($paths.BuildPython))
    $status = Test-ServiceDependencies $Root
    if (-not $status.Ready) { Stop-ServiceOperation 'Dependency verification failed after installation.' }
    return $status
}

Export-ModuleMember -Function Get-ServiceToolPaths, Test-ServiceDependencies, Install-ServiceDependencies, Add-ServiceUserPath

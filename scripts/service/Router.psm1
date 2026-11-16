Set-StrictMode -Version Latest

function Get-ServiceRouterInformation($Configuration, [switch]$Interfaces,
    [string]$Root = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)) {
    if (-not $Configuration.RouterAddress) { Stop-ServiceOperation 'Сначала укажите адрес Keenetic в CFG/NETWORK.' }
    if ($Interfaces -and (-not $Configuration.RouterLogin -or -not $Configuration.RouterPassword)) {
        Stop-ServiceOperation 'Сначала заполните логин и пароль Keenetic в CFG/LOGIN.'
    }
    $python = Join-Path $Root '.local/service-tools/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        Stop-ServiceOperation 'Сначала установите зависимости: SERVICE, пункт 1.'
    }
    $homeDirectory = Get-ServiceHome
    Assert-ServicePlainPath $homeDirectory
    [void][IO.Directory]::CreateDirectory($homeDirectory)
    $directory = [IO.Path]::GetFullPath((Join-Path $homeDirectory ('.router-' + [Guid]::NewGuid().ToString('N'))))
    New-ServicePrivateDirectory $directory
    $path = Join-Path $directory 'request.json'
    $request = [ordered]@{ address = [string]$Configuration.RouterAddress; port = [int]$Configuration.RouterPort }
    try {
        if ($Interfaces) { $request.login = [string]$Configuration.RouterLogin; $request.password = [string]$Configuration.RouterPassword }
        Write-ServiceUtf8 $path (ConvertTo-Json -InputObject $request -Compress)
        Set-ServicePrivateFile $path
        $arguments = @((Join-Path $Root 'scripts/service_router.py'), '--request', $path)
        if ($Interfaces) { $arguments += '--interfaces' }
        $result = Invoke-ServiceEventTool $python $arguments 'Получение параметров Keenetic' 50
        if ($result.tls_verified -ne $true -or $result.https_name -isnot [string] -or -not $result.https_name) {
            Stop-ServiceOperation 'Keenetic не подтвердил HTTPS-имя.'
        }
        return $result
    }
    finally {
        $request.Clear()
        # Delete only the unique private staging directory created above.
        Assert-ServicePlainPath $directory
        if ([IO.Path]::GetDirectoryName($directory) -ine [IO.Path]::GetFullPath($homeDirectory) -or
            [IO.Path]::GetFileName($directory) -notmatch '^\.router-[a-f0-9]{32}$') {
            Stop-ServiceOperation 'Некорректный путь временных параметров Keenetic.'
        }
        Remove-Item -LiteralPath $directory -Recurse -Force
    }
}

Export-ModuleMember -Function Get-ServiceRouterInformation

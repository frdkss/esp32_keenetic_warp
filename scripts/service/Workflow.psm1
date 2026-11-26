Set-StrictMode -Version Latest

function Get-ServiceSelectedDevice([string]$Root, $State, $Paths) {
    if (-not $State.Port) { Stop-ServiceOperation 'Выберите плату: SERVICE/CFG, пункт 3.' }
    $matching = @(Get-ServicePorts | Where-Object { $_.Port -eq $State.Port })
    if ($matching.Count -ne 1 -or ($State.UsbId -and $matching[0].UsbId -and $State.UsbId -ne $matching[0].UsbId)) {
        Stop-ServiceOperation 'Выбранный порт исчез или устройство изменилось. Выберите плату заново.'
    }
    $device = Invoke-ServiceEventTool $Paths.ServicePython @((Join-Path $Root 'scripts/service_device.py'), 'identify', '--port', $State.Port) 'Проверка выбранного USB'
    return [string]$device.mac
}

function Read-ServiceBackupRequest([string]$Directory, [switch]$Confirm) {
    $passphrase = $null; $repeat = $null
    try {
        $passphrase = Read-ServiceConsoleText ': Пароль резервной копии: ' -Secret
        if ([Text.Encoding]::UTF8.GetByteCount($passphrase) -lt 16) { Stop-ServiceOperation 'Пароль копии должен содержать не меньше 16 байт UTF-8.' }
        if ($Confirm) {
            $repeat = Read-ServiceConsoleText ': Повторите пароль копии: ' -Secret
            if ($passphrase -cne $repeat) { Stop-ServiceOperation 'Пароли копии не совпадают.' }
        }
        $request = Join-Path $Directory 'request.secrets.json'
        Write-ServiceUtf8 $request (ConvertTo-Json -InputObject @{ passphrase = $passphrase } -Compress)
        return $request
    }
    finally { $passphrase = $null; $repeat = $null }
}

function Invoke-ServiceMenuKeys([string]$Root, $State, $Paths) {
    Clear-ServiceScreen 'SERVICE/KEYS'
    $mac = Get-ServiceSelectedDevice $Root $State $Paths
    $base = Join-Path (Get-ServiceHome) 'devices'
    Assert-ServicePlainPath $base
    [void][IO.Directory]::CreateDirectory((Get-ServiceHome))
    if (-not [IO.Directory]::Exists($base)) { New-ServicePrivateDirectory $base }
    $vault = Join-Path $base $mac
    if (-not $State.Devices.Contains($mac)) {
        $State.Devices[$mac] = [ordered]@{ Vault = $vault; Backup = ''; Evidence = ''; Port = $State.Port }
    }
    $record = $State.Devices[$mac]
    $vault = $record.Vault
    if (-not (Test-Path -LiteralPath $vault)) {
        $evidence = Join-Path $base ('evidence-' + $mac + '-' + [Guid]::NewGuid().ToString('N') + '.json')
        [void](Invoke-ServiceProcess $Paths.ServicePython @((Join-Path $Root 'scripts/security_device.py'), '--port', $State.Port, '--output', $evidence) 'Осмотр платы (сброс в ROM)' 180)
        $proof = ConvertFrom-Json ([IO.File]::ReadAllText($evidence))
        if ($proof.preflight -ne 'passed' -or $proof.identity.mac -cne $mac) { Stop-ServiceOperation 'Плата не соответствует поддерживаемому чистому профилю ESP32-C3.' }
        [void](Invoke-ServiceProcess $Paths.ServicePython @((Join-Path $Root 'scripts/security_store.py'), 'new', '--vault', $vault, '--evidence', $evidence, '--idf-path', $Paths.Idf) 'Создание ключей' 180)
        $record.Evidence = $evidence
    }
    $info = Invoke-ServiceEventTool $Paths.ServicePython @((Join-Path $Root 'scripts/service_device.py'), 'vault-info', '--vault', $vault) 'Проверка хранилища'
    if ($info.identity.mac -cne $mac) { Stop-ServiceOperation 'Хранилище ключей относится к другому устройству.' }
    $State.SelectedMac = $mac
    Save-ServiceState $State
    if ($record.Backup -and (Test-Path -LiteralPath $record.Backup)) {
        Show-ServiceNotice ('Ключи уже существуют и сохранены: ' + $vault + [Environment]::NewLine + 'Резервная копия: ' + $record.Backup) 'Green'
        return
    }
    Clear-ServiceScreen 'SERVICE/KEYS/BACKUP'
    Write-Host 'Ключи созданы. Выберите каталог резервной копии вне проекта и хранилища.'
    $destination = Read-ServiceConsoleText ': Каталог копии: '
    if (-not [IO.Path]::IsPathRooted($destination)) { Stop-ServiceOperation 'Нужен абсолютный путь каталога копии.' }
    Assert-ServicePlainPath $destination
    if (-not (Test-Path -LiteralPath $destination -PathType Container)) { Stop-ServiceOperation 'Каталог копии не существует.' }
    $backup = Join-Path $destination ($mac + '-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '.warpbackup')
    $stage = Join-Path $base ('.backup-' + [Guid]::NewGuid().ToString('N'))
    New-ServicePrivateDirectory $stage
    try {
        $request = Read-ServiceBackupRequest $stage -Confirm
        [void](Invoke-ServiceProcess $Paths.ServicePython @((Join-Path $Root 'scripts/security_store.py'), 'backup', '--vault', $vault, '--backup', $backup, '--request', $request, '--idf-path', $Paths.Idf) 'Создание и проверка резервной копии' 180)
        $record.Backup = $backup
        Save-ServiceState $State
    }
    finally { Remove-ServiceWorkflowStage $stage $base }
    Show-ServiceNotice ('Ключи и проверенная резервная копия сохранены.' + [Environment]::NewLine + 'После осмотра плата может оставаться в ROM. RESET возвращает её приложение.') 'Green'
}

function Remove-ServiceWorkflowStage([string]$Stage, [string]$ParentDirectory) {
    Assert-ServicePlainPath $Stage
    $full = [IO.Path]::GetFullPath($Stage)
    $parent = [IO.Path]::GetFullPath($ParentDirectory).TrimEnd('\', '/')
    if ([IO.Path]::GetDirectoryName($full) -cne $parent -or -not [IO.Path]::GetFileName($full).StartsWith('.')) {
        Stop-ServiceOperation 'Invalid private workflow cleanup path.'
    }
    if ([IO.Directory]::Exists($full)) { Remove-Item -LiteralPath $full -Recurse -Force }
}

function Invoke-ServiceMenuWifiUpdate([string]$Root, $State, $Paths) {
    Clear-ServiceScreen 'SERVICE/WIFI'
    Write-Host ('Порт: ' + $State.Port)
    Write-ServiceProgress 'Проверка выбранной платы' 0 -StepsDone 0 -StepsTotal 5
    $mac = Get-ServiceSelectedDevice $Root $State $Paths
    if (-not $State.Devices.Contains($mac)) { Stop-ServiceOperation 'Сначала создайте ключи выбранной платы: пункт 3.' }
    $record = $State.Devices[$mac]
    $State.SelectedMac = $mac
    Save-ServiceState $State
    $tools = Resolve-ServiceTools $Root $Paths.ServicePython $Paths.Idf
    $configuration = ConvertTo-ServiceConfiguration $State.Configuration
    $environment = if ($configuration.OledEnabled) { 'c3-production-oled' } else { 'c3-production-no-oled' }
    $tools | Add-Member -NotePropertyName Environment -NotePropertyValue $environment
    Write-ServiceProgress 'Поиск микроконтроллера в сети' 15 -StepsDone 1 -StepsTotal 5
    $found = Invoke-ServiceWifiDiscover $Root $tools $record.Vault 15
    if (@($found.devices | Where-Object { $_.mac -eq $mac }).Count -eq 0) {
        Stop-ServiceOperation 'Устройство выбранной платы не найдено в сети. Проверьте подключение к той же LAN.'
    }
    Write-ServiceProgress 'Сборка прошивки' 35 -StepsDone 2 -StepsTotal 5
    [void](Invoke-ServiceProcess $Paths.BuildPython @('-m', 'platformio', 'run', '--project-dir', $Root, '-e', $environment) 'Сборка прошивки' 3600)
    $package = Join-Path (Join-Path $Root '.local/service') ('wifi-' + [Guid]::NewGuid().ToString('N'))
    Write-ServiceProgress 'Подготовка пакета прошивки' 60 -StepsDone 3 -StepsTotal 5
    Invoke-ServiceUpdate $Root $tools $record.Vault $package -Prepare
    Write-ServiceProgress 'Загрузка по Wi-Fi и проверка запуска' 80 -StepsDone 4 -StepsTotal 5
    [void](Invoke-ServiceWifiUpdate $Root $tools $record.Vault $package 300)
    Show-ServiceNotice 'Прошивка загружена по Wi-Fi, запуск нового слота подтверждён.' 'Green'
}

function Invoke-ServiceMenuFlash([string]$Root, $State, $Paths) {
    Clear-ServiceScreen 'SERVICE/FLASH'
    Write-Host ('Порт: ' + $State.Port)
    Write-ServiceProgress 'Проверка выбранной платы' 0 -StepsDone 0 -StepsTotal 5
    $mac = Get-ServiceSelectedDevice $Root $State $Paths
    if (-not $State.Devices.Contains($mac)) { Stop-ServiceOperation 'Сначала создайте ключи выбранной платы: пункт 3.' }
    $record = $State.Devices[$mac]
    $State.SelectedMac = $mac
    Save-ServiceState $State
    $tools = Resolve-ServiceTools $Root $Paths.ServicePython $Paths.Idf
    $receiptPath = Join-Path $record.Vault 'provision-receipt.json'
    Assert-ServicePlainPath $receiptPath
    if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
        $receipt = ConvertFrom-Json ([IO.File]::ReadAllText($receiptPath))
        $bootAuthenticated = $receipt.PSObject.Properties['authenticated_image_and_configuration'] -and
            $receipt.authenticated_image_and_configuration -is [bool] -and $receipt.authenticated_image_and_configuration
        if ($receipt.result -ne 'verified' -and -not $bootAuthenticated) {
            Write-Host 'Найдена незавершённая проверка защиты. Продолжается только проверка существующей записи.'
            [void](Invoke-ServiceProvisionVerification $Root $tools $record.Vault $State.Port)
            Show-ServiceNotice 'Защита, ранее записанная прошивка и запуск мониторинга подтверждены.' 'Green'
            return
        }
        # Once the installed image/CFG have authenticated, normal protected
        # updates may apply corrected settings even if monitoring is not ready.
    }
    $configuration = ConvertTo-ServiceConfiguration $State.Configuration
    $environment = if ($configuration.OledEnabled) { 'c3-production-oled' } else { 'c3-production-no-oled' }
    $tools | Add-Member -NotePropertyName Environment -NotePropertyValue $environment
    Write-ServiceProgress 'Создание CFG' 20 -StepsDone 1 -StepsTotal 5
    Write-ServiceConfigurationFromVault $Root $configuration $tools $record.Vault
    Write-ServiceProgress 'Сборка прошивки' 40 -StepsDone 2 -StepsTotal 5
    [void](Invoke-ServiceProcess $Paths.BuildPython @('-m', 'platformio', 'run', '--project-dir', $Root, '-e', $environment) 'Сборка прошивки' 3600)
    $base = Join-Path $Root '.local/service'
    $package = Join-Path $base ('update-' + [Guid]::NewGuid().ToString('N'))
    Write-ServiceProgress 'Подготовка пакета прошивки' 60 -StepsDone 3 -StepsTotal 5
    Invoke-ServiceUpdate $Root $tools $record.Vault $package -Prepare -ApplyConfiguration
    Write-ServiceProgress 'Проверка приложения' 80 -StepsDone 4 -StepsTotal 5
    $running = Invoke-ServiceEventTool $tools.Python @((Join-Path $Root 'scripts/service_device.py'), 'probe', '--port', $State.Port, '--vault', $record.Vault, '--package', $package, '--idf-path', $tools.Idf) 'Проверка работающего приложения'
    $timeout = [Math]::Min(900, [Math]::Max(180, 120 + 2 * ($configuration.TargetUrls.Count + $configuration.ControlUrls.Count) * ($configuration.ConnectTimeoutSeconds + $configuration.ReadTimeoutSeconds + 1)))
    if ($running.running) {
        Invoke-ServiceUpdate $Root $tools $record.Vault $package $State.Port $timeout
        Show-ServiceNotice 'Обновление, текущий CFG и запуск мониторинга подтверждены.' 'Green'
        return
    }
    Write-ServiceProgress 'Проверка первичной платы' 0 -StepsDone 0 -StepsTotal 3
    if (-not $record.Backup -or -not (Test-Path -LiteralPath $record.Backup)) { Stop-ServiceOperation 'Для первичной защиты нужна резервная копия ключей. Выполните пункт 3.' }
    $stage = Join-Path $base ('.provision-' + [Guid]::NewGuid().ToString('N'))
    New-ServicePrivateDirectory $stage
    try {
        $evidence = Join-Path $stage 'evidence.json'
        [void](Invoke-ServiceProcess $tools.Python @((Join-Path $Root 'scripts/security_device.py'), '--port', $State.Port, '--output', $evidence) 'Проверка первичной платы' 180)
        Write-ServiceProgress 'Проверка пакета и резервной копии' 33 -StepsDone 1 -StepsTotal 3
        $request = Read-ServiceBackupRequest $stage
        $initial = Join-Path $base ('initial-' + [Guid]::NewGuid().ToString('N'))
        [void](Invoke-ServiceProcess $tools.Python @((Join-Path $Root 'scripts/security_store.py'), 'prepare', '--vault', $record.Vault, '--backup', $record.Backup, '--request', $request, '--evidence', $evidence, '--output', $initial, '--environment', $environment, '--idf-path', $tools.Idf) 'Проверка первичного пакета и резервной копии' 300)
        Clear-ServiceScreen 'SERVICE/PROVISION'
        Write-ServiceProgress 'Сверка устройства перед записью' 66 -StepsDone 2 -StepsTotal 3
        Write-Host ('Порт: ' + $State.Port + ' | ESP32-C3 v0.4 | 4 МБ | MAC: ' + $mac)
        Write-Host 'Будут записаны прошивка и CFG, включены Flash Encryption Release и Secure Boot v2.'
        Write-Host 'JTAG отключается; USB Secure Download сохраняется. Изменения eFuse необратимы.' -ForegroundColor Yellow
        Write-Host 'Физическая приёмка защищённого USB/BOOT/RESET ещё не выполнена.' -ForegroundColor Yellow
        Write-Host ('Пакет: ' + $initial)
        Write-Host 'MAC считывается автоматически и сверяется с выбранной платой и ключами.'
        $currentMac = Get-ServiceSelectedDevice $Root $State $Paths
        if ($currentMac -cne $mac) { Stop-ServiceOperation 'Устройство изменилось во время подготовки. Запись отменена.' }
        [void](Invoke-ServiceProvisioning $initial $Root $tools $record.Vault $record.Backup $State.Port $request $currentMac $timeout)
        Show-ServiceNotice 'Первичная защита, прошивка, CFG и запуск мониторинга подтверждены.' 'Green'
    }
    finally { Remove-ServiceWorkflowStage $stage $base }
}

Export-ModuleMember -Function Invoke-ServiceMenuKeys, Invoke-ServiceMenuFlash, Invoke-ServiceMenuWifiUpdate

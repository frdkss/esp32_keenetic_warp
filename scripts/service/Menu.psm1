Set-StrictMode -Version Latest
$script:Days = @('Воскресенье', 'Понедельник', 'Вторник', 'Среда', 'Четверг', 'Пятница', 'Суббота')
$script:Policies = @('Любой нерабочий сервис', 'Половина', 'Больше половины', 'Все')

function Show-ServiceBack {
    Write-Host ''
    Write-ServiceOption '0. Назад' 'Red'
    Write-ServiceOption '00. Выход'
}

function Show-ServiceAccountScreen([string]$Title, [string]$Label, [string]$Name, [bool]$HasPassword, [switch]$Confirm) {
    Clear-ServiceScreen $Title
    Write-Host ($Label + ': ' + $Name)
    Write-Host ('Password: ' + $(if ($HasPassword) { '********' } else { '' }))
    if ($Confirm) {
        Write-Host ''
        Write-ServiceOption '1. Подтвердить?' 'Green'
        Write-ServiceOption ('2. Изменить ' + $Label) 'DarkYellow'
        Write-ServiceOption '3. Изменить Password' 'DarkYellow'
        Show-ServiceBack
    }
}

function Invoke-ServiceAccountMenu($State, [switch]$Wifi) {
    $drawAccount = Get-Command Show-ServiceAccountScreen
    $title = if ($Wifi) { 'SERVICE/CFG/CONNECTION' } else { 'SERVICE/CFG/LOGIN' }
    $nameKey = if ($Wifi) { 'WifiSsid' } else { 'RouterLogin' }
    $passwordKey = if ($Wifi) { 'WifiPassword' } else { 'RouterPassword' }
    $label = if ($Wifi) { 'SSID' } else { 'Login' }
    $name = [string]$State.Configuration[$nameKey]
    $password = [string]$State.Configuration[$passwordKey]
    $edit = if ($name) { '' } else { 'both' }
    try {
        while ($true) {
            Show-ServiceAccountScreen $title $label $name ([bool]$password)
            $redraw = { & $drawAccount $title $label $name ([bool]$password) }.GetNewClosure()
            if ($edit -in @('both', 'name')) {
                $name = Read-ServiceConsoleText ($label + ': ') $name -Row 1 -OnResize $redraw
            }
            if ($edit -in @('both', 'password')) {
                $redraw = { & $drawAccount $title $label $name ([bool]$password) }.GetNewClosure()
                $password = Read-ServiceConsoleText 'Password: ' -Secret -Row 2 -OnResize $redraw
            }
            $edit = ''
            Show-ServiceAccountScreen $title $label $name ([bool]$password) -Confirm
            $redraw = { & $drawAccount $title $label $name ([bool]$password) -Confirm }.GetNewClosure()
            switch (Read-ServiceChoice -OnResize $redraw) {
                '1' {
                    $values = [ordered]@{}; $values[$nameKey] = $name; $values[$passwordKey] = $password
                    try { Set-ServiceDraftValues $State $values; return $false }
                    catch { Show-ServiceNotice (Get-ServiceSafeError $_.Exception) 'Red' }
                }
                '2' { $edit = 'name' }
                '3' { $edit = 'password' }
                '0' { return $false }
                '00' { return $true }
            }
        }
    }
    catch [OperationCanceledException] { return $false }
    finally { $password = $null }
}

function Show-ServiceModulesScreen($State) {
    Clear-ServiceScreen 'SERVICE/CFG/MODULES'
    $enabled = [bool]$State.Configuration.OledEnabled
    Write-ServiceStatus '1. Дисплей ' $(if ($enabled) { 'ВКЛ' } else { 'ОТКЛ' }) $enabled
    if ($enabled) { Write-Host 'OLED 72x40: SDA GPIO5, SCL GPIO6.' }
    Show-ServiceBack
}

function Invoke-ServiceModulesMenu($State) {
    $drawModules = Get-Command Show-ServiceModulesScreen
    while ($true) {
        Show-ServiceModulesScreen $State
        $redraw = { & $drawModules $State }.GetNewClosure()
        switch (Read-ServiceChoice -OnResize $redraw) {
            '1' { Set-ServiceDraftValues $State @{ OledEnabled = [int](-not $State.Configuration.OledEnabled) } }
            '0' { return $false }
            '00' { return $true }
        }
    }
}

function Show-ServiceBoardScreen($State, $Ports) {
    Clear-ServiceScreen 'SERVICE/CFG/BOARD'
    for ($index = 0; $index -lt $Ports.Count; $index++) {
        $selected = $Ports[$index].Port -eq $State.Port
        Write-ServiceStatus (($index + 1).ToString() + '. ' + $Ports[$index].Port + ' ' + $Ports[$index].Name + ' ') $(if ($selected) { 'ENABLED' } else { 'DISABLED' }) $selected
    }
    if (-not $Ports.Count) { Write-Host 'COM-порты не найдены.' -ForegroundColor Yellow }
    Write-Host ''
    Write-Host 'R. Обновить список'
    Show-ServiceBack
}

function Invoke-ServiceBoardMenu($State) {
    $drawBoard = Get-Command Show-ServiceBoardScreen
    while ($true) {
        $ports = @(Get-ServicePorts)
        Show-ServiceBoardScreen $State $ports
        $redraw = { & $drawBoard $State $ports }.GetNewClosure()
        $choice = Read-ServiceChoice -OnResize $redraw
        if ($choice -eq '0') { return $false }
        if ($choice -eq '00') { return $true }
        $number = 0
        if ([int]::TryParse($choice, [ref]$number) -and $number -ge 1 -and $number -le $ports.Count) {
            $selected = $ports[$number - 1]
            if ($State.Port -ne $selected.Port -or $State.UsbId -ne $selected.UsbId) { $State.SelectedMac = '' }
            $State.Port = $selected.Port; $State.UsbId = $selected.UsbId
            Save-ServiceState $State
        }
    }
}

function Get-ServiceNetworkFields {
    return @(
        @{ Key = 'TargetUrls'; Label = 'Домены проверки WARP'; Type = 'urls' }
        @{ Key = 'ControlUrls'; Label = 'Домены проверки NETWORK'; Type = 'urls' }
        @{ Key = 'CheckIntervalSeconds'; Label = 'Интервал циклов, сек'; Type = 'number' }
        @{ Key = 'ConnectTimeoutSeconds'; Label = 'Таймаут соединения, сек'; Type = 'number' }
        @{ Key = 'FailureThreshold'; Label = 'Подтверждение сбоя, циклов'; Type = 'number' }
        @{ Key = 'TargetFailurePolicy'; Label = 'Порог целевых отказов'; Type = 'policy' }
        @{ Key = 'WarmupSeconds'; Label = 'Ожидание после включения, сек'; Type = 'number' }
        @{ Key = 'CooldownSeconds'; Label = 'Пауза между попытками восстановления'; Type = 'cooldown' }
        @{ Key = 'ScheduleTime'; Label = 'Плановый перезапуск'; Type = 'schedule' }
        @{ Key = 'RouterAddress'; Label = 'Адрес Keenetic'; Type = 'text' }
        @{ Key = 'RouterHttpsName'; Label = 'HTTPS-имя Keenetic (авто)'; Type = 'automatic' }
        @{ Key = 'RouterPort'; Label = 'HTTPS-порт Keenetic'; Type = 'number' }
        @{ Key = 'WarpInterface'; Label = 'Интерфейс WARP'; Type = 'interface' }
        @{ Key = 'Timezone'; Label = 'Часовой пояс POSIX'; Type = 'text' }
        @{ Key = 'ReadTimeoutSeconds'; Label = 'Таймаут чтения, сек'; Type = 'number' }
        @{ Key = 'DisablePauseSeconds'; Label = 'Пауза выключения/включения, сек'; Type = 'number' }
        @{ Key = 'EnableAutoRecovery'; Label = 'Автоматическое восстановление'; Type = 'toggle' }
    )
}

function Get-ServiceNetworkValue($Configuration, $Field, [int]$Component = -1) {
    $value = $Configuration[$Field.Key]
    switch ($Field.Type) {
        'urls' { return (@($value) -join ', ') }
        'policy' { return $script:Policies[[int]$value] }
        'cooldown' { return (([int]$value / 60).ToString() + ' минут') }
        'toggle' { return $(if ($value) { 'Вкл' } else { 'Выкл' }) }
        'automatic' { return $(if ($value) { [string]$value } else { 'Enter: получить с роутера' }) }
        'interface' { return $(if ($value) { [string]$value } else { 'Enter: выбрать из списка' }) }
        'schedule' {
            $pieces = @($(if ($Configuration.EnableWeeklyRestart) { 'Вкл' } else { 'Выкл' }), $script:Days[[int]$Configuration.ScheduleDay]) + @($Configuration.ScheduleTime -split ':')
            if ($Component -ge 0) { $pieces[$Component] = '<' + $pieces[$Component] + '>' }
            return ($pieces[0] + ' | ' + $pieces[1] + ' | ' + $pieces[2] + ':' + $pieces[3])
        }
        default { return [string]$value }
    }
}

function Show-ServiceNetworkScreen($Configuration, $Fields, [int]$Selected, [bool]$Editing, [int]$Component = -1, [string]$RouterStatus = '') {
    Clear-ServiceScreen 'SERVICE/CFG/NETWORK'
    $height = [Math]::Max(1, [Console]::WindowHeight - 7)
    $start = [Math]::Max(0, $Selected - $height + 1)
    $width = [Math]::Max(10, [Console]::WindowWidth - 1)
    for ($index = $start; $index -lt [Math]::Min($Fields.Count, $start + $height); $index++) {
        $focus = if ($index -eq $Selected -and $Editing) { $Component } else { -1 }
        $text = $Fields[$index].Label + ': ' + (Get-ServiceNetworkValue $Configuration $Fields[$index] $focus)
        $text = $text.PadRight($width).Substring(0, $width)
        if ($index -eq $Selected) {
            [Console]::BackgroundColor = if ($Editing) { 'White' } else { 'DarkCyan' }
            [Console]::ForegroundColor = if ($Editing) { 'Black' } else { 'White' }
        }
        Write-Host $text
        [Console]::ResetColor()
    }
    $status = if ($RouterStatus) { $RouterStatus } else { 'HTTPS-имя загружается автоматически. WARP: Enter открывает список.' }
    Write-Host $status.Substring(0, [Math]::Min($status.Length, $width)) -ForegroundColor Yellow
    $hint = 'Стрелки: выбор | Enter: изменить | R: обновить HTTPS-имя | Esc: назад'
    Write-Host $hint.Substring(0, [Math]::Min($hint.Length, $width))
    Write-Host '0. Назад     00. Выход' -ForegroundColor Red
    [Console]::SetCursorPosition(0, [Console]::WindowTop + [Console]::WindowHeight - 1)
    [Console]::Write(': ')
    [Console]::CursorVisible = $false
}

function ConvertTo-ServiceDomainList([string]$Text) {
    $values = @()
    foreach ($item in ($Text -split ',')) {
        $item = $item.Trim()
        if (-not $item) { Stop-ServiceOperation 'Введите домены через запятую без пустых элементов.' }
        if ($item -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $item = 'https://' + $item }
        $values += $item
    }
    return ,$values
}

function Update-ServiceRouterConfiguration($State, [switch]$Interfaces) {
    $router = Get-ServiceRouterInformation $State.Configuration -Interfaces:$Interfaces
    if ($State.Configuration.RouterHttpsName -cne $router.https_name) {
        Set-ServiceDraftValues $State @{ RouterHttpsName = $router.https_name }
    }
    return $router
}

function Show-ServiceWarpScreen($Interfaces, [int]$Selected, [string]$Current) {
    Clear-ServiceScreen 'SERVICE/CFG/NETWORK/WARP'
    $width = [Math]::Max(10, [Console]::WindowWidth - 1)
    $height = [Math]::Max(1, [Console]::WindowHeight - 6)
    $start = [Math]::Max(0, $Selected - $height + 1)
    for ($index = $start; $index -lt [Math]::Min($Interfaces.Count, $start + $height); $index++) {
        $item = $Interfaces[$index]
        $text = $item.id
        if ($item.description) { $text += ' | ' + $item.description }
        $text += ' | ' + $(if ($item.enabled) { 'включён' } else { 'выключен' })
        if ($item.connected) { $text += ', подключён' }
        if ($item.id -ceq $Current) { $text += ' [ВЫБРАН]' }
        if ($index -eq $Selected) { [Console]::BackgroundColor = 'DarkCyan'; [Console]::ForegroundColor = 'White' }
        Write-Host $text.PadRight($width).Substring(0, $width)
        [Console]::ResetColor()
    }
    $hint = 'Стрелки: выбор | Enter: сохранить в CFG | Esc: отменить'
    Write-Host $hint.Substring(0, [Math]::Min($hint.Length, $width))
    Write-Host '0. Назад     00. Выход' -ForegroundColor Red
    [Console]::SetCursorPosition(0, [Console]::WindowTop + [Console]::WindowHeight - 1)
    [Console]::Write(': ')
    [Console]::CursorVisible = $false
}

function Select-ServiceWarpInterface($Interfaces, [string]$Current) {
    if (-not $Interfaces.Count) { Stop-ServiceOperation 'На Keenetic не найдены интерфейсы WireGuard. Сначала создайте подключение на роутере.' }
    $selected = 0
    for ($index = 0; $index -lt $Interfaces.Count; $index++) {
        if ($Interfaces[$index].id -ceq $Current) { $selected = $index; break }
    }
    $drawWarp = Get-Command Show-ServiceWarpScreen
    while ($true) {
        Show-ServiceWarpScreen $Interfaces $selected $Current
        $redraw = { & $drawWarp $Interfaces $selected $Current }.GetNewClosure()
        $key = Read-ServiceKey -OnResize $redraw
        if ($key.Key -eq 'Escape') { return [pscustomobject]@{ Interface = ''; Exit = $false } }
        if ($key.KeyChar -eq '0') {
            try { $choice = Read-ServiceConsoleText ': ' '0' -OnResize $redraw }
            catch [OperationCanceledException] { return [pscustomobject]@{ Interface = ''; Exit = $false } }
            if ($choice -in @('0', '00')) { return [pscustomobject]@{ Interface = ''; Exit = ($choice -eq '00') } }
        }
        if ($key.Key -in @('UpArrow', 'LeftArrow')) { $selected = ($selected + $Interfaces.Count - 1) % $Interfaces.Count }
        if ($key.Key -in @('DownArrow', 'RightArrow')) { $selected = ($selected + 1) % $Interfaces.Count }
        if ($key.Key -eq 'Enter') { return [pscustomobject]@{ Interface = $Interfaces[$selected].id; Exit = $false } }
    }
}

function Invoke-ServiceNetworkMenu($State) {
    $drawNetwork = Get-Command Show-ServiceNetworkScreen
    $fields = Get-ServiceNetworkFields
    $selected = 0
    $routerStatus = ''
    if ($State.Configuration.RouterAddress) {
        Show-ServiceNetworkScreen $State.Configuration $fields $selected $false
        try { [void](Update-ServiceRouterConfiguration $State); $routerStatus = 'HTTPS-имя получено автоматически и сохранено в CFG.' }
        catch { $routerStatus = Get-ServiceSafeError $_.Exception }
    }
    while ($true) {
        Show-ServiceNetworkScreen $State.Configuration $fields $selected $false -RouterStatus $routerStatus
        $redraw = { & $drawNetwork $State.Configuration $fields $selected $false -RouterStatus $routerStatus }.GetNewClosure()
        $key = Read-ServiceKey -OnResize $redraw
        if ($key.Key -eq 'Escape') { return $false }
        if ($key.KeyChar -eq '0') {
            try { $choice = Read-ServiceConsoleText ': ' '0' -OnResize $redraw }
            catch [OperationCanceledException] { return $false }
            if ($choice -eq '0') { return $false }
            if ($choice -eq '00') { return $true }
        }
        if ($key.Key -eq 'UpArrow') { $selected = ($selected + $fields.Count - 1) % $fields.Count }
        if ($key.Key -eq 'DownArrow') { $selected = ($selected + 1) % $fields.Count }
        if ($key.Key -notin @('Enter', 'R')) { continue }
        $field = if ($key.Key -eq 'R') { @{ Type = 'automatic' } } else { $fields[$selected] }
        try {
            Show-ServiceNetworkScreen $State.Configuration $fields $selected $true
            if ($field.Type -in @('automatic', 'interface')) {
                $router = Update-ServiceRouterConfiguration $State -Interfaces:($field.Type -eq 'interface')
                $routerStatus = 'HTTPS-имя получено автоматически и сохранено в CFG.'
                if ($field.Type -eq 'interface') {
                    $choice = Select-ServiceWarpInterface @($router.interfaces) ([string]$State.Configuration.WarpInterface)
                    if ($choice.Exit) { return $true }
                    if ($choice.Interface) { Set-ServiceDraftValues $State @{ WarpInterface = $choice.Interface } }
                }
                continue
            }
            if ($field.Type -in @('text', 'number', 'urls')) {
                $editRedraw = { & $drawNetwork $State.Configuration $fields $selected $true }.GetNewClosure()
                $text = Read-ServiceConsoleText ': ' (Get-ServiceNetworkValue $State.Configuration $field) -OnResize $editRedraw
                $value = if ($field.Type -eq 'urls') { ConvertTo-ServiceDomainList $text } else { $text }
                $values = [ordered]@{}; $values[$field.Key] = $value
                Set-ServiceDraftValues $State $values
                if ($field.Key -in @('RouterAddress', 'RouterPort')) {
                    try { [void](Update-ServiceRouterConfiguration $State); $routerStatus = 'HTTPS-имя получено автоматически и сохранено в CFG.' }
                    catch { $routerStatus = Get-ServiceSafeError $_.Exception }
                }
                continue
            }
            $working = [ordered]@{}
            foreach ($name in $State.Configuration.Keys) { $working[$name] = $State.Configuration[$name] }
            $component = 0
            $commit = $false
            while ($true) {
                Show-ServiceNetworkScreen $working $fields $selected $true $(if ($field.Type -eq 'schedule') { $component } else { -1 })
                $editRedraw = { & $drawNetwork $working $fields $selected $true $(if ($field.Type -eq 'schedule') { $component } else { -1 }) }.GetNewClosure()
                $editKey = Read-ServiceKey -OnResize $editRedraw
                if ($editKey.Key -eq 'Escape') { break }
                if ($editKey.Key -eq 'Enter') { $commit = $true; break }
                if ($field.Type -eq 'schedule' -and $editKey.Key -in @('LeftArrow', 'RightArrow')) {
                    $component = ($component + $(if ($editKey.Key -eq 'RightArrow') { 1 } else { 3 })) % 4
                    continue
                }
                if ($editKey.Key -notin @('LeftArrow', 'RightArrow', 'UpArrow', 'DownArrow')) { continue }
                $delta = if ($editKey.Key -in @('RightArrow', 'DownArrow')) { 1 } else { -1 }
                switch ($field.Type) {
                    'policy' { $working[$field.Key] = ([int]$working[$field.Key] + $delta + 4) % 4 }
                    'toggle' { $working[$field.Key] = [int](-not $working[$field.Key]) }
                    'cooldown' {
                        $options = @(300, 600, 900, 1200, 1800)
                        $position = [Array]::IndexOf($options, [int]$working[$field.Key])
                        $working[$field.Key] = $options[($position + $delta + $options.Count) % $options.Count]
                    }
                    'schedule' {
                        $time = $working.ScheduleTime -split ':'
                        switch ($component) {
                            0 { $working.EnableWeeklyRestart = [int](-not $working.EnableWeeklyRestart) }
                            1 { $working.ScheduleDay = ([int]$working.ScheduleDay + $delta + 7) % 7 }
                            2 { $time[0] = (([int]$time[0] + $delta + 24) % 24).ToString('00') }
                            3 { $time[1] = (([int]$time[1] + $delta + 60) % 60).ToString('00') }
                        }
                        $working.ScheduleTime = $time -join ':'
                    }
                }
            }
            if ($commit) {
                $values = [ordered]@{}
                $names = if ($field.Type -eq 'schedule') { @('EnableWeeklyRestart', 'ScheduleDay', 'ScheduleTime') } else { @($field.Key) }
                foreach ($name in $names) { $values[$name] = $working[$name] }
                Set-ServiceDraftValues $State $values
            }
        }
        catch [OperationCanceledException] { }
        catch { Show-ServiceNotice (Get-ServiceSafeError $_.Exception) 'Red' }
    }
}

function Show-ServiceConfigScreen {
    Clear-ServiceScreen 'SERVICE/CFG'
    Write-Host '1. Логин и пароль для входа в систему'
    Write-Host '2. Используемые модули'
    Write-Host '3. Используемая плата (Выбор порта)'
    Write-Host '4. Сеть и мониторинг'
    Write-Host '5. Подключение к сети'
    Show-ServiceBack
}

function Invoke-ServiceConfigMenu($State) {
    while ($true) {
        Show-ServiceConfigScreen
        $exitRequested = $false
        switch (Read-ServiceChoice -OnResize { Show-ServiceConfigScreen }) {
            '1' { $exitRequested = Invoke-ServiceAccountMenu $State }
            '2' { $exitRequested = Invoke-ServiceModulesMenu $State }
            '3' { $exitRequested = Invoke-ServiceBoardMenu $State }
            '4' { $exitRequested = Invoke-ServiceNetworkMenu $State }
            '5' { $exitRequested = Invoke-ServiceAccountMenu $State -Wifi }
            '0' { return $false }
            '00' { return $true }
        }
        if ($exitRequested) { return $true }
    }
}

function Show-ServiceHomeScreen($State, $Dependencies) {
    Clear-ServiceScreen 'SERVICE'
    if ($Dependencies.Ready) { Write-ServiceStatus '1. Установить зависимости ' 'OK' $true }
    else { Write-Host '1. Установить зависимости' }
    Write-Host ''
    Write-Host '2. Настроить config для подключения'
    Write-Host '3. Создать ключ устройства'
    Write-Host ''
    Write-Host '4. Загрузить прошивку на микроконтроллер'
    Write-Host ''
    Write-ServiceOption '0. Выход' 'Red'
    Write-Host ''
    Write-Host ('Порт: ' + $(if ($State.Port) { $State.Port } else { 'не выбран' }))
    Write-Host ('CFG: ' + $(if (Test-ServiceDraft $State.Configuration) { 'заполнен' } else { 'не заполнен' }))
    Write-Host ('Ключи: ' + $(if ($State.SelectedMac -and $State.Devices.Contains($State.SelectedMac)) { 'созданы' } else { 'не выбраны' }))
}

function Start-ServiceMenu([string]$Root) {
    $drawHome = Get-Command Show-ServiceHomeScreen
    Assert-ServiceConsole
    Enable-ServiceProgressUI
    Clear-ServiceScreen 'SERVICE'
    $state = Read-ServiceState
    $dependencies = Test-ServiceDependencies $Root
    try {
        while ($true) {
            Show-ServiceHomeScreen $state $dependencies
            $redraw = { & $drawHome $state $dependencies }.GetNewClosure()
            $operation = ''
            try {
                switch (Read-ServiceChoice -OnResize $redraw) {
                    '1' {
                        $operation = 'dependencies'
                        Clear-ServiceScreen 'SERVICE/DEPENDENCIES'
                        $dependencies = Install-ServiceDependencies $Root
                        Write-ServiceOperationLog $operation $true
                        Show-ServiceNotice 'Зависимости установлены и проверены.' 'Green'
                    }
                    '2' { if (Invoke-ServiceConfigMenu $state) { return } }
                    '3' {
                        $operation = 'keys'
                        if (-not $dependencies.Ready) { Stop-ServiceOperation 'Сначала установите зависимости: пункт 1.' }
                        Invoke-ServiceMenuKeys $Root $state $dependencies.Paths
                        Write-ServiceOperationLog $operation $true
                    }
                    '4' {
                        $operation = 'flash'
                        if (-not $dependencies.Ready) { Stop-ServiceOperation 'Сначала установите зависимости: пункт 1.' }
                        Invoke-ServiceMenuFlash $Root $state $dependencies.Paths
                        Write-ServiceOperationLog $operation $true
                    }
                    '0' { return }
                    '00' { return }
                }
            }
            catch [OperationCanceledException] { Write-ServiceOperationLog $operation $false }
            catch { Write-ServiceOperationLog $operation $false; Show-ServiceNotice (Get-ServiceSafeError $_.Exception) 'Red' }
        }
    }
    finally { [Console]::ResetColor(); [Console]::CursorVisible = $true; $state = $null }
}

Export-ModuleMember -Function Start-ServiceMenu, Get-ServiceNetworkFields, ConvertTo-ServiceDomainList

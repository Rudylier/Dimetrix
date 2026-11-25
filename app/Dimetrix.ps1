# Dimetrix - быстрая диагностика домашней сети
# Ничего не меняет в системе: только читает состояние и делает замеры.
# Запуск: Dimetrix.cmd (откроется страница в браузере) или Dimetrix.ps1 -Console
param([switch]$Console, [switch]$NoBrowser, [int]$Port = 0)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:Lines  = New-Object System.Collections.ArrayList
$script:Metric = ''
$script:Web    = -not $Console

# ---------- вывод ----------
function Emit([string]$Level, [string]$Text, [string]$Reason, [string]$Fix) {
    if ($script:Web) {
        $line = @{ l = $Level; t = $Text }
        if ($Reason) { $line.reason = $Reason }
        if ($Fix) { $line.fix = $Fix }
        [void]$script:Lines.Add([pscustomobject]$line)
        return
    }
    switch ($Level) {
        'head' { Write-Host ""; Write-Host ("== " + $Text + " ==") -ForegroundColor Cyan }
        'ok'   { Write-Host ("  [OK]  " + $Text) -ForegroundColor Green }
        'warn' { Write-Host ("  [!]   " + $Text) -ForegroundColor Yellow }
        'bad'  { Write-Host ("  [X]   " + $Text) -ForegroundColor Red }
        'dim'  { Write-Host ("        " + $Text) -ForegroundColor DarkGray }
        default { Write-Host ("        " + $Text) }
    }
    if ($Reason) { Write-Host ("        " + $Reason) }
    if ($Fix) { Write-Host ("        " + $Fix) }
}
function Head([string]$t) { Emit 'head' $t }
function Ok([string]$t)   { Emit 'ok' $t }
function Info([string]$t) { Emit 'info' $t }
function Dim([string]$t)  { Emit 'dim' $t }
function Warn([string]$t, [string]$reason, [string]$fix) { Emit 'warn' $t $reason $fix }
function Bad([string]$t)  { Emit 'bad' $t }

$VpnPattern = 'vpn|proxy|outline|happ|zapret|winws|warp|tgws|v2ray|xray|clash|sing-box|singbox|nekoray|nekobox|hiddify|amnezia|wireguard|wg-|tun2socks|shadowsocks|ss-local|psiphon|tor\.exe|lantern|windscribe|proton|planet|vanya|anyconnect|forti|netzone'
$VpnAdapterPattern = 'tap|tun|wintun|wireguard|vpn|openvpn|outline|anyconnect|forti|warp|cloudflare|amnezia|happ|sing|clash|hiddify|zerotier|tailscale|hamachi|radmin'
$WaitStates = 'TimeWait','CloseWait','FinWait1','FinWait2','LastAck','Closing'

# ---------- 1. Подключение и VPN ----------
function Update-RouteInfo {
    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -in '0.0.0.0/0','0.0.0.0/1','128.0.0.0/1' }
    $script:SplitRoutes = @($routes | Where-Object { $_.DestinationPrefix -ne '0.0.0.0/0' })
    $script:Gateway = ($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0' } |
        Sort-Object RouteMetric | Select-Object -First 1).NextHop
    $probe = Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction SilentlyContinue | Select-Object -Last 1
    $script:InternetIf = $null
    if ($probe) { $script:InternetIf = $probe.InterfaceAlias }
}

function Get-NetworkContext {
    Update-RouteInfo
    $adapter = $null
    if ($script:InternetIf) {
        $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Name -eq $script:InternetIf | Select-Object -First 1
    }
    $proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $vpn = $null
    if ($script:InternetIf) {
        $vpn = ($script:InternetIf -in $script:SplitRoutes.InterfaceAlias) -or
            (("$($script:InternetIf) $($adapter.InterfaceDescription)") -match $VpnAdapterPattern)
    }
    return @{ vpn = $vpn; adapter = $script:InternetIf; proxy = [bool]((($proxy.ProxyEnable -eq 1) -and $proxy.ProxyServer) -or $proxy.AutoConfigURL) }
}

function Check-Connection {
    Head "Подключение и VPN"
    $up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
    foreach ($a in $up) {
        $ip = ($ips | Where-Object InterfaceIndex -eq $a.ifIndex | Select-Object -First 1).IPAddress
        $kind = 'сеть'
        if (($a.Name + ' ' + $a.InterfaceDescription) -match $VpnAdapterPattern) { $kind = 'VPN/туннель' }
        Info ("{0} — {1}, {2}, {3}" -f $a.Name, $kind, $ip, $a.LinkSpeed)
    }
    Update-RouteInfo
    if ($script:SplitRoutes.Count -gt 0) {
        $via = $script:SplitRoutes[0].InterfaceAlias
        Warn ("Весь интернет идёт через VPN-адаптер «{0}»." -f $via) 'Маршрут через VPN может увеличить задержку и снизить скорость. При включённом VPN это ожидаемо.' 'Если интернет тормозит, сравни результаты без VPN или через другой VPN-сервер.'
        if (Get-Process openvpn -ErrorAction SilentlyContinue) { Dim "Запущен OpenVPN: если в его конфиге есть redirect-gateway, через него идёт весь трафик." }
        $script:Metric = "Через VPN: $via"
    } elseif ($script:InternetIf) {
        Ok ("Интернет идёт напрямую через «{0}», шлюз {1}" -f $script:InternetIf, $script:Gateway)
        $script:Metric = "Напрямую: $($script:InternetIf)"
    }
    if (-not $script:Gateway) { Bad "Не найден основной шлюз (роутер). Похоже, нет подключения к сети."; $script:Metric = 'Нет сети' }
}

# ---------- 2. Прокси ----------
function Check-Proxy {
    Head "Системный прокси"
    $is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $script:Metric = 'Не используется'
    if ($is.ProxyEnable -eq 1 -and $is.ProxyServer) {
        Info ("Включён системный прокси: {0}. Его часто ставят VPN-программы (например, Happ в режиме «Системный прокси»)." -f $is.ProxyServer)
        $script:Metric = "Прокси $($is.ProxyServer)"
    }
    if ($is.AutoConfigURL) {
        $u = $is.AutoConfigURL; $hostPart = $u
        try { $hostPart = ([Uri]$u).Host } catch {}
        $script:Metric = "PAC: $hostPart"
        Info ("Используется сценарий прокси (PAC) с узла {0}. Обычно его настраивает рабочая сеть или VPN — это нормально." -f $hostPart)
        try {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = [Net.WebRequest]::Create($u); $r.Timeout = 4000; $r.Proxy = $null
            $resp = $r.GetResponse(); $resp.Close()
            Ok ("Сценарий прокси отвечает за {0} мс" -f $sw.ElapsedMilliseconds)
        } catch {
            Dim "Сценарий прокси сейчас не отвечает. Если сайты и рабочие сервисы открываются нормально, на это можно не обращать внимания."
        }
    }
    if ($script:Metric -eq 'Не используется') { Ok "Системный прокси не используется" }
}

# ---------- 3. Пинг ----------
function Measure-Ping([string]$Target, [int]$Count = 15) {
    $p = New-Object Net.NetworkInformation.Ping
    $times = New-Object System.Collections.ArrayList
    $lost = 0
    for ($i = 0; $i -lt $Count; $i++) {
        try {
            $r = $p.Send($Target, 1000)
            if ($r.Status -eq 'Success') { [void]$times.Add([int]$r.RoundtripTime) } else { $lost++ }
        } catch { $lost++ }
        Start-Sleep -Milliseconds 120
    }
    $res = [ordered]@{ Target = $Target; Sent = $Count; Lost = $lost; Avg = $null; Min = $null; Max = $null; Jitter = $null }
    if ($times.Count -gt 0) {
        $m = $times | Measure-Object -Average -Minimum -Maximum
        $res.Avg = [math]::Round($m.Average); $res.Min = $m.Minimum; $res.Max = $m.Maximum
        $j = 0; for ($k = 1; $k -lt $times.Count; $k++) { $j += [math]::Abs($times[$k] - $times[$k-1]) }
        if ($times.Count -gt 1) { $res.Jitter = [math]::Round($j / ($times.Count - 1)) } else { $res.Jitter = 0 }
    }
    return [pscustomobject]$res
}

function Format-PingMs($Value) {
    if ($null -eq $Value) { return 'нет ответа' }
    if ($Value -eq 0) { return '<1 мс' }
    return "$Value мс"
}

function Check-Ping {
    Head "Задержка и потери"
    if (-not $script:Gateway) { Update-RouteInfo }
    $targets = @()
    if ($script:Gateway) { $targets += ,@('Роутер', $script:Gateway) }
    $targets += ,@('Cloudflare', '1.1.1.1')
    $targets += ,@('Google DNS', '8.8.8.8')
    $targets += ,@('Яндекс', 'ya.ru')
    $router = $null; $net = @()
    foreach ($t in $targets) {
        $r = Measure-Ping $t[1]
        $lossPct = [math]::Round(100 * $r.Lost / $r.Sent)
        $isRouter = ($t[0] -eq 'Роутер')
        if ($r.Avg -eq $null) {
            $fix = if ($isRouter) { 'Проверь Wi-Fi или кабель и повтори замер. Некоторые роутеры не отвечают на пинг.' }
            Emit 'bad' ("{0} ({1}): нет ответа" -f $t[0], $t[1]) '' $fix
        } else {
            $line = "{0} ({1}): ср {2}, мин {3}, макс {4}, джиттер {5} мс, потери {6}%" -f $t[0], $t[1], (Format-PingMs $r.Avg), (Format-PingMs $r.Min), (Format-PingMs $r.Max), $r.Jitter, $lossPct
            $limit = 120; if ($isRouter) { $limit = 10 }
            if ($lossPct -gt 0 -or $r.Avg -gt $limit -or $r.Jitter -gt 40) {
                $level = if ($lossPct -ge 10 -or $r.Avg -gt ($limit * 2)) { 'bad' } else { 'warn' }
                $threshold = if ($r.Avg -gt ($limit * 2)) { $limit * 2 } else { $limit }
                $reasons = @(
                    if ($lossPct -gt 0) { "Потеряно $lossPct% пакетов." }
                    if ($r.Avg -gt $limit) { "Средняя задержка выше порога $threshold мс." }
                    if ($r.Jitter -gt 40) { 'Задержка между ответами меняется более чем на 40 мс.' }
                )
                $fix = if ($isRouter) { 'Повтори проверку ближе к роутеру или по кабелю.' }
                       else { 'Приостанови загрузки и повтори проверку. Если включён VPN, сравни результаты без него.' }
                Emit $level $line ($reasons -join ' ') $fix
            }
            else { Emit 'ok' $line }
        }
        if ($isRouter) { $router = $r } else { $net += ,$r }
    }
    $netLoss = ($net | Measure-Object Lost -Sum).Sum
    $okNet = @($net | Where-Object { $_.Avg -ne $null })
    $netAvg = $null; if ($okNet.Count) { $netAvg = [math]::Round(($okNet | Measure-Object Avg -Average).Average) }
    if ($netLoss -gt 2 -and ($router -eq $null -or $router.Lost -le 1)) {
        Bad "Потери начинаются за роутером: канал перегружен, проблема у провайдера или у VPN."
    }
    if ($netAvg -gt 60) { Warn ("Средний пинг в интернет {0} мс." -f $netAvg) 'Задержка выше порога 60 мс. Это может быть заметно в играх и звонках.' 'Приостанови загрузки и повтори замер. Если включён VPN, сравни результаты без него.' }
    $totalSent = ($net | Measure-Object Sent -Sum).Sum
    $lossAll = 0; if ($totalSent) { $lossAll = [math]::Round(100 * $netLoss / $totalSent) }
    $script:Metric = "Внешние адреса $(Format-PingMs $netAvg) · потери $lossAll%"
    if ($router) { $script:Metric += " · роутер $(Format-PingMs $router.Avg)" }
    $script:Num = @{ ping = $netAvg; loss = $lossAll }
}

# ---------- 4. DNS ----------
function Check-Dns {
    Head "DNS"
    $servers = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } |
        ForEach-Object { $_.ServerAddresses }) | Select-Object -Unique
    Dim ("DNS-серверы: " + (($servers | Select-Object -First 4) -join ', '))
    $times = @()
    foreach ($n in 'ya.ru','google.com','telegram.org') {
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $r = Resolve-DnsName $n -Type A -DnsOnly -ErrorAction Stop | Where-Object Type -eq 'A' | Select-Object -First 1
            $ms = $sw.ElapsedMilliseconds; $times += $ms
            $line = "{0}: {1} мс → {2}" -f $n, $ms, $r.IPAddress
            if ($ms -gt 500) { Bad ("DNS отвечает очень медленно. " + $line) }
            elseif ($ms -gt 150) { Warn $line 'Поиск IP-адреса занял больше 150 мс. Из-за этого сайт может дольше начинать открываться.' 'Повтори проверку. Если ответы стабильно медленные, сравни с другим DNS-сервером.' }
            else { Ok $line }
        } catch { Bad ("{0}: не удалось получить адрес" -f $n) }
    }
    if ($times.Count) { $script:Metric = "≈{0} мс" -f [math]::Round(($times | Measure-Object -Average).Average) } else { $script:Metric = 'Не отвечает' }
}

# ---------- 5. Текущая нагрузка ----------
function Get-Bytes {
    $h = @{}
    Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object {
        $s = Get-NetAdapterStatistics -Name $_.Name -ErrorAction SilentlyContinue
        if ($s) { $h[$_.Name] = @($s.ReceivedBytes, $s.SentBytes) }
    }
    return $h
}

function Check-Load {
    Head "Текущая нагрузка (замер 5 сек)"
    $a = Get-Bytes; Start-Sleep -Seconds 5; $b = Get-Bytes
    $maxRx = 0; $maxTx = 0
    foreach ($k in $b.Keys) {
        if (-not $a.ContainsKey($k)) { continue }
        $rx = ($b[$k][0] - $a[$k][0]) * 8 / 5 / 1e6
        $tx = ($b[$k][1] - $a[$k][1]) * 8 / 5 / 1e6
        Info ("{0}: ↓ {1:N2} Мбит/с, ↑ {2:N2} Мбит/с" -f $k, $rx, $tx)
        if ($rx -gt $maxRx) { $maxRx = $rx }; if ($tx -gt $maxTx) { $maxTx = $tx }
    }
    if ($maxRx -gt 50) { Warn "Этот ПК сейчас активно качает." 'Фоновая загрузка занимает часть канала. Замер скорости и пинга может отличаться от результата без нагрузки.' 'Приостанови загрузки, обновления и синхронизацию файлов, затем повтори замер.' } else { Ok "Компьютер сейчас не нагружает канал" }
    Dim "Это трафик только этого ПК. Телефоны и ТВ видно в веб-интерфейсе роутера (раздел «Устройства»)."
    $script:Metric = "↓{0:N1} ↑{1:N1} Мбит/с" -f $maxRx, $maxTx
}

# ---------- 6. Соединения ----------
function Check-Connections {
    Head "Соединения программ"
    $all = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $est = @($all | Where-Object State -eq 'Established').Count
    $wait = @($all | Where-Object { $_.State -in $WaitStates }).Count
    Info ("Всего TCP: {0}, активных: {1}, закрывающихся: {2}" -f $all.Count, $est, $wait)
    if ($wait -gt 1500) { Bad "Очень много зависших соединений: какая-то программа их не закрывает и может «вешать» интернет." }
    elseif ($wait -gt 500) { Warn "Закрывается $wait TCP-соединений." 'Более 500 соединений ожидают закрытия. Такой всплеск бывает после активной работы сетевых приложений.' 'Если число долго не снижается, посмотри список программ ниже и перезапусти ту, у которой больше всего таких соединений.' }

    $names = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
    $groups = $all | Where-Object { $_.OwningProcess -gt 4 } | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 8
    $leak = $false
    foreach ($g in $groups) {
        $pidN = [int]$g.Name
        $n = $names[$pidN]; if (-not $n) { $n = "PID $pidN" }
        $e = @($g.Group | Where-Object State -eq 'Established').Count
        $w = @($g.Group | Where-Object { $_.State -in $WaitStates }).Count
        $line = "{0}: всего {1}, активных {2}, висят {3}" -f $n, $g.Count, $e, $w
        if ($g.Count -gt 300 -or $w -gt 150) {
            Bad ("{0} — так вела себя утечка в TgWsProxy. Попробуй закрыть эту программу." -f $line); $leak = $true
        } elseif ($g.Count -gt 100) { Warn $line 'У программы больше 100 TCP-соединений. Для браузера или загрузчика это может быть обычной нагрузкой.' 'Если программа простаивает и число остаётся высоким, перезапусти её и повтори проверку.' }
        else { Info $line }
    }
    if (-not $leak -and $wait -le 500) { Ok "Ни одна программа не копит соединения" }
    $script:Metric = "$($all.Count) TCP · $wait висят"
}

# ---------- 7. Скорость ----------
function Publish-Speed($Event) {
    if (-not $script:SpeedResponse) { return }
    try {
        $json = ConvertTo-Json -InputObject $Event -Depth 5 -Compress
        $bytes = [Text.Encoding]::UTF8.GetBytes($json + "`n")
        $script:SpeedResponse.OutputStream.Write($bytes, 0, $bytes.Length)
        $script:SpeedResponse.OutputStream.Flush()
    } catch {
        # A closed browser should not interrupt the measurement.
        $script:SpeedResponse = $null
    }
}

function Test-Download([int]$MaxSec = 12) {
    $url = 'https://speed.cloudflare.com/__down?bytes=25000000'
    $buf = New-Object byte[] 262144; $total = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $sampleTime = $null; $sampleBytes = 0
    for ($round = 0; $round -lt 4 -and $sw.Elapsed.TotalSeconds -lt $MaxSec; $round++) {
        $req = [Net.HttpWebRequest]::Create($url); $req.Timeout = 10000; $req.ReadWriteTimeout = 10000; $req.UserAgent = 'Dimetrix'
        $resp = $req.GetResponse(); $s = $resp.GetResponseStream()
        if ($null -eq $sampleTime) { $sampleTime = $sw.Elapsed.TotalSeconds }
        try {
            while ($true) {
                $n = $s.Read($buf, 0, $buf.Length); if ($n -le 0) { break }
                $total += $n
                $elapsed = $sw.Elapsed.TotalSeconds
                if ($script:SpeedResponse -and $elapsed - $sampleTime -ge 0.25) {
                    $rate = [math]::Round(($total - $sampleBytes) * 8 / ($elapsed - $sampleTime) / 1e6, 1)
                    $fraction = [math]::Max($total / 100000000, $elapsed / $MaxSec)
                    Publish-Speed @{ type = 'sample'; down = $rate; progress = [math]::Min(75, 75 * $fraction) }
                    $sampleTime = $elapsed; $sampleBytes = $total
                }
                if ($elapsed -ge $MaxSec) { break }
            }
        } finally {
            $s.Close(); $resp.Close()
        }
    }
    $sec = $sw.Elapsed.TotalSeconds
    return @([math]::Round($total * 8 / $sec / 1e6, 1), [math]::Round($total / 1MB, 1))
}

function Test-Upload([int]$Bytes = 8000000) {
    $req = [Net.HttpWebRequest]::Create('https://speed.cloudflare.com/__up'); $req.Method = 'POST'
    $req.Timeout = 20000; $req.ReadWriteTimeout = 20000; $req.UserAgent = 'Dimetrix'
    $req.ContentType = 'application/octet-stream'; $req.ContentLength = $Bytes; $req.AllowWriteStreamBuffering = $false
    $buf = New-Object byte[] 65536
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $st = $req.GetRequestStream(); $left = $Bytes
    while ($left -gt 0) { $n = [math]::Min($buf.Length, $left); $st.Write($buf, 0, $n); $left -= $n }
    $st.Close()
    Publish-Speed @{ type = 'upload-sent'; progress = 95 }
    $resp = $req.GetResponse(); $resp.Close()
    return [math]::Round($Bytes * 8 / $sw.Elapsed.TotalSeconds / 1e6, 1)
}

function Get-RateLimit($Exception) {
    for ($e = $Exception; $null -ne $e; $e = $e.InnerException) {
        if ($e -is [Net.WebException] -and $e.Response -is [Net.HttpWebResponse]) {
            try {
                if ([int]$e.Response.StatusCode -ne 429) { return }
                $header = $e.Response.Headers['Retry-After']
                $seconds = 0
                if ([int]::TryParse($header, [ref]$seconds) -and $seconds -ge 0) {
                    return @{ retryAt = [DateTimeOffset]::UtcNow.AddSeconds($seconds).ToUnixTimeMilliseconds() }
                }
                $date = [DateTimeOffset]::MinValue
                if ([DateTimeOffset]::TryParse($header, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$date)) {
                    return @{ retryAt = $date.ToUnixTimeMilliseconds() }
                }
                return @{ retryAt = $null }
            }
            finally { $e.Response.Close() }
        }
    }
}

function Check-Speed {
    Head "Скорость интернета"
    if (-not $script:InternetIf) { Update-RouteInfo }
    if ($script:InternetIf) { Dim ("Замер через speed.cloudflare.com, трафик идёт через «{0}»" -f $script:InternetIf) }
    $d = $null; $u = $null; $retryAt = $null
    try {
        $dr = Test-Download; $d = $dr[0]
        $line = "Загрузка: {0} Мбит/с (скачано {1} МБ)" -f $dr[0], $dr[1]
        if ($d -lt 5) { Bad $line } elseif ($d -lt 25) { Warn $line 'Загрузка ниже порога 25 Мбит/с. Скачивание файлов и видео высокого качества может идти медленнее.' 'Приостанови другие загрузки и повтори замер по кабелю или ближе к роутеру.' } else { Ok $line }
    } catch {
        $limit = Get-RateLimit $_.Exception
        if ($limit) {
            $retryAt = $limit.retryAt
            Warn 'Cloudflare временно ограничил замер загрузки (HTTP 429).' 'Сервер отклонил запрос из-за лимита. Скорость загрузки неизвестна.' 'Подожди перед повторным замером.'
        }
        else { Bad ("Тест загрузки не удался: " + (Get-ErrText $_.Exception)) }
    }
    Publish-Speed @{ type = 'upload'; down = $d; progress = 75 }
    try {
        $u = Test-Upload
        $line = "Отдача: {0} Мбит/с" -f $u
        if ($u -lt 2) { Bad $line } elseif ($u -lt 10) { Warn $line 'Отдача ниже порога 10 Мбит/с. Это может замедлить отправку файлов и ухудшить качество видеосвязи.' 'Приостанови выгрузку файлов и облачную синхронизацию, затем повтори замер.' } else { Ok $line }
    } catch {
        $limit = Get-RateLimit $_.Exception
        if ($limit) {
            if ($limit.retryAt -gt $retryAt) { $retryAt = $limit.retryAt }
            Warn 'Cloudflare временно ограничил замер отдачи (HTTP 429).' 'Сервер отклонил запрос из-за лимита. Скорость отдачи неизвестна.' 'Подожди перед повторным замером.'
        }
        else { Warn ("Тест отдачи не удался: " + (Get-ErrText $_.Exception)) 'Передачу данных не удалось завершить, поэтому скорость отдачи неизвестна.' 'Повтори замер. Если ошибка повторится и включён VPN, сравни результат без него.' }
    }
    if ($script:SplitRoutes.Count -gt 0) { Dim "Сейчас замер показывает скорость через VPN. Чтобы узнать скорость тарифа, выключи VPN и повтори." }
    $ds = '—'; if ($d -ne $null) { $ds = $d }
    $us = '—'; if ($u -ne $null) { $us = $u }
    $script:Metric = "↓$ds ↑$us Мбит/с"
    $script:Num = @{ down = $d; up = $u; retryAt = $retryAt }
}

# ---------- Сервисы: YouTube, Telegram, Discord ----------
Add-Type -AssemblyName System.Net.Http

function Get-ErrText($ex) {
    $e = $ex
    while ($e.InnerException) {
        if ($e -is [Net.WebException] -or $e -is [Net.Sockets.SocketException]) { break }
        $e = $e.InnerException
    }
    if ($ex -is [Threading.Tasks.TaskCanceledException] -or $e -is [Threading.Tasks.TaskCanceledException]) { return 'нет ответа (таймаут)' }
    if ($e -is [Net.WebException]) {
        switch ($e.Status.ToString()) {
            'NameResolutionFailure' { return 'не удалось узнать адрес (DNS)' }
            'ConnectFailure'        { return 'не удалось подключиться' }
            'SecureChannelFailure'  { return 'не удалось установить защищённое соединение' }
            'ReceiveFailure'        { return 'соединение оборвалось при получении данных' }
            'ConnectionClosed'      { return 'соединение закрыто до получения ответа' }
            'Timeout'               { return 'нет ответа (таймаут)' }
            'ProtocolError'         { return $e.Message }
            default                 { return $e.Status.ToString() }
        }
    }
    if ($e -is [Net.Sockets.SocketException]) {
        switch ($e.SocketErrorCode.ToString()) {
            'ConnectionReset'  { return 'соединение сброшено' }
            'TimedOut'         { return 'нет ответа (таймаут)' }
            'HostNotFound'     { return 'не удалось узнать адрес (DNS)' }
            'ConnectionRefused'{ return 'подключение отклонено' }
            default            { return $e.SocketErrorCode.ToString() }
        }
    }
    return $e.Message
}

# Endpoints: @{ name; url } для HTTPS или @{ name; tcp = 'host:port' }. Все проверки идут параллельно.
function Test-Endpoints($List, [int]$TimeoutSec = 8) {
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Dimetrix')
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $jobs = foreach ($ep in $List) {
        $o = [pscustomobject]@{ ep = $ep; task = $null; tcp = $null; ms = $null; ok = $false; code = $null; err = $null }
        try {
            if ($ep.tcp) {
                $hp = $ep.tcp.Split(':'); $o.tcp = New-Object Net.Sockets.TcpClient
                $o.task = $o.tcp.ConnectAsync($hp[0], [int]$hp[1])
            } else {
                $o.task = $client.GetAsync($ep.url, [Net.Http.HttpCompletionOption]::ResponseHeadersRead)
            }
        } catch { $o.err = Get-ErrText $_.Exception; $o.ms = 0 }
        $o
    }
    $deadline = ($TimeoutSec + 1) * 1000
    while ($sw.ElapsedMilliseconds -lt $deadline) {
        $pending = 0
        foreach ($j in $jobs) {
            if ($j.ms -ne $null -or -not $j.task) { continue }
            if ($j.task.IsCompleted) { $j.ms = $sw.ElapsedMilliseconds } else { $pending++ }
        }
        if ($pending -eq 0) { break }
        Start-Sleep -Milliseconds 40
    }
    foreach ($j in $jobs) {
        if (-not $j.task) { continue }
        if (-not $j.task.IsCompleted) { $j.err = 'нет ответа (таймаут)'; $j.ms = $deadline }
        elseif ($j.task.IsFaulted) { $j.err = Get-ErrText $j.task.Exception }
        elseif ($j.task.IsCanceled) { $j.err = Get-ErrText (New-Object Threading.Tasks.TaskCanceledException) }
        else {
            $j.ok = $true
            if (-not $j.ep.tcp) { $j.code = [int]$j.task.Result.StatusCode; $j.task.Result.Dispose() }
        }
        if ($j.tcp) { $j.tcp.Close() }
    }
    $client.Dispose()
    return $jobs
}

# Каталог популярных сервисов и адресов для проверки соединения.
$Services = @(
    @{ name = 'YouTube';    cat = 'Видео';       note = 'Проверяются ответы веб-страницы и вспомогательных адресов. Воспроизведение проверяй в браузере.'; eps = @(
        @{ name = 'Главная страница YouTube';   url = 'https://www.youtube.com/' },
        @{ name = 'Картинки и превью (ytimg)';  url = 'https://i.ytimg.com/generate_204' },
        @{ name = 'Маршрутизация видео (googlevideo)'; url = 'https://redirector.googlevideo.com/report_mapping' }) }
    @{ name = 'Twitch';     cat = 'Видео';       eps = @( @{ name = 'Сайт twitch.tv'; url = 'https://www.twitch.tv/' } ) }
    @{ name = 'TikTok';     cat = 'Видео';       eps = @( @{ name = 'Сайт tiktok.com'; url = 'https://www.tiktok.com/' } ) }
    @{ name = 'Telegram';   cat = 'Мессенджеры'; note = 'Если серверы DC недоступны, приложение висит на «Соединение…» без прокси или VPN.'; eps = @(
        @{ name = 'Сервер DC2 (149.154.167.51)'; tcp = '149.154.167.51:443' },
        @{ name = 'Сервер DC4 (149.154.167.91)'; tcp = '149.154.167.91:443' },
        @{ name = 'Веб-версия web.telegram.org'; url = 'https://web.telegram.org/' }) }
    @{ name = 'WhatsApp';   cat = 'Мессенджеры'; eps = @(
        @{ name = 'Веб-версия web.whatsapp.com'; url = 'https://web.whatsapp.com/' },
        @{ name = 'Сервер сообщений';            tcp = 'g.whatsapp.net:443' }) }
    @{ name = 'Discord';    cat = 'Мессенджеры'; note = 'Голосовые каналы работают по UDP — эта проверка их не покрывает.'; eps = @(
        @{ name = 'Сайт и API discord.com';  url = 'https://discord.com/api/v9/gateway' },
        @{ name = 'Шлюз чата (gateway)';     url = 'https://gateway.discord.gg/' },
        @{ name = 'Картинки и файлы (cdn)';  url = 'https://cdn.discordapp.com/' }) }
    @{ name = 'ВКонтакте';  cat = 'Соцсети';     eps = @( @{ name = 'Сайт vk.com'; url = 'https://vk.com/' } ) }
    @{ name = 'Instagram';  cat = 'Соцсети';     eps = @( @{ name = 'Сайт instagram.com'; url = 'https://www.instagram.com/' } ) }
    @{ name = 'Facebook';   cat = 'Соцсети';     eps = @( @{ name = 'Сайт facebook.com'; url = 'https://www.facebook.com/' } ) }
    @{ name = 'X (Twitter)';cat = 'Соцсети';     eps = @( @{ name = 'Сайт x.com'; url = 'https://x.com/' } ) }
    @{ name = 'ChatGPT';    cat = 'ИИ';          eps = @(
        @{ name = 'Сайт chatgpt.com'; url = 'https://chatgpt.com/' },
        @{ name = 'API openai.com';   url = 'https://api.openai.com/v1/models' }) }
    @{ name = 'Claude';     cat = 'ИИ';          eps = @( @{ name = 'Сайт claude.ai'; url = 'https://claude.ai/' } ) }
    @{ name = 'Cursor';     cat = 'ИИ';          note = 'Если сайт открывается, а сервер ИИ нет — редактор запустится, но чат и автодополнение работать не будут.'; eps = @(
        @{ name = 'Сайт cursor.com';           url = 'https://cursor.com/' },
        @{ name = 'Сервер ИИ (api2.cursor.sh)'; url = 'https://api2.cursor.sh/' },
        @{ name = 'Вход в аккаунт';            url = 'https://authenticator.cursor.sh/' }) }
    @{ name = 'Steam';      cat = 'Игры';        note = 'Если магазин открывается, а загрузка игр или серверы клиента нет — игры не будут качаться, а клиент не войдёт в сеть.'; eps = @(
        @{ name = 'Магазин store.steampowered.com'; url = 'https://store.steampowered.com/' },
        @{ name = 'Сообщество steamcommunity.com';  url = 'https://steamcommunity.com/' },
        @{ name = 'Вход в аккаунт';                 url = 'https://login.steampowered.com/' },
        @{ name = 'Серверы клиента Steam';          url = 'https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0' },
        @{ name = 'Картинки магазина';              url = 'https://shared.akamai.steamstatic.com/store_item_assets/steam/apps/570/header.jpg' },
        @{ name = 'Загрузка игр (SteamPipe)';       url = 'https://steampipe.akamaized.net/' }) }
    @{ name = 'Epic Games'; cat = 'Игры';        eps = @( @{ name = 'Сайт epicgames.com'; url = 'https://store.epicgames.com/' } ) }
    @{ name = 'Spotify';    cat = 'Музыка';      note = 'Spotify сам ушёл из России: без VPN он не работает, даже если сайт открывается.'; eps = @( @{ name = 'Сайт open.spotify.com'; url = 'https://open.spotify.com/' } ) }
    @{ name = 'Яндекс';     cat = 'Сервисы';     eps = @( @{ name = 'Сайт ya.ru'; url = 'https://ya.ru/' } ) }
    @{ name = 'Google';     cat = 'Сервисы';     eps = @( @{ name = 'Поиск google.com'; url = 'https://www.google.com/generate_204' } ) }
    @{ name = 'GitHub';     cat = 'Сервисы';     eps = @( @{ name = 'Сайт github.com'; url = 'https://github.com/' } ) }
    @{ name = 'Госуслуги';  cat = 'Сервисы';     note = 'Госуслуги и банки часто не открываются через зарубежный VPN.'; eps = @( @{ name = 'Сайт gosuslugi.ru'; url = 'https://www.gosuslugi.ru/' } ) }
)

function Check-Popular {
    if (-not $script:InternetIf) { Update-RouteInfo }
    $flat = foreach ($s in $Services) { foreach ($e in $s.eps) { @{ svc = $s.name; name = $e.name; url = $e.url; tcp = $e.tcp } } }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $res = Test-Endpoints @($flat)
    $out = foreach ($s in $Services) {
        $mine = @($res | Where-Object { $_.ep.svc -eq $s.name })
        $lines = New-Object System.Collections.ArrayList
        $okCount = 0; $slow = $false; $times = @()
        foreach ($r in $mine) {
            if ($r.ok) {
                $okCount++; $times += $r.ms
                $extra = ''; if ($r.code) { $extra = ", ответ $($r.code)" }
                $t = "{0}: ответ за {1} мс{2}" -f $r.ep.name, $r.ms, $extra
                if ($r.ms -gt 2500) { [void]$lines.Add([pscustomobject]@{ l = 'warn'; t = $t; reason = 'Ответ занял больше 2,5 секунды. Из-за этого часть сервиса может загружаться с задержкой.' }); $slow = $true }
                else { [void]$lines.Add([pscustomobject]@{ l = 'ok'; t = $t }) }
            } else {
                [void]$lines.Add([pscustomobject]@{ l = 'bad'; t = ("{0}: {1}" -f $r.ep.name, $r.err) })
            }
        }
        if ($s.note) { [void]$lines.Add([pscustomobject]@{ l = 'dim'; t = $s.note }) }
        $avg = $null; if ($times.Count) { $avg = [math]::Round(($times | Measure-Object -Average).Average) }
        $total = $mine.Count
        if ($okCount -eq 0) { $lv = 'bad'; $st = 'Нет ответа в проверке' }
        elseif ($okCount -lt $total) { $lv = 'warn'; $st = "Частично ($okCount из $total)" }
        elseif ($slow) { $lv = 'warn'; $st = 'Медленно' }
        else { $lv = 'ok'; $st = 'Адреса ответили' }
        [pscustomobject]@{ name = $s.name; cat = $s.cat; level = $lv; status = $st; ms = $avg; lines = @($lines) }
    }
    $via = 'напрямую'; if ($script:InternetIf) { $via = $script:InternetIf }
    return [pscustomobject]@{ via = $via; ms = $sw.ElapsedMilliseconds; services = @($out) }
}

# ---------- 8. Автозапуск ----------
function Check-Autostart {
    Head "VPN и прокси в автозапуске"
    $found = New-Object System.Collections.ArrayList
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.StartMode -eq 'Auto' -and (($_.Name + ' ' + $_.DisplayName + ' ' + $_.PathName) -match $VpnPattern) } |
        ForEach-Object { [void]$found.Add(("Служба {0} ({1})" -f $_.DisplayName, $_.State)) }
    $z = Get-Service zapret -ErrorAction SilentlyContinue
    if ($z -and -not (@($found) -match 'zapret')) { [void]$found.Add(("Служба zapret ({0})" -f $z.Status)) }
    foreach ($key in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
        $p = Get-ItemProperty $key -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and (($_.Name + ' ' + $_.Value) -match $VpnPattern) } |
            ForEach-Object { [void]$found.Add(("Автозагрузка: {0}" -f $_.Name)) }
    }
    foreach ($dir in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {
        Get-ChildItem $dir -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $VpnPattern } |
            ForEach-Object { [void]$found.Add(("Ярлык в автозагрузке: {0}" -f $_.BaseName)) }
    }
    if ($found.Count -eq 0) { Ok "Ничего похожего на VPN или прокси в автозапуске нет" }
    else {
        foreach ($f in $found) { Info $f }
        if ($found.Count -ge 3) { Warn ("В автозапуске {0} VPN/прокси-компонентов." -f $found.Count) 'Если несколько клиентов одновременно меняют маршруты или настройки прокси, соединение может стать нестабильным.' 'Если есть сбои, проверь список ниже и отключи автозапуск клиентов, которыми не пользуешься.' }
        else { Ok "Немного VPN-компонентов, конфликтов быть не должно" }
    }
    $script:Metric = "$($found.Count) шт."
}

$Steps = [ordered]@{
    connection  = @{ fn = 'Check-Connection';  title = 'Подключение и VPN';     slow = $false }
    proxy       = @{ fn = 'Check-Proxy';       title = 'Системный прокси';      slow = $false }
    ping        = @{ fn = 'Check-Ping';        title = 'Пинг и потери';         slow = $false }
    dns         = @{ fn = 'Check-Dns';         title = 'DNS';                   slow = $false }
    load        = @{ fn = 'Check-Load';        title = 'Нагрузка сейчас';       slow = $false }
    connections = @{ fn = 'Check-Connections'; title = 'Соединения программ';   slow = $false }
    speed       = @{ fn = 'Check-Speed';       title = 'Скорость';              slow = $true  }
    autostart   = @{ fn = 'Check-Autostart';   title = 'Автозапуск VPN';        slow = $false }
}

function Invoke-Step([string]$Id) {
    $script:Lines.Clear(); $script:Metric = ''; $script:Num = $null
    $s = $Steps[$Id]
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $s.fn } catch { Bad ("Ошибка проверки: " + $_.Exception.Message) }
    $lv = 'info'
    $levels = @($script:Lines | ForEach-Object { $_.l })
    if ($levels -contains 'bad') { $lv = 'bad' } elseif ($levels -contains 'warn') { $lv = 'warn' } elseif ($levels -contains 'ok') { $lv = 'ok' }
    return [pscustomobject]@{
        id = $Id; title = $s.title; level = $lv; metric = $script:Metric; ms = $sw.ElapsedMilliseconds; num = $script:Num
        lines = @($script:Lines | Where-Object { $_.l -ne 'head' })
    }
}

# ---------- Консольный режим ----------
if ($Console) {
    Write-Host ("Dimetrix — " + (Get-Date -Format 'dd.MM.yyyy HH:mm:ss')) -ForegroundColor DarkGray
    foreach ($k in $Steps.Keys) { try { & $Steps[$k].fn } catch { Bad ("Ошибка: " + $_.Exception.Message) } }
    Head "Сайты и приложения"
    $p = Check-Popular
    foreach ($s in $p.services) {
        $ms = ''; if ($s.ms) { $ms = " · ≈$($s.ms) мс" }
        Emit $s.level ("{0}: {1}{2}" -f $s.name, $s.status, $ms)
    }
    return
}

# ---------- Локальный веб-сервер ----------
# Постоянный порт, чтобы браузер запоминал тему и вкладку. Если занят — берём любой свободный.
if ($Port -eq 0) {
    $Port = 47800
    try { $tl = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port); $tl.Start(); $tl.Stop() }
    catch {
        $tl = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0); $tl.Start()
        $Port = $tl.LocalEndpoint.Port; $tl.Stop()
    }
}

# История проверок: по одной JSON-записи на строку, хранится в профиле пользователя (не в папке проекта).
$DataDir = Join-Path $env:APPDATA 'Dimetrix'
$HistoryPath = Join-Path $DataDir 'history.jsonl'
function Get-HistoryLines {
    if (-not (Test-Path $HistoryPath)) { return @() }
    return @([IO.File]::ReadAllLines($HistoryPath, [Text.Encoding]::UTF8) | Where-Object { $_.Trim() })
}
function Set-HistoryLines($Lines) {
    [void][IO.Directory]::CreateDirectory($DataDir)
    $tempPath = Join-Path $DataDir ("history-" + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllLines($tempPath, [string[]]@($Lines), (New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($HistoryPath)) { [IO.File]::Replace($tempPath, $HistoryPath, [NullString]::Value) }
        else { [IO.File]::Move($tempPath, $HistoryPath) }
    } finally { if ([IO.File]::Exists($tempPath)) { [IO.File]::Delete($tempPath) } }
}
function Read-Body($Ctx) {
    $sr = New-Object IO.StreamReader($Ctx.Request.InputStream, [Text.Encoding]::UTF8)
    try { return $sr.ReadToEnd() } finally { $sr.Close() }
}
$Token = [guid]::NewGuid().ToString('N')
$HtmlPath = Join-Path $PSScriptRoot 'Dimetrix.html'
$listener = New-Object Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
$Url = "http://localhost:$Port/?t=$Token"
Write-Host "Dimetrix: $Url"

function Send([object]$Ctx, [int]$Code, [string]$Type, [string]$Body) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
    $Ctx.Response.StatusCode = $Code
    $Ctx.Response.ContentType = $Type
    $Ctx.Response.Headers['Cache-Control'] = 'no-store'
    $Ctx.Response.ContentLength64 = $bytes.Length
    $Ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Ctx.Response.Close()
}

if (-not $NoBrowser) {
    $app = $null
    foreach ($exe in 'chrome.exe','msedge.exe') {
        $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$exe" -ErrorAction SilentlyContinue
        if ($reg -and $reg.'(default)' -and (Test-Path $reg.'(default)')) { $app = $reg.'(default)'; break }
    }
    if ($app) { Start-Process $app -ArgumentList "--app=$Url", '--window-size=1180,860' }
    else { Start-Process $Url }
}

$lastSeen = Get-Date
$idleTimeout = [TimeSpan]::FromMinutes(10)
try {
    while ($listener.IsListening) {
        $task = $listener.GetContextAsync()
        while (-not $task.Wait(1000)) {
            if (((Get-Date) - $lastSeen) -gt $idleTimeout) { $listener.Stop(); break }
        }
        if (-not $listener.IsListening) { break }
        $ctx = $task.Result
        $lastSeen = Get-Date
        $path = $ctx.Request.Url.AbsolutePath
        $tok = $ctx.Request.QueryString['t']
        try {
            if ($tok -ne $Token) { Send $ctx 403 'text/plain; charset=utf-8' 'Нет доступа'; continue }
            switch ($path) {
                '/' {
                    $html = [IO.File]::ReadAllText($HtmlPath, [Text.Encoding]::UTF8).Replace('{{TOKEN}}', $Token)
                    Send $ctx 200 'text/html; charset=utf-8' $html
                }
                '/api/steps' {
                    $list = foreach ($k in $Steps.Keys) { [pscustomobject]@{ id = $k; title = $Steps[$k].title; slow = $Steps[$k].slow } }
                    Send $ctx 200 'application/json; charset=utf-8' (ConvertTo-Json @($list) -Compress)
                }
                '/api/network' { Send $ctx 200 'application/json; charset=utf-8' ((Get-NetworkContext) | ConvertTo-Json -Compress) }
                '/api/run' {
                    $id = $ctx.Request.QueryString['step']
                    if (-not $Steps.Contains($id)) { Send $ctx 404 'text/plain' 'unknown step' }
                    elseif ($id -eq 'speed' -and $ctx.Request.QueryString['live'] -eq '1') {
                        $response = $ctx.Response
                        $response.ContentType = 'application/x-ndjson; charset=utf-8'
                        $response.Headers['Cache-Control'] = 'no-store'
                        $response.SendChunked = $true
                        $script:SpeedResponse = $response
                        try {
                            Publish-Speed @{ type = 'start' }
                            $result = Invoke-Step $id
                            Publish-Speed @{ type = 'result'; result = $result }
                        } finally {
                            $script:SpeedResponse = $null
                            $response.Close()
                        }
                    }
                    else { Send $ctx 200 'application/json; charset=utf-8' ((Invoke-Step $id) | ConvertTo-Json -Depth 4 -Compress) }
                }
                { $_ -in '/logo.png', '/logo-dark.png', '/icon.png' } {
                    $bytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $path.TrimStart('/')))
                    $ctx.Response.StatusCode = 200; $ctx.Response.ContentType = 'image/png'
                    $ctx.Response.Headers['Cache-Control'] = 'max-age=3600'
                    $ctx.Response.ContentLength64 = $bytes.Length
                    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length); $ctx.Response.Close()
                }
                '/api/services' { Send $ctx 200 'application/json; charset=utf-8' ((Check-Popular) | ConvertTo-Json -Depth 5 -Compress) }
                '/api/services/catalog' {
                    $cat = foreach ($s in $Services) { [pscustomobject]@{ name = $s.name; cat = $s.cat } }
                    Send $ctx 200 'application/json; charset=utf-8' (ConvertTo-Json @($cat) -Compress)
                }
                '/api/history' {
                    if ($ctx.Request.HttpMethod -eq 'POST') {
                        $body = Read-Body $ctx
                        if ($body.Length -gt 600000) { Send $ctx 413 'text/plain' 'too large'; break }
                        try { $obj = $body | ConvertFrom-Json } catch { Send $ctx 400 'text/plain' 'bad json'; break }
                        if (-not $obj.id -or $obj.type -notin 'overview','sites') { Send $ctx 400 'text/plain' 'bad entry'; break }
                        $line = $body -replace "[\r\n]+", ' '
                        $all = @(Get-HistoryLines) + $line
                        Set-HistoryLines $all
                        Send $ctx 200 'text/plain' 'saved'
                    } else {
                        Send $ctx 200 'application/json; charset=utf-8' ('[' + ((Get-HistoryLines) -join ',') + ']')
                    }
                }
                '/api/history/delete' {
                    $id = $ctx.Request.QueryString['id']
                    if ($ctx.Request.HttpMethod -ne 'POST' -or $id -notmatch '^[\w-]{6,64}$') { Send $ctx 400 'text/plain' 'bad request'; break }
                    Set-HistoryLines @(Get-HistoryLines | Where-Object { $_ -notlike "*`"id`":`"$id`"*" })
                    Send $ctx 200 'text/plain' 'deleted'
                }
                '/api/history/clear' {
                    if ($ctx.Request.HttpMethod -ne 'POST') { Send $ctx 400 'text/plain' 'bad request'; break }
                    if (Test-Path $HistoryPath) { Remove-Item $HistoryPath }
                    Send $ctx 200 'text/plain' 'cleared'
                }
                '/api/ping' { Send $ctx 200 'text/plain' 'ok' }
                '/api/quit' { Send $ctx 200 'text/plain' 'bye'; $listener.Stop() }
                default { Send $ctx 404 'text/plain' 'not found' }
            }
        } catch {
            try { Send $ctx 500 'text/plain; charset=utf-8' $_.Exception.Message } catch {}
        }
        $lastSeen = Get-Date
    }
} finally {
    if ($listener.IsListening) { $listener.Stop() }
    $listener.Close()
}

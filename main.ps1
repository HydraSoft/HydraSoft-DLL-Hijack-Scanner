<#
B2B / Corporate check (Windows)

Собирает сигналы:
- В домене ли ПК (AD Domain Join)
- Azure AD Join / Workplace Join (dsregcmd)
- Наличие MDM/Intune enrollment (реестр Enrollments)
- Secure Channel до домена (Test-ComputerSecureChannel)
- Поиск DC (nltest /dsgetdc и /dclist)
- DNS SRV-записи AD (_ldap._tcp.dc._msdcs)
- Kerberos tickets (klist)
- Проверка доступности портов на DC (88/389/445/53/135)
- Признаки VPN (Get-VpnConnection / адаптеры)

Возвращает JSON в stdout (не пишет файл).
#>

[CmdletBinding()]
param(
    [string]$OutputPath = $null,
    [string]$DomainOverride = "",
    [string[]]$ExtraInternalHosts = @()
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Continue"

function Run-External {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [string[]]$Args = @()
    )
    $result = [ordered]@{
        file      = $FilePath
        args      = $Args
        exitCode  = $null
        stdout    = @()
        stderr    = @()
        ok        = $false
        error     = $null
    }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = ($Args -join " ")
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()
        $p.WaitForExit()

        $result.exitCode = $p.ExitCode
        if ($stdout) { $result.stdout = $stdout -split "`r?`n" }
        if ($stderr) { $result.stderr = $stderr -split "`r?`n" }
        $result.ok = ($p.ExitCode -eq 0)
    } catch {
        $result.error = $_.Exception.Message
    }
    return $result
}

function Get-ComputerDomainInfo {
    $info = [ordered]@{
        partOfDomain = $false
        domain       = $null
        workgroup    = $null
        userDomain   = $env:USERDOMAIN
        logonServer  = $env:LOGONSERVER
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $info.partOfDomain = [bool]$cs.PartOfDomain
        $info.domain = $cs.Domain
        $info.workgroup = $cs.Workgroup
    } catch { }

    return $info
}

function Parse-DsregStatus {
    $parsed = [ordered]@{
        available       = $false
        raw             = $null
        azureAdJoined   = $null
        domainJoined    = $null
        workplaceJoined = $null
        deviceId        = $null
        tenantName      = $null
        tenantId        = $null
        mdmUrl          = $null
        notes           = @()
    }

    $cmd = Get-Command dsregcmd.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $parsed.notes += "dsregcmd.exe не найден"
        return $parsed
    }

    $r = Run-External -FilePath $cmd.Source -Args @("/status")
    $parsed.available = $true
    $parsed.raw = $r

    $lines = @($r.stdout)

    function Get-YesNoValue($name) {
        $m = $lines | Select-String -Pattern ("^\s*{0}\s*:\s*(YES|NO)\s*$" -f [regex]::Escape($name)) | Select-Object -First 1
        if ($m) { return ($m.Matches[0].Groups[1].Value -eq "YES") }
        return $null
    }

    function Get-StringValue($name) {
        $m = $lines | Select-String -Pattern ("^\s*{0}\s*:\s*(.+?)\s*$" -f [regex]::Escape($name)) | Select-Object -First 1
        if ($m) { return $m.Matches[0].Groups[1].Value.Trim() }
        return $null
    }

    $parsed.azureAdJoined   = Get-YesNoValue "AzureAdJoined"
    $parsed.domainJoined    = Get-YesNoValue "DomainJoined"
    $parsed.workplaceJoined = Get-YesNoValue "WorkplaceJoined"

    $parsed.deviceId   = Get-StringValue "DeviceId"
    $parsed.tenantName = Get-StringValue "TenantName"
    $parsed.tenantId   = Get-StringValue "TenantId"
    $parsed.mdmUrl     = Get-StringValue "MDMUrl"

    return $parsed
}

function Get-MdmEnrollmentInfo {
    $info = [ordered]@{
        enrollmentsKeyExists = $false
        enrollmentCount      = 0
        guids                = @()
        note                 = $null
    }

    $path = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    try {
        if (Test-Path $path) {
            $info.enrollmentsKeyExists = $true
            $subs = Get-ChildItem $path -ErrorAction Stop | Where-Object { $_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$' }
            $info.enrollmentCount = ($subs | Measure-Object).Count
            $info.guids = @($subs | Select-Object -ExpandProperty PSChildName)
        }
    } catch {
        $info.note = $_.Exception.Message
    }

    return $info
}

function Get-NltestDcInfo {
    param([Parameter(Mandatory)] [string]$Domain)

    $info = [ordered]@{
        available   = $false
        dsgetdc     = $null
        dclist      = $null
        dcNames     = @()
        note        = $null
    }

    $cmd = Get-Command nltest.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $info.note = "nltest.exe не найден"
        return $info
    }
    $info.available = $true

    $info.dsgetdc = Run-External -FilePath $cmd.Source -Args @("/dsgetdc:$Domain")
    $info.dclist  = Run-External -FilePath $cmd.Source -Args @("/dclist:$Domain")

    $dcLines = @()
    if ($info.dclist -and $info.dclist.stdout) {
        $dcLines = $info.dclist.stdout | Where-Object { $_ -match '^\s*\\\\' }
    }

    $dcs = @()
    foreach ($l in $dcLines) {
        if ($l -match '^\s*\\\\([^\s]+)') { $dcs += $Matches[1] }
    }

    if ($info.dsgetdc -and $info.dsgetdc.stdout) {
        foreach ($l in $info.dsgetdc.stdout) {
            if ($l -match 'DC:\s*\\\\([^\s]+)') { $dcs += $Matches[1] }
        }
    }

    $info.dcNames = @($dcs | Sort-Object -Unique)
    return $info
}

function Test-AdSrvDns {
    param([Parameter(Mandatory)] [string]$Domain)
    $res = [ordered]@{
        ok      = $false
        records = @()
        error   = $null
    }
    try {
        $q = "_ldap._tcp.dc._msdcs.$Domain"
        $ans = Resolve-DnsName -Name $q -Type SRV -ErrorAction Stop
        $res.ok = $true
        $res.records = @($ans | Select-Object Name, Type, Priority, Weight, Port, NameTarget)
    } catch {
        $res.error = $_.Exception.Message
    }
    return $res
}

# FIX: параметр НЕ называется Host (конфликт с $Host)
function Test-Ports {
    param(
        [Parameter(Mandatory)] [string]$ComputerName,
        [int[]]$Ports = @(88,389,445,53,135)
    )
    $out = [ordered]@{
        computerName = $ComputerName
        tests        = @()
        anyOk        = $false
    }

    foreach ($p in $Ports) {
        try {
            $t = Test-NetConnection -ComputerName $ComputerName -Port $p -WarningAction SilentlyContinue
            $out.tests += [ordered]@{
                port = $p
                tcpTestSucceeded = [bool]$t.TcpTestSucceeded
                remoteAddress    = $t.RemoteAddress
            }
        } catch {
            $out.tests += [ordered]@{
                port = $p
                tcpTestSucceeded = $false
                error = $_.Exception.Message
            }
        }
    }
    $out.anyOk = (($out.tests | Where-Object { $_.tcpTestSucceeded } | Measure-Object).Count -gt 0)
    return $out
}

function Get-KerberosInfo {
    $info = [ordered]@{
        available  = $false
        raw        = $null
        hasTickets = $null
        note       = $null
    }
    $cmd = Get-Command klist.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $info.note = "klist.exe не найден"
        return $info
    }
    $info.available = $true
    $r = Run-External -FilePath $cmd.Source -Args @()
    $info.raw = $r

    $ticketsLines = @($r.stdout | Where-Object { $_ -match '^\s*\d+\s' -or $_ -match 'Server:' })
    $info.hasTickets = (($ticketsLines | Measure-Object).Count -gt 0)
    return $info
}

function Get-VpnSignals {
    $vpn = [ordered]@{
        vpnConnectionsAvailable = $false
        vpnConnections          = @()
        adapterHints            = @()
        likelyVpnConnected      = $false
        note                    = $null
    }

    try {
        $cmd = Get-Command Get-VpnConnection -ErrorAction SilentlyContinue
        if ($cmd) {
            $vpn.vpnConnectionsAvailable = $true
            $conns = Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue
            if (-not $conns) { $conns = Get-VpnConnection -ErrorAction SilentlyContinue }
            if ($conns) {
                $vpn.vpnConnections = @($conns | Select-Object Name, ServerAddress, ConnectionStatus, SplitTunneling, RememberCredential)
                if (($conns | Where-Object { $_.ConnectionStatus -eq "Connected" } | Measure-Object).Count -gt 0) {
                    $vpn.likelyVpnConnected = $true
                }
            }
        }
    } catch {
        $vpn.note = $_.Exception.Message
    }

    try {
        $patterns = "VPN|AnyConnect|Cisco|Pulse|GlobalProtect|Forti|OpenVPN|WireGuard|Juniper|Check Point|SonicWall|Zscaler|TAP|TUN"
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
        foreach ($a in $adapters) {
            $desc = ($a.InterfaceDescription + " " + $a.Name)
            if ($desc -match $patterns) {
                $vpn.adapterHints += [ordered]@{
                    name = $a.Name
                    ifIndex = $a.ifIndex
                    description = $a.InterfaceDescription
                }
            }
        }
        if (($vpn.adapterHints | Measure-Object).Count -gt 0) {
            $vpn.likelyVpnConnected = $true
        }
    } catch { }

    return $vpn
}

# --- MAIN ---
$now = Get-Date
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$domainInfo = Get-ComputerDomainInfo
$dsreg = Parse-DsregStatus
$mdm  = Get-MdmEnrollmentInfo
$vpn  = Get-VpnSignals
$krb  = Get-KerberosInfo

$domain = $null
if ($DomainOverride.Trim()) { $domain = $DomainOverride.Trim() }
elseif ($domainInfo.domain -and $domainInfo.partOfDomain) { $domain = $domainInfo.domain }
elseif ($dsreg.domainJoined -eq $true -and $domainInfo.domain) { $domain = $domainInfo.domain }

$secureChannel = [ordered]@{ attempted = $false; ok = $null; error = $null }
if ($domainInfo.partOfDomain -or $dsreg.domainJoined -eq $true) {
    $secureChannel.attempted = $true
    try {
        $secureChannel.ok = [bool](Test-ComputerSecureChannel -ErrorAction Stop)
    } catch {
        $secureChannel.ok = $false
        $secureChannel.error = $_.Exception.Message
    }
}

$nl = $null
$dnsSrv = $null
$dcPortTests = @()
$extraHostTests = @()

if ($domain) {
    $nl = Get-NltestDcInfo -Domain $domain
    $dnsSrv = Test-AdSrvDns -Domain $domain

    $dcToTest = @($nl.dcNames | Select-Object -First 3)
    foreach ($dc in $dcToTest) {
        $dcPortTests += (Test-Ports -ComputerName $dc)
    }
}

foreach ($h in ($ExtraInternalHosts | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique)) {
    $extraHostTests += (Test-Ports -ComputerName $h.Trim() -Ports @(443,80,445,3389))
}

$signals = [ordered]@{
    domainJoined      = [bool]($domainInfo.partOfDomain -or $dsreg.domainJoined -eq $true)
    azureAdJoined     = [bool]($dsreg.azureAdJoined -eq $true)
    workplaceJoined   = [bool]($dsreg.workplaceJoined -eq $true)
    mdmEnrolled       = [bool]($mdm.enrollmentCount -gt 0 -or ($dsreg.mdmUrl -and $dsreg.mdmUrl.Trim()))
    secureChannelOk   = [bool]($secureChannel.ok -eq $true)
    dcFound           = [bool]($nl -and ($nl.dcNames | Measure-Object).Count -gt 0)
    adSrvDnsOk        = [bool]($dnsSrv -and $dnsSrv.ok -eq $true)
    anyDcPortReachable= [bool](($dcPortTests | Where-Object { $_.anyOk } | Measure-Object).Count -gt 0)
    likelyVpnConnected= [bool]($vpn.likelyVpnConnected -eq $true)
    kerberosTickets   = [bool]($krb.hasTickets -eq $true)
}

$deviceIsCorporate = $signals.domainJoined -or $signals.azureAdJoined -or $signals.mdmEnrolled
$networkHasCorpAccess = $signals.secureChannelOk -or $signals.dcFound -or $signals.adSrvDnsOk -or $signals.anyDcPortReachable

$score = 0
if ($signals.domainJoined)       { $score += 4 }
if ($signals.azureAdJoined)      { $score += 4 }
if ($signals.workplaceJoined)    { $score += 2 }
if ($signals.mdmEnrolled)        { $score += 2 }
if ($signals.secureChannelOk)    { $score += 3 }
if ($signals.dcFound)            { $score += 2 }
if ($signals.adSrvDnsOk)         { $score += 2 }
if ($signals.anyDcPortReachable) { $score += 2 }
if ($signals.likelyVpnConnected) { $score += 1 }
if ($signals.kerberosTickets)    { $score += 1 }

$classification = if ($deviceIsCorporate -and $networkHasCorpAccess) {
    "CorporateDevice_And_CorporateConnectivity"
} elseif ($deviceIsCorporate -and -not $networkHasCorpAccess) {
    "CorporateDevice_But_NoCorporateConnectivityNow"
} elseif (-not $deviceIsCorporate -and $networkHasCorpAccess) {
    "Inconclusive_PossibleCorporateNetworkButDeviceNotJoined"
} else {
    "LikelyNotCorporate"
}

$result = [ordered]@{
    meta = [ordered]@{
        timestamp    = $now.ToString("o")
        computerName = $env:COMPUTERNAME
        userName     = $env:USERNAME
        psVersion    = $PSVersionTable.PSVersion.ToString()
        outputPath   = $OutputPath
    }

    system = [ordered]@{
        osCaption   = $os.Caption
        osVersion   = $os.Version
        buildNumber = $os.BuildNumber
    }

    domainInfo = $domainInfo
    effectiveDomain = $domain

    checks = [ordered]@{
        dsregcmd        = $dsreg
        mdmEnrollment   = $mdm
        secureChannel   = $secureChannel
        nltest          = $nl
        adSrvDns        = $dnsSrv
        dcPortTests     = $dcPortTests
        extraHostTests  = $extraHostTests
        vpnSignals      = $vpn
        kerberos        = $krb
    }

    signals = $signals

    conclusion = [ordered]@{
        deviceIsCorporate         = $deviceIsCorporate
        networkHasCorporateAccess = $networkHasCorpAccess
        classification            = $classification
        score                     = $score
    }
}

try {
    $json = $result | ConvertTo-Json -Depth 12 -Compress
    Write-Output $json
} catch {
    Write-Error "Не удалось сформировать JSON: $($_.Exception.Message)"
    exit 1
}

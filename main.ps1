[CmdletBinding()]
param()

Set-StrictMode -Version Latest

[Flags()] enum ProductState {
    Off     = 0x0000
    On      = 0x1000
    Snoozed = 0x2000
    Expired = 0x3000
}

[Flags()] enum SignatureStatus {
    UpToDate  = 0x00
    OutOfDate = 0x10
}

[Flags()] enum ProductOwner {
    NonMs   = 0x000
    Windows = 0x100
}

[Flags()] enum ProductFlags {
    SignatureStatus = 0x00F0
    ProductOwner    = 0x0F00
    ProductState    = 0xF000
}

function Get-AntiVirusProductsFromWmi {
    param([string[]]$Namespaces)

    foreach ($ns in $Namespaces) {
        try {
            $items = Get-CimInstance -Namespace $ns -ClassName AntiVirusProduct -ErrorAction Stop
            if ($items) {
                return ,$items
            }
        } catch {
            continue
        }
    }

    return @()
}

function Get-ExecutablePath {
    param([string]$Path)

    if (-not $Path) {
        return $null
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($Path).Trim()
    if ($expanded.StartsWith('"')) {
        $end = $expanded.IndexOf('"', 1)
        if ($end -gt 1) {
            $expanded = $expanded.Substring(1, $end - 1)
        }
    } else {
        $expanded = $expanded.Split(' ')[0]
    }

    return $expanded
}

function Get-FileVersion {
    param([string]$Path)

    $exePath = Get-ExecutablePath -Path $Path
    if (-not $exePath) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $exePath)) {
        return $null
    }

    try {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exePath)
        if ($info.ProductVersion) {
            return $info.ProductVersion
        }
        if ($info.FileVersion) {
            return $info.FileVersion
        }
    } catch {
        return $null
    }

    return $null
}

function Convert-ProductState {
    param([uint32]$State)

    $productState = [ProductState]($State -band [ProductFlags]::ProductState)
    $signatureStatus = [SignatureStatus]($State -band [ProductFlags]::SignatureStatus)
    $owner = [ProductOwner]($State -band [ProductFlags]::ProductOwner)

    [pscustomobject]@{
        ActivityState   = $productState.ToString()
        SignatureStatus = $signatureStatus.ToString()
        Owner           = $owner.ToString()
        IsActive        = ($productState -eq [ProductState]::On)
    }
}

$namespaces = @("root/SecurityCenter2", "root/SecurityCenter")
$avProducts = @(Get-AntiVirusProductsFromWmi -Namespaces $namespaces)

if ($avProducts.Count -gt 0) {
    $results = foreach ($av in $avProducts) {
        $version = Get-FileVersion -Path $av.pathToSignedProductExe
        if (-not $version) {
            $version = Get-FileVersion -Path $av.pathToSignedReportingExe
        }

        $stateInfo = Convert-ProductState -State ([uint32]$av.productState)

        [pscustomobject]@{
            Name            = $av.displayName
            Version         = $version
            ActivityState   = $stateInfo.ActivityState
            SignatureStatus = $stateInfo.SignatureStatus
            Owner           = $stateInfo.Owner
            IsActive        = $stateInfo.IsActive
            ProductStateRaw = [uint32]$av.productState
            ProductStateHex = ("0x{0:X6}" -f [uint32]$av.productState)
            ProductExe      = $av.pathToSignedProductExe
        }
    }

    $results
    return
}

$mpCmd = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($null -ne $mpCmd) {
    $mp = Get-MpComputerStatus
    $isActive = ($mp.AntivirusEnabled -or $mp.RealTimeProtectionEnabled)

    [pscustomobject]@{
        Name            = "Windows Defender"
        Version         = $mp.AMProductVersion
        ActivityState   = if ($isActive) { "On" } else { "Off" }
        SignatureStatus = "Unknown"
        Owner           = "Windows"
        IsActive        = $isActive
        ProductStateRaw = $null
        ProductStateHex = $null
        ProductExe      = $null
    }

    return
}

Write-Warning "No antivirus information found via SecurityCenter namespaces or Defender cmdlets."

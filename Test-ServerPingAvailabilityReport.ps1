<#
.SYNOPSIS
    Server Ping Availability Report.

.DESCRIPTION
    Testaa mÃ¤Ã¤riteltyjen palvelimien ICMP-saavutettavuuden ja muodostaa yksinkertaisen saatavuusraportin.

.REQUIREMENTS
    - Verkkoyhteys kohdepalvelimiin ja ICMP sallittuna

.OUTPUTS
    - HTML/CSV-raportti palvelimien ping-tilasta

.EXAMPLE
    .\Test-ServerPingAvailabilityReport.ps1 -HostsToTest "server01.example.com","server02.example.com"

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Test-ServerPingAvailabilityReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

param(
    [string]$OutputFolder = (Join-Path $PSScriptRoot "output\ping"),
    [ValidateSet("All","SuccessOnly","FailedOnly")]
    [string]$Filter = "All",
    [int]$TimeoutMs = 2000,
    [int]$MaxConcurrentJobs = 15,
    [string[]]$HostsToTest = @()
)

$ErrorActionPreference = "Stop"

if (-not $HostsToTest -or $HostsToTest.Count -eq 0) {
    throw "No hosts were provided. Use -HostsToTest or wrap this script with your own environment-specific host source. Example: .\Test-ServerPingAvailabilityReport.ps1 -HostsToTest 'server01.example.com','server02.example.com'"
}


# ---------------------------------------
# Varmistukset
# ---------------------------------------
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CsvPath   = Join-Path $OutputFolder "PingResults_$TimeStamp.csv"
$HtmlPath  = Join-Path $OutputFolder "PingResults_$TimeStamp.html"

# ---------------------------------------
# HTML helper
# ---------------------------------------
function New-SafeHtml {
    param([object]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

# ---------------------------------------
# Job scriptblock
# ---------------------------------------
$JobScript = {
    param(
        [string]$HostName,
        [int]$TimeoutMs
    )

    $Resolved4 = @()
    $Resolved6 = @()
    $ReplyIP   = $null
    $ReplyRDNS = $null
    $PingOk    = $false
    $Status    = "Unknown"
    $Rtt       = $null
    $ErrorText = $null

    try {
        try {
            $dnsEntries = [System.Net.Dns]::GetHostAddresses($HostName)

            $Resolved4 = $dnsEntries |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { $_.IPAddressToString }

            $Resolved6 = $dnsEntries |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 } |
                ForEach-Object { $_.IPAddressToString }
        }
        catch {
            $ErrorText = "DNS resolve failed: $($_.Exception.Message)"
        }

        try {
            $pinger = New-Object System.Net.NetworkInformation.Ping
            $reply  = $pinger.Send($HostName, $TimeoutMs)

            if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $PingOk  = $true
                $Status  = "Success"
                $ReplyIP = $reply.Address.IPAddressToString
                $Rtt     = $reply.RoundtripTime

                try {
                    $ptr = [System.Net.Dns]::GetHostEntry($ReplyIP)
                    if ($ptr -and $ptr.HostName) {
                        $ReplyRDNS = $ptr.HostName
                    }
                }
                catch {
                    $ReplyRDNS = ""
                }
            }
            else {
                if ($reply) {
                    $Status = $reply.Status.ToString()
                }
                else {
                    $Status = "NoReply"
                }
            }
        }
        catch {
            if ([string]::IsNullOrWhiteSpace($ErrorText)) {
                $ErrorText = "Ping failed: $($_.Exception.Message)"
            }
            $Status = "Error"
        }
    }
    catch {
        $Status = "Error"
        $ErrorText = $_.Exception.Message
    }

    [PSCustomObject]@{
        HostName         = $HostName
        ResolvedIPv4     = if ($Resolved4.Count -gt 0) { $Resolved4 -join ", " } else { "" }
        ResolvedIPv6     = if ($Resolved6.Count -gt 0) { $Resolved6 -join ", " } else { "" }
        ReplyIP          = if ($ReplyIP) { $ReplyIP } else { "" }
        ReplyReverseDNS  = if ($ReplyRDNS) { $ReplyRDNS } else { "" }
        Status           = $Status
        Success          = $PingOk
        ResponseTimeMs   = $Rtt
        Error            = if ($ErrorText) { $ErrorText } else { "" }
    }
}

# ---------------------------------------
# Jobit kÃ¤yntiin throttlen kanssa
# ---------------------------------------
$Jobs = New-Object System.Collections.ArrayList
$Started = 0
$Total = $HostsToTest.Count

foreach ($HostName in $HostsToTest) {
    while (($Jobs | Where-Object { $_.State -eq "Running" }).Count -ge $MaxConcurrentJobs) {
        Start-Sleep -Milliseconds 300
    }

    $Started++
    Write-Progress -Activity "KÃ¤ynnistetÃ¤Ã¤n ping-jobit" `
                   -Status "$Started / $Total : $HostName" `
                   -PercentComplete (($Started / $Total) * 100)

    $job = Start-Job -ScriptBlock $JobScript -ArgumentList $HostName, $TimeoutMs
    [void]$Jobs.Add($job)
}

# ---------------------------------------
# Odota valmistumista
# ---------------------------------------
$Completed = 0
do {
    $DoneNow = ($Jobs | Where-Object { $_.State -in @("Completed","Failed","Stopped") }).Count
    if ($DoneNow -ne $Completed) {
        $Completed = $DoneNow
        Write-Progress -Activity "Odotetaan jobien valmistumista" `
                       -Status "$Completed / $Total valmiina" `
                       -PercentComplete (($Completed / $Total) * 100)
    }
    Start-Sleep -Milliseconds 300
}
while ($Completed -lt $Total)

Write-Progress -Activity "Odotetaan jobien valmistumista" -Completed

# ---------------------------------------
# KerÃ¤Ã¤ tulokset
# ---------------------------------------
$Results = foreach ($job in $Jobs) {
    try {
        Receive-Job -Job $job -ErrorAction Stop
    }
    catch {
        [PSCustomObject]@{
            HostName         = "<unknown>"
            ResolvedIPv4     = ""
            ResolvedIPv6     = ""
            ReplyIP          = ""
            ReplyReverseDNS  = ""
            Status           = "JobError"
            Success          = $false
            ResponseTimeMs   = $null
            Error            = $_.Exception.Message
        }
    }
}

# Siivotaan jobit pois
$Jobs | Remove-Job -Force -ErrorAction SilentlyContinue

# ---------------------------------------
# JÃ¤rjestys
# ---------------------------------------
$Results = $Results | Sort-Object HostName

# ---------------------------------------
# FiltterÃ¶inti
# ---------------------------------------
$FilteredResults = switch ($Filter) {
    "SuccessOnly" { $Results | Where-Object { $_.Success -eq $true } }
    "FailedOnly"  { $Results | Where-Object { $_.Success -ne $true } }
    default       { $Results }
}

# ---------------------------------------
# CSV
# ---------------------------------------
$FilteredResults | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

# ---------------------------------------
# HTML
# ---------------------------------------
$TotalCount   = @($Results).Count
$SuccessCount = @($Results | Where-Object { $_.Success -eq $true }).Count
$FailedCount  = $TotalCount - $SuccessCount

$RowsHtml = foreach ($row in $FilteredResults) {
    $rowClass = if ($row.Success) { "ok" } else { "fail" }

@"
<tr class="$rowClass">
  <td>$(New-SafeHtml $row.HostName)</td>
  <td>$(New-SafeHtml $row.ResolvedIPv4)</td>
  <td>$(New-SafeHtml $row.ResolvedIPv6)</td>
  <td>$(New-SafeHtml $row.ReplyIP)</td>
  <td>$(New-SafeHtml $row.ReplyReverseDNS)</td>
  <td>$(New-SafeHtml $row.Status)</td>
  <td>$(New-SafeHtml $row.ResponseTimeMs)</td>
  <td>$(New-SafeHtml $row.Error)</td>
</tr>
"@
}

$Html = @"
<!doctype html>
<html lang="fi">
<head>
<meta charset="utf-8">
<title>Ping-raportti</title>
<style>
body {
    font-family: Segoe UI, Arial, sans-serif;
    background: #0f172a;
    color: #e5e7eb;
    margin: 24px;
}
h1, h2 {
    margin-bottom: 8px;
}
.meta {
    color: #94a3b8;
    margin-bottom: 18px;
}
.cards {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin: 16px 0 24px 0;
}
.card {
    background: #111827;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 14px 18px;
    min-width: 180px;
}
.card .label {
    color: #94a3b8;
    font-size: 12px;
    text-transform: uppercase;
}
.card .value {
    font-size: 28px;
    font-weight: 700;
    margin-top: 6px;
}
table {
    width: 100%;
    border-collapse: collapse;
    background: #111827;
    border: 1px solid #334155;
}
th, td {
    padding: 10px 12px;
    border-bottom: 1px solid #1f2937;
    text-align: left;
    vertical-align: top;
    font-size: 14px;
}
th {
    background: #1e293b;
}
tr.ok td {
    background: rgba(34,197,94,0.08);
}
tr.fail td {
    background: rgba(239,68,68,0.08);
}
.small {
    font-size: 12px;
    color: #94a3b8;
}
</style>
</head>
<body>
    <h1>Ping-raportti</h1>
    <div class="meta">
        Luotu: $(Get-Date -Format "dd.MM.yyyy HH:mm:ss")<br>
        Filtteri: $(New-SafeHtml $Filter)<br>
        Timeout: $(New-SafeHtml $TimeoutMs) ms<br>
        MaxConcurrentJobs: $(New-SafeHtml $MaxConcurrentJobs)
    </div>

    <div class="cards">
        <div class="card">
            <div class="label">YhteensÃ¤</div>
            <div class="value">$TotalCount</div>
        </div>
        <div class="card">
            <div class="label">Onnistuneet</div>
            <div class="value">$SuccessCount</div>
        </div>
        <div class="card">
            <div class="label">EpÃ¤onnistuneet</div>
            <div class="value">$FailedCount</div>
        </div>
        <div class="card">
            <div class="label">NÃ¤ytetyt rivit</div>
            <div class="value">$(@($FilteredResults).Count)</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>HostName</th>
                <th>Resolved IPv4</th>
                <th>Resolved IPv6</th>
                <th>Reply IP</th>
                <th>Reverse DNS</th>
                <th>Status</th>
                <th>ResponseTimeMs</th>
                <th>Error</th>
            </tr>
        </thead>
        <tbody>
            $($RowsHtml -join "`r`n")
        </tbody>
    </table>

    <p class="small">
        Success = host vastasi ICMP-pingiin. Reply IP kertoo miltÃ¤ osoitteelta vastaus tuli. Reverse DNS yrittÃ¤Ã¤ tehdÃ¤ PTR-haun vastaavalle IP:lle.
    </p>
</body>
</html>
"@

Set-Content -Path $HtmlPath -Value $Html -Encoding UTF8

# ---------------------------------------
# RuutunÃ¤kymÃ¤
# ---------------------------------------
$FilteredResults |
    Select-Object HostName, ResolvedIPv4, ReplyIP, ReplyReverseDNS, Status, ResponseTimeMs, Error |
    Format-Table -AutoSize

# ---------------------------------------
# Yhteenveto
# ---------------------------------------
Write-Host ""
Write-Host "Valmis." -ForegroundColor Green
Write-Host "CSV : $CsvPath"
Write-Host "HTML: $HtmlPath"
Write-Host ""

$Results |
    Group-Object Status |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table -AutoSize

#requires -version 5.1
<#
.SYNOPSIS
    Audits LocalMachine certificates and Windows services running under named service accounts.

.DESCRIPTION
    Read-only local or remote Windows audit.
    
    Checks LocalMachine certificate stores for expired and soon-expiring certificates, and lists Windows services running under named service accounts while excluding built-in Windows service identities. Exports combined and per-computer CSV/HTML reports.

.OUTPUTS
    CSV and HTML reports are written to the selected output directory.

.REQUIREMENTS
      - Windows PowerShell 5.1
      - PowerShell remoting / WinRM for remote computers
      - Local administrator or sufficient read permissions on target computers

.DISCLAIMER
    This script is provided as an AI-assisted community example.
    It is intended for read-only auditing, but you must review and test it in a lab or test tenant before production use.
    Use at your own risk. No warranty is provided.

.NOTES
    GitHub-ready anonymized version.
    No customer names, tenant IDs, server names, domains or credentials are hardcoded.
    Save as UTF-8 with BOM when using Windows PowerShell 5.1.
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [int]$WarningDays = 30,
    [string]$OutDir = "$env:TEMP\NOC-Audit\Windows-Certificates",
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = "Stop"
$Now = Get-Date
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RunAs = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

$CsvPath  = Join-Path $OutDir "computer-certificates-services-$Timestamp.csv"
$HtmlPath = Join-Path $OutDir "computer-certificates-services-$Timestamp.html"

$AllCerts = New-Object System.Collections.Generic.List[object]
$AllServices = New-Object System.Collections.Generic.List[object]
$AllErrors = New-Object System.Collections.Generic.List[object]

function Convert-ToHtmlEncoded {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Test-IsLocalComputer {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }

    $LocalNames = @(
        ".",
        "localhost",
        $env:COMPUTERNAME,
        "$($env:COMPUTERNAME).$env:USERDNSDOMAIN"
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    return $LocalNames -contains $Name
}

$AuditScriptBlock = {
    param([int]$WarningDays)

    $Now = Get-Date
    $TargetComputer = $env:COMPUTERNAME

    $CertStores = @(
        "Cert:\LocalMachine\My",
        "Cert:\LocalMachine\WebHosting",
        "Cert:\LocalMachine\CA",
        "Cert:\LocalMachine\Root",
        "Cert:\LocalMachine\AuthRoot",
        "Cert:\LocalMachine\TrustedPeople",
        "Cert:\LocalMachine\TrustedPublisher",
        "Cert:\LocalMachine\Disallowed"
    )

    $CertRows = foreach ($Store in $CertStores) {
        if (-not (Test-Path $Store)) { continue }

        Get-ChildItem -Path $Store -ErrorAction SilentlyContinue | ForEach-Object {
            $DaysLeft = [math]::Floor(($_.NotAfter - $Now).TotalDays)

            $Status = if ($DaysLeft -lt 0) {
                "Expired"
            }
            elseif ($DaysLeft -le $WarningDays) {
                "ExpiringSoon"
            }
            else {
                "OK"
            }

            $DnsNames = ""
            try {
                $DnsNames = ($_.DnsNameList | ForEach-Object { $_.Unicode }) -join ", "
            }
            catch {
                $DnsNames = ""
            }

            [PSCustomObject]@{
                RecordType     = "Certificate"
                ComputerName   = $TargetComputer
                Status         = $Status
                Store          = $Store
                Subject        = $_.Subject
                Issuer         = $_.Issuer
                FriendlyName   = $_.FriendlyName
                DNSNames       = $DnsNames
                Thumbprint     = $_.Thumbprint
                SerialNumber   = $_.SerialNumber
                NotBefore      = $_.NotBefore
                NotAfter       = $_.NotAfter
                DaysLeft       = $DaysLeft
                HasPrivateKey  = $_.HasPrivateKey
                Archived       = $_.Archived
            }
        }
    }

    $ExcludedServiceAccounts = @(
        "localsystem",
        "system",
        "nt authority\system",
        "localservice",
        "local service",
        "networkservice",
        "network service",
        "nt authority\localservice",
        "nt authority\local service",
        "nt authority\networkservice",
        "nt authority\network service"
    )

    $ServiceRows = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
        Where-Object {
            $StartNameRaw = [string]$_.StartName
            $StartName = $StartNameRaw.Trim().ToLowerInvariant()

            -not [string]::IsNullOrWhiteSpace($StartNameRaw) -and
            $ExcludedServiceAccounts -notcontains $StartName -and
            $StartName -notlike "nt service\*"
        } |
        Sort-Object StartName, Name |
        ForEach-Object {
            [PSCustomObject]@{
                RecordType    = "ServiceAccount"
                ComputerName  = $TargetComputer
                Status        = "Info"
                ServiceName   = $_.Name
                DisplayName   = $_.DisplayName
                StartName     = $_.StartName
                State         = $_.State
                StartMode     = $_.StartMode
                PathName      = $_.PathName
                Description   = $_.Description
            }
        }

    [PSCustomObject]@{
        ComputerName  = $TargetComputer
        Certs         = [object[]]@($CertRows)
        Services      = [object[]]@($ServiceRows)
        CertCount     = @($CertRows).Count
        ServiceCount  = @($ServiceRows).Count
    }
}

Write-Host ""
Write-Host "=== Computer Certificate + Windows Service Account Audit ===" -ForegroundColor Cyan
Write-Host "Ajetaan käyttäjänä : $RunAs"
Write-Host "Tarkistushetki    : $Now"
Write-Host "Varoitusraja      : $WarningDays päivää"
Write-Host "Raporttikansio    : $OutDir"
Write-Host "Kohdekoneet       : $($ComputerName -join ', ')"
Write-Host ""

foreach ($Computer in $ComputerName) {
    Write-Host "Käsitellään: $Computer" -ForegroundColor Cyan

    try {
        if (Test-IsLocalComputer -Name $Computer) {
            $Result = & $AuditScriptBlock $WarningDays
        }
        else {
            $InvokeParams = @{
                ComputerName = $Computer
                ScriptBlock  = $AuditScriptBlock
                ArgumentList = @($WarningDays)
                ErrorAction  = "Stop"
            }

            if ($Credential) { $InvokeParams.Credential = $Credential }
            $Result = Invoke-Command @InvokeParams
        }

        Write-Host "  Sertifikaatteja palautui : $($Result.CertCount)" -ForegroundColor DarkGray
        Write-Host "  Palvelutilejä palautui  : $($Result.ServiceCount)" -ForegroundColor DarkGray

        foreach ($Cert in [object[]]@($Result.Certs)) {
            if ($null -ne $Cert) { $AllCerts.Add($Cert) }
        }

        foreach ($Service in [object[]]@($Result.Services)) {
            if ($null -ne $Service) { $AllServices.Add($Service) }
        }
    }
    catch {
        $AllErrors.Add([PSCustomObject]@{
            RecordType   = "Error"
            ComputerName = $Computer
            Status       = "Warning"
            Error        = $_.Exception.Message
        })

        Write-Host "  VIRHE: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$AllCertsSorted = $AllCerts | Sort-Object ComputerName, DaysLeft, Subject
$Expired = $AllCertsSorted | Where-Object { $_.Status -eq "Expired" }
$ExpiringSoon = $AllCertsSorted | Where-Object { $_.Status -eq "ExpiringSoon" }
$OkCerts = $AllCertsSorted | Where-Object { $_.Status -eq "OK" }
$AllServicesSorted = $AllServices | Sort-Object ComputerName, StartName, ServiceName

$ServiceAccountSummary = $AllServicesSorted |
    Group-Object ComputerName, StartName |
    Sort-Object Name |
    ForEach-Object {
        $Parts = $_.Name -split ", ", 2
        [PSCustomObject]@{
            ComputerName = $Parts[0]
            StartName    = $Parts[1]
            ServiceCount = $_.Count
            Services     = ($_.Group.ServiceName -join ", ")
        }
    }

$CsvRows = New-Object System.Collections.Generic.List[object]

foreach ($Cert in $AllCertsSorted) {
    $CsvRows.Add([PSCustomObject]@{
        RecordType     = "Certificate"
        ComputerName   = $Cert.ComputerName
        Status         = $Cert.Status
        Store          = $Cert.Store
        Subject        = $Cert.Subject
        Issuer         = $Cert.Issuer
        FriendlyName   = $Cert.FriendlyName
        DNSNames       = $Cert.DNSNames
        Thumbprint     = $Cert.Thumbprint
        SerialNumber   = $Cert.SerialNumber
        NotBefore      = $Cert.NotBefore
        NotAfter       = $Cert.NotAfter
        DaysLeft       = $Cert.DaysLeft
        HasPrivateKey  = $Cert.HasPrivateKey
        Archived       = $Cert.Archived
        ServiceName    = ""
        DisplayName    = ""
        StartName      = ""
        State          = ""
        StartMode      = ""
        PathName       = ""
        Error          = ""
    })
}

foreach ($Service in $AllServicesSorted) {
    $CsvRows.Add([PSCustomObject]@{
        RecordType     = "ServiceAccount"
        ComputerName   = $Service.ComputerName
        Status         = $Service.Status
        Store          = ""
        Subject        = ""
        Issuer         = ""
        FriendlyName   = ""
        DNSNames       = ""
        Thumbprint     = ""
        SerialNumber   = ""
        NotBefore      = ""
        NotAfter       = ""
        DaysLeft       = ""
        HasPrivateKey  = ""
        Archived       = ""
        ServiceName    = $Service.ServiceName
        DisplayName    = $Service.DisplayName
        StartName      = $Service.StartName
        State          = $Service.State
        StartMode      = $Service.StartMode
        PathName       = $Service.PathName
        Error          = ""
    })
}

foreach ($Err in $AllErrors) {
    $CsvRows.Add([PSCustomObject]@{
        RecordType     = "Error"
        ComputerName   = $Err.ComputerName
        Status         = $Err.Status
        Store          = ""
        Subject        = ""
        Issuer         = ""
        FriendlyName   = ""
        DNSNames       = ""
        Thumbprint     = ""
        SerialNumber   = ""
        NotBefore      = ""
        NotAfter       = ""
        DaysLeft       = ""
        HasPrivateKey  = ""
        Archived       = ""
        ServiceName    = ""
        DisplayName    = ""
        StartName      = ""
        State          = ""
        StartMode      = ""
        PathName       = ""
        Error          = $Err.Error
    })
}

$CsvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

$DetectedComputers = $CsvRows |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_.ComputerName) } |
    Select-Object -ExpandProperty ComputerName -Unique |
    Sort-Object

foreach ($DetectedComputer in $DetectedComputers) {
    $SafeComputerName = ($DetectedComputer -replace '[\\/:*?"<>|]', '_')
    $ComputerCsvPath = Join-Path $OutDir "$SafeComputerName-certificates-services-$Timestamp.csv"

    $ComputerRows = $CsvRows | Where-Object { $_.ComputerName -eq $DetectedComputer }
    if ($ComputerRows.Count -gt 0) {
        $ComputerRows | Export-Csv -Path $ComputerCsvPath -NoTypeInformation -Encoding UTF8
    }
}

function New-CertRowsHtml {
    param([object[]]$Certs)

    foreach ($Cert in $Certs) {
        $BadgeClass = switch ($Cert.Status) {
            "OK"           { "badge badge-ok" }
            "ExpiringSoon" { "badge badge-warn" }
            "Expired"      { "badge badge-crit" }
            default        { "badge badge-info" }
        }

        $ModalId = "certModal_" + ([guid]::NewGuid().ToString("N"))

@"
<tr data-cert-status="$(Convert-ToHtmlEncoded $Cert.Status)">
    <td>$(Convert-ToHtmlEncoded $Cert.ComputerName)</td>
    <td><span class="$BadgeClass">$(Convert-ToHtmlEncoded $Cert.Status)</span></td>
    <td>$(Convert-ToHtmlEncoded $Cert.Store)</td>
    <td>$(Convert-ToHtmlEncoded $Cert.Subject)</td>
    <td>$(Convert-ToHtmlEncoded $Cert.DNSNames)</td>
    <td>$(Convert-ToHtmlEncoded $Cert.NotAfter)</td>
    <td>$(Convert-ToHtmlEncoded $Cert.DaysLeft)</td>
    <td>
        <button class="details-button" type="button" onclick="openModal('$ModalId')">Lisätiedot</button>
        <div id="$ModalId" class="modal-overlay">
            <div class="modal-box">
                <div class="modal-header">
                    <h2>Sertifikaatin lisätiedot</h2>
                    <button class="modal-close" type="button" onclick="closeModal('$ModalId')">&times;</button>
                </div>
                <div class="modal-content">
                    <table class="details-table">
                        <tr><th>ComputerName</th><td>$(Convert-ToHtmlEncoded $Cert.ComputerName)</td></tr>
                        <tr><th>Status</th><td>$(Convert-ToHtmlEncoded $Cert.Status)</td></tr>
                        <tr><th>Store</th><td>$(Convert-ToHtmlEncoded $Cert.Store)</td></tr>
                        <tr><th>Subject</th><td>$(Convert-ToHtmlEncoded $Cert.Subject)</td></tr>
                        <tr><th>Issuer</th><td>$(Convert-ToHtmlEncoded $Cert.Issuer)</td></tr>
                        <tr><th>FriendlyName</th><td>$(Convert-ToHtmlEncoded $Cert.FriendlyName)</td></tr>
                        <tr><th>DNSNames</th><td>$(Convert-ToHtmlEncoded $Cert.DNSNames)</td></tr>
                        <tr><th>NotBefore</th><td>$(Convert-ToHtmlEncoded $Cert.NotBefore)</td></tr>
                        <tr><th>NotAfter</th><td>$(Convert-ToHtmlEncoded $Cert.NotAfter)</td></tr>
                        <tr><th>DaysLeft</th><td>$(Convert-ToHtmlEncoded $Cert.DaysLeft)</td></tr>
                        <tr><th>HasPrivateKey</th><td>$(Convert-ToHtmlEncoded $Cert.HasPrivateKey)</td></tr>
                        <tr><th>Archived</th><td>$(Convert-ToHtmlEncoded $Cert.Archived)</td></tr>
                        <tr><th>SerialNumber</th><td class="mono">$(Convert-ToHtmlEncoded $Cert.SerialNumber)</td></tr>
                        <tr><th>Thumbprint</th><td class="mono">$(Convert-ToHtmlEncoded $Cert.Thumbprint)</td></tr>
                    </table>
                </div>
            </div>
        </div>
    </td>
</tr>
"@
    }
}

function New-ServiceSummaryRowsHtml {
    param([object[]]$ServiceSummary)
    foreach ($Item in $ServiceSummary) {
@"
<tr>
    <td>$(Convert-ToHtmlEncoded $Item.ComputerName)</td>
    <td>$(Convert-ToHtmlEncoded $Item.StartName)</td>
    <td>$(Convert-ToHtmlEncoded $Item.ServiceCount)</td>
    <td>$(Convert-ToHtmlEncoded $Item.Services)</td>
</tr>
"@
    }
}

function New-ServiceRowsHtml {
    param([object[]]$Services)
    foreach ($Service in $Services) {
@"
<tr>
    <td>$(Convert-ToHtmlEncoded $Service.ComputerName)</td>
    <td>$(Convert-ToHtmlEncoded $Service.StartName)</td>
    <td>$(Convert-ToHtmlEncoded $Service.ServiceName)</td>
    <td>$(Convert-ToHtmlEncoded $Service.DisplayName)</td>
    <td>$(Convert-ToHtmlEncoded $Service.State)</td>
    <td>$(Convert-ToHtmlEncoded $Service.StartMode)</td>
    <td class="path-cell" title="$(Convert-ToHtmlEncoded $Service.PathName)">$(Convert-ToHtmlEncoded $Service.PathName)</td>
</tr>
"@
    }
}

function New-ErrorRowsHtml {
    param([object[]]$Errors)
    foreach ($Err in $Errors) {
@"
<tr>
    <td>$(Convert-ToHtmlEncoded $Err.ComputerName)</td>
    <td><span class="badge badge-warn">Warning</span></td>
    <td>$(Convert-ToHtmlEncoded $Err.Error)</td>
</tr>
"@
    }
}

function New-ServiceSummary {
    param([object[]]$Services)
    $Services |
        Group-Object ComputerName, StartName |
        Sort-Object Name |
        ForEach-Object {
            $Parts = $_.Name -split ", ", 2
            [PSCustomObject]@{
                ComputerName = $Parts[0]
                StartName    = $Parts[1]
                ServiceCount = $_.Count
                Services     = ($_.Group.ServiceName -join ", ")
            }
        }
}

$HtmlStyle = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; background: #f3f4f6; color: #111827; margin: 24px; }
h1, h2 { margin-bottom: 6px; }
.meta { color: #4b5563; margin-bottom: 24px; }
.summary { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }
.card { background: #ffffff; border: 1px solid #d1d5db; border-radius: 10px; padding: 14px 18px; min-width: 160px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); cursor: pointer; text-align: left; transition: transform 0.08s ease, box-shadow 0.08s ease, border-color 0.08s ease; font-family: inherit; }
.card:hover { transform: translateY(-1px); box-shadow: 0 4px 14px rgba(0,0,0,0.12); border-color: #94a3b8; }
.card.active { outline: 2px solid #2563eb; border-color: #2563eb; }
.card-title { font-size: 12px; text-transform: uppercase; color: #6b7280; margin-bottom: 4px; }
.card-value { font-size: 24px; font-weight: 700; }
.ok { color: #15803d; font-weight: 700; }
.warn { color: #b45309; font-weight: 700; }
.crit { color: #b91c1c; font-weight: 700; }
.info { color: #2563eb; font-weight: 700; }
.table-wrap { width: 100%; overflow-x: auto; overflow-y: visible; margin-bottom: 32px; border: 1px solid #d1d5db; border-radius: 10px; background: #ffffff; }
table { border-collapse: collapse; width: max-content; min-width: 100%; background: #ffffff; font-size: 13px; table-layout: fixed; }
th { background: #111827; color: #ffffff; text-align: left; padding: 9px 8px; position: sticky; top: 0; z-index: 2; white-space: normal; }
td { border: 1px solid #d1d5db; padding: 8px; vertical-align: top; word-break: normal; overflow-wrap: break-word; white-space: normal; line-height: 1.35; }
tr:nth-child(even) { background: #f9fafb; }
.badge { display: inline-block; padding: 2px 7px; border-radius: 999px; font-weight: 700; font-size: 12px; }
.badge-ok { background: #dcfce7; color: #166534; }
.badge-warn { background: #fef3c7; color: #92400e; }
.badge-crit { background: #fee2e2; color: #991b1b; }
.badge-info { background: #dbeafe; color: #1d4ed8; }
#certTable th:nth-child(1), #certTable td:nth-child(1) { width: 150px; }
#certTable th:nth-child(2), #certTable td:nth-child(2) { width: 120px; }
#certTable th:nth-child(3), #certTable td:nth-child(3) { width: 230px; }
#certTable th:nth-child(4), #certTable td:nth-child(4) { width: 420px; }
#certTable th:nth-child(5), #certTable td:nth-child(5) { width: 320px; }
#certTable th:nth-child(6), #certTable td:nth-child(6) { width: 180px; }
#certTable th:nth-child(7), #certTable td:nth-child(7) { width: 90px; text-align: right; }
#certTable th:nth-child(8), #certTable td:nth-child(8) { width: 130px; text-align: center; }
#serviceSummaryTable th:nth-child(1), #serviceSummaryTable td:nth-child(1) { width: 160px; }
#serviceSummaryTable th:nth-child(2), #serviceSummaryTable td:nth-child(2) { width: 260px; }
#serviceSummaryTable th:nth-child(3), #serviceSummaryTable td:nth-child(3) { width: 100px; text-align: right; }
#serviceSummaryTable th:nth-child(4), #serviceSummaryTable td:nth-child(4) { width: 650px; }
#serviceTable th:nth-child(1), #serviceTable td:nth-child(1) { width: 160px; }
#serviceTable th:nth-child(2), #serviceTable td:nth-child(2) { width: 260px; }
#serviceTable th:nth-child(3), #serviceTable td:nth-child(3) { width: 230px; }
#serviceTable th:nth-child(4), #serviceTable td:nth-child(4) { width: 320px; }
#serviceTable th:nth-child(5), #serviceTable td:nth-child(5) { width: 100px; }
#serviceTable th:nth-child(6), #serviceTable td:nth-child(6) { width: 110px; }
#serviceTable th:nth-child(7), #serviceTable td:nth-child(7) { width: 520px; max-width: 520px; white-space: pre-wrap; }
#errorTable th:nth-child(1), #errorTable td:nth-child(1) { width: 180px; }
#errorTable th:nth-child(2), #errorTable td:nth-child(2) { width: 120px; }
#errorTable th:nth-child(3), #errorTable td:nth-child(3) { width: 800px; }
.details-button { padding: 6px 10px; border: 1px solid #cbd5e1; border-radius: 8px; background: #ffffff; color: #111827; cursor: pointer; font-size: 13px; }
.details-button:hover { background: #f9fafb; border-color: #94a3b8; }
.modal-overlay { display: none; position: fixed; z-index: 9999; inset: 0; background: rgba(15, 23, 42, 0.65); padding: 32px; }
.modal-overlay.open { display: flex; align-items: center; justify-content: center; }
.modal-box { background: #ffffff; border-radius: 12px; border: 1px solid #d1d5db; width: min(980px, 96vw); max-height: 88vh; overflow: auto; box-shadow: 0 24px 80px rgba(0,0,0,0.35); }
.modal-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 16px 18px; border-bottom: 1px solid #e5e7eb; position: sticky; top: 0; background: #ffffff; z-index: 1; }
.modal-header h2 { margin: 0; font-size: 18px; }
.modal-close { border: none; background: #f3f4f6; color: #111827; font-size: 24px; line-height: 1; border-radius: 8px; cursor: pointer; padding: 4px 10px; }
.modal-close:hover { background: #e5e7eb; }
.modal-content { padding: 18px; }
.details-table { width: 100%; min-width: 0; table-layout: fixed; border-collapse: collapse; }
.details-table th { width: 180px; background: #f9fafb; color: #111827; position: static; cursor: default; }
.details-table td { background: #ffffff; }
.mono { font-family: Consolas, monospace; font-size: 12px; overflow-wrap: break-word; }
.path-cell { max-width: 520px; white-space: pre-wrap; overflow-wrap: break-word; line-height: 1.35; }
.service-wrap { overflow-x: auto; }
.section-hidden { display: none; }
.cert-row-hidden { display: none; }
</style>
"@

$HtmlScript = @"
<script>
function openModal(id) {
    var modal = document.getElementById(id);
    if (modal) { modal.classList.add('open'); }
}

function closeModal(id) {
    var modal = document.getElementById(id);
    if (modal) { modal.classList.remove('open'); }
}

function setActiveCard(card) {
    document.querySelectorAll('.card[data-filter]').forEach(function(item) { item.classList.remove('active'); });
    if (card) { card.classList.add('active'); }
}

function showSection(id, show) {
    var section = document.getElementById(id);
    if (!section) { return; }
    if (show) { section.classList.remove('section-hidden'); }
    else { section.classList.add('section-hidden'); }
}

function filterCertificates(status) {
    var rows = document.querySelectorAll('#certTable tbody tr[data-cert-status]');
    rows.forEach(function(row) {
        var rowStatus = row.getAttribute('data-cert-status');
        if (status === 'all' || rowStatus === status) { row.classList.remove('cert-row-hidden'); }
        else { row.classList.add('cert-row-hidden'); }
    });
}

function applyDashboardFilter(filter) {
    if (filter === 'cert-all') {
        showSection('certSection', true);
        showSection('serviceSection', true);
        showSection('errorSection', true);
        filterCertificates('all');
        return;
    }
    if (filter === 'cert-ok') { showSection('certSection', true); showSection('serviceSection', false); showSection('errorSection', false); filterCertificates('OK'); return; }
    if (filter === 'cert-expiring') { showSection('certSection', true); showSection('serviceSection', false); showSection('errorSection', false); filterCertificates('ExpiringSoon'); return; }
    if (filter === 'cert-expired') { showSection('certSection', true); showSection('serviceSection', false); showSection('errorSection', false); filterCertificates('Expired'); return; }
    if (filter === 'services') { showSection('certSection', false); showSection('serviceSection', true); showSection('errorSection', false); return; }
    if (filter === 'errors') { showSection('certSection', false); showSection('serviceSection', false); showSection('errorSection', true); return; }
}

document.addEventListener('click', function(event) {
    if (event.target.classList && event.target.classList.contains('modal-overlay')) { event.target.classList.remove('open'); return; }
    var card = event.target.closest ? event.target.closest('.card[data-filter]') : null;
    if (card) {
        var filter = card.getAttribute('data-filter');
        setActiveCard(card);
        applyDashboardFilter(filter);
    }
});

document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.open').forEach(function(modal) { modal.classList.remove('open'); });
    }
});

document.addEventListener('DOMContentLoaded', function() { applyDashboardFilter('cert-all'); });
</script>
"@

function New-ReportBody {
    param(
        [string]$Title,
        [string]$MetaComputerLine,
        [object[]]$Certs,
        [object[]]$Services,
        [object[]]$Errors
    )

    $ExpiredLocal = $Certs | Where-Object { $_.Status -eq "Expired" }
    $ExpiringLocal = $Certs | Where-Object { $_.Status -eq "ExpiringSoon" }
    $OkLocal = $Certs | Where-Object { $_.Status -eq "OK" }
    $ServiceSummaryLocal = New-ServiceSummary -Services $Services

    $CertRowsHtml = New-CertRowsHtml -Certs $Certs
    $ServiceSummaryRowsHtml = New-ServiceSummaryRowsHtml -ServiceSummary $ServiceSummaryLocal
    $ServiceRowsHtml = New-ServiceRowsHtml -Services $Services
    $ErrorRowsHtml = New-ErrorRowsHtml -Errors $Errors

    $ErrorSection = if ($Errors.Count -gt 0) {
@"
<h2>Virheet / tavoittamattomat koneet</h2>
<div class="table-wrap">
<table id="errorTable">
    <thead><tr><th>ComputerName</th><th>Status</th><th>Error</th></tr></thead>
    <tbody>$($ErrorRowsHtml -join "`n")</tbody>
</table>
</div>
"@
    }
    else {
@"
<h2>Virheet / tavoittamattomat koneet</h2>
<p>Ei virheitä.</p>
"@
    }

@"
<h1>$Title</h1>
<div class="meta">
    Tarkistushetki: $Now<br>
    Ajetaan käyttäjänä: $RunAs<br>
    Varoitusraja: $WarningDays päivää<br>
    Raporttikansio: $OutDir<br>
    $MetaComputerLine<br>
    Scope: LocalMachine certificates + Windows services running as named service accounts. Read-only.
</div>

<div class="summary">
    <button class="card active" type="button" data-filter="cert-all"><div class="card-title">Sertifikaatteja</div><div class="card-value">$($Certs.Count)</div></button>
    <button class="card" type="button" data-filter="cert-ok"><div class="card-title">OK</div><div class="card-value ok">$($OkLocal.Count)</div></button>
    <button class="card" type="button" data-filter="cert-expiring"><div class="card-title">Vanhenemassa</div><div class="card-value warn">$($ExpiringLocal.Count)</div></button>
    <button class="card" type="button" data-filter="cert-expired"><div class="card-title">Vanhentuneet</div><div class="card-value crit">$($ExpiredLocal.Count)</div></button>
    <button class="card" type="button" data-filter="services"><div class="card-title">Palveluita palvelutileillä</div><div class="card-value info">$($Services.Count)</div></button>
    <button class="card" type="button" data-filter="errors"><div class="card-title">Virheitä</div><div class="card-value warn">$($Errors.Count)</div></button>
</div>

<div id="certSection">
<h2>Sertifikaatit</h2>
<div class="table-wrap">
<table id="certTable">
    <thead><tr><th>ComputerName</th><th>Status</th><th>Store</th><th>Subject</th><th>DNSNames</th><th>NotAfter</th><th>DaysLeft</th><th>Lisätiedot</th></tr></thead>
    <tbody>$($CertRowsHtml -join "`n")</tbody>
</table>
</div>
</div>

<div id="serviceSection">
<h2>Palvelutilit, yhteenveto</h2>
<div class="table-wrap">
<table id="serviceSummaryTable">
    <thead><tr><th>ComputerName</th><th>StartName</th><th>ServiceCount</th><th>Services</th></tr></thead>
    <tbody>$($ServiceSummaryRowsHtml -join "`n")</tbody>
</table>
</div>

<h2>Palvelutilit, palvelukohtainen listaus</h2>
<div class="table-wrap service-wrap">
<table id="serviceTable">
    <thead><tr><th>ComputerName</th><th>StartName</th><th>ServiceName</th><th>DisplayName</th><th>State</th><th>StartMode</th><th>PathName</th></tr></thead>
    <tbody>$($ServiceRowsHtml -join "`n")</tbody>
</table>
</div>
</div>

<div id="errorSection">
$ErrorSection
</div>
"@
}

$HtmlHead = @"
<meta charset="utf-8">
$HtmlStyle
"@

$HtmlBody = New-ReportBody `
    -Title "Computer Certificate + Windows Service Account Audit" `
    -MetaComputerLine "Kohdekoneet: $($ComputerName -join ', ')" `
    -Certs $AllCertsSorted `
    -Services $AllServicesSorted `
    -Errors $AllErrors

$Html = ConvertTo-Html -Title "Computer Certificate + Service Account Audit" -Head $HtmlHead -Body ($HtmlBody + $HtmlScript)
$Html | Out-File -FilePath $HtmlPath -Encoding UTF8

foreach ($DetectedComputer in $DetectedComputers) {
    $SafeComputerName = ($DetectedComputer -replace '[\\/:*?"<>|]', '_')
    $ComputerHtmlPath = Join-Path $OutDir "$SafeComputerName-certificates-services-$Timestamp.html"

    $ComputerCerts = $AllCertsSorted | Where-Object { $_.ComputerName -eq $DetectedComputer }
    $ComputerServices = $AllServicesSorted | Where-Object { $_.ComputerName -eq $DetectedComputer }
    $ComputerErrors = $AllErrors | Where-Object { $_.ComputerName -eq $DetectedComputer }

    $ComputerBody = New-ReportBody `
        -Title "Computer Certificate + Service Account Audit - $DetectedComputer" `
        -MetaComputerLine "Kone: $DetectedComputer" `
        -Certs $ComputerCerts `
        -Services $ComputerServices `
        -Errors $ComputerErrors

    $ComputerHtml = ConvertTo-Html -Title "Computer Certificate + Service Account Audit - $DetectedComputer" -Head $HtmlHead -Body ($ComputerBody + $HtmlScript)
    $ComputerHtml | Out-File -FilePath $ComputerHtmlPath -Encoding UTF8
}

Write-Host ""
Write-Host "Raportit luotu:" -ForegroundColor Cyan
Write-Host "  CSV : $CsvPath"
Write-Host "  HTML: $HtmlPath"
Write-Host ""

Write-Host "Yhteenveto:" -ForegroundColor Cyan
Write-Host "  Koneita                 : $($ComputerName.Count)"
Write-Host "  Sertifikaatteja         : $($AllCertsSorted.Count)"
Write-Host "  OK                      : $($OkCerts.Count)" -ForegroundColor Green
Write-Host "  Vanhenemassa            : $($ExpiringSoon.Count)" -ForegroundColor Yellow
Write-Host "  Vanhentuneet            : $($Expired.Count)" -ForegroundColor Red
Write-Host "  Palvelutili-yhteenvedot : $($ServiceAccountSummary.Count)" -ForegroundColor Cyan
Write-Host "  Service-rivejä          : $($AllServicesSorted.Count)" -ForegroundColor Cyan
Write-Host "  Virheitä                : $($AllErrors.Count)" -ForegroundColor Yellow
Write-Host ""

if ($Expired.Count -gt 0) {
    Write-Host "CRITICAL: Vanhentuneita sertifikaatteja löytyi: $($Expired.Count)" -ForegroundColor Red
    $Expired | Select-Object ComputerName, Status, Store, Subject, NotAfter, DaysLeft, Thumbprint | Format-Table -AutoSize
    exit 2
}

if ($ExpiringSoon.Count -gt 0 -or $AllErrors.Count -gt 0) {
    if ($ExpiringSoon.Count -gt 0) {
        Write-Host "WARNING: $WarningDays päivän sisällä vanhenevia sertifikaatteja löytyi: $($ExpiringSoon.Count)" -ForegroundColor Yellow
        $ExpiringSoon | Select-Object ComputerName, Status, Store, Subject, NotAfter, DaysLeft, Thumbprint | Format-Table -AutoSize
    }

    if ($AllErrors.Count -gt 0) {
        Write-Host ""
        Write-Host "WARNING: Osa koneista epäonnistui: $($AllErrors.Count)" -ForegroundColor Yellow
        $AllErrors | Select-Object ComputerName, Error | Format-Table -AutoSize
    }

    exit 1
}

Write-Host "OK: Ei vanhentuneita tai pian vanhenevia computer-sertifikaatteja, eikä etäkonevirheitä." -ForegroundColor Green
exit 0

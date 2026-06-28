#requires -version 5.1
<#
.SYNOPSIS
    Audits Microsoft Entra app registration and enterprise application credential expiry.

.DESCRIPTION
    Read-only Microsoft Graph audit for App Registrations and Enterprise Applications / Service Principals.
    
    Checks certificate credentials and client secrets, calculates expiry status, and exports CSV and HTML reports. Long technical values such as ObjectId, KeyId, Hint and CustomKeyIdentifier values are shown in an HTML details modal to keep the main table readable.

.OUTPUTS
    CSV and HTML reports are written to the selected output directory.

.REQUIREMENTS
      - Microsoft.Graph PowerShell module
      - Delegated Graph permission: Application.Read.All
      - Admin consent may be required

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
    [int]$WarningDays = 30,

    [string]$OutDir = "$env:TEMP\NOC-Audit\M365-Entra-Credentials",

    [switch]$SkipGraphConnect
)

$ErrorActionPreference = "Stop"

$Now = Get-Date
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$CsvPath  = Join-Path $OutDir "m365-apps-enterpriseapps-credentials-$Timestamp.csv"
$HtmlPath = Join-Path $OutDir "m365-apps-enterpriseapps-credentials-$Timestamp.html"

New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

function Get-CredentialStatus {
    param(
        [datetime]$EndDate,
        [datetime]$Now,
        [int]$WarningDays
    )

    $DaysLeft = [math]::Floor(($EndDate - $Now).TotalDays)

    $Status = if ($DaysLeft -lt 0) {
        "Expired"
    }
    elseif ($DaysLeft -le $WarningDays) {
        "ExpiringSoon"
    }
    else {
        "OK"
    }

    [PSCustomObject]@{
        Status   = $Status
        DaysLeft = $DaysLeft
    }
}

function Convert-CustomKeyIdentifierToBase64 {
    param(
        $CustomKeyIdentifier
    )

    if ($null -eq $CustomKeyIdentifier) {
        return ""
    }

    try {
        return [System.Convert]::ToBase64String($CustomKeyIdentifier)
    }
    catch {
        return ""
    }
}

function Convert-CustomKeyIdentifierToHex {
    param(
        $CustomKeyIdentifier
    )

    if ($null -eq $CustomKeyIdentifier) {
        return ""
    }

    try {
        return (($CustomKeyIdentifier | ForEach-Object { $_.ToString("X2") }) -join "")
    }
    catch {
        return ""
    }
}

function Convert-ToHtmlEncoded {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

Write-Host ""
Write-Host "=== M365 / Entra ID Credential Expiry Audit ===" -ForegroundColor Cyan
Write-Host "Tarkistushetki : $Now"
Write-Host "Varoitusraja   : $WarningDays päivää"
Write-Host "Raporttikansio : $OutDir"
Write-Host ""

# Module check
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications"
)

foreach ($ModuleName in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Puuttuva moduuli: $ModuleName" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Asenna Microsoft Graph PowerShell näin:" -ForegroundColor Yellow
        Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Cyan
        exit 2
    }
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Applications -ErrorAction Stop

if (-not $SkipGraphConnect) {
    Write-Host "Yhdistetään Microsoft Graphiin read-only scopeilla..." -ForegroundColor Cyan

    Connect-MgGraph `
        -Scopes "Application.Read.All" `
        -NoWelcome
}

$Context = Get-MgContext

if (-not $Context) {
    Write-Host "Microsoft Graph -yhteyttä ei ole. Kirjaudu ensin Connect-MgGraph-komennolla tai aja ilman -SkipGraphConnect-parametria." -ForegroundColor Red
    exit 2
}

Write-Host ""
Write-Host "Graph-yhteys:" -ForegroundColor Cyan
Write-Host "  TenantId : $($Context.TenantId)"
Write-Host "  Account  : $($Context.Account)"
Write-Host "  Scopes   : $($Context.Scopes -join ', ')"
Write-Host ""

$Rows = New-Object System.Collections.Generic.List[object]

# ------------------------------------------------------------
# App Registrations / Applications
# ------------------------------------------------------------

Write-Host "Haetaan App Registrations / Applications..." -ForegroundColor Cyan

$Applications = Get-MgApplication `
    -All `
    -Property Id,AppId,DisplayName,KeyCredentials,PasswordCredentials,SignInAudience,CreatedDateTime

foreach ($App in $Applications) {

    foreach ($Key in $App.KeyCredentials) {
        if ($null -eq $Key.EndDateTime) {
            continue
        }

        $Start = [datetime]$Key.StartDateTime
        $End   = [datetime]$Key.EndDateTime

        $StatusInfo = Get-CredentialStatus `
            -EndDate $End `
            -Now $Now `
            -WarningDays $WarningDays

        $Rows.Add([PSCustomObject]@{
            Status                = $StatusInfo.Status
            SourceType            = "AppRegistration"
            CredentialType        = "Certificate"
            DisplayName           = $App.DisplayName
            AppId                 = $App.AppId
            ObjectId              = $App.Id
            SignInAudience        = $App.SignInAudience
            CredentialName        = $Key.DisplayName
            KeyId                 = $Key.KeyId
            Hint                  = ""
            CustomKeyIdBase64     = Convert-CustomKeyIdentifierToBase64 -CustomKeyIdentifier $Key.CustomKeyIdentifier
            CustomKeyIdHex        = Convert-CustomKeyIdentifierToHex -CustomKeyIdentifier $Key.CustomKeyIdentifier
            StartDateTime         = $Start
            EndDateTime           = $End
            DaysLeft              = $StatusInfo.DaysLeft
            CreatedDateTime       = $App.CreatedDateTime
        })
    }

    foreach ($Secret in $App.PasswordCredentials) {
        if ($null -eq $Secret.EndDateTime) {
            continue
        }

        $Start = [datetime]$Secret.StartDateTime
        $End   = [datetime]$Secret.EndDateTime

        $StatusInfo = Get-CredentialStatus `
            -EndDate $End `
            -Now $Now `
            -WarningDays $WarningDays

        $Rows.Add([PSCustomObject]@{
            Status                = $StatusInfo.Status
            SourceType            = "AppRegistration"
            CredentialType        = "ClientSecret"
            DisplayName           = $App.DisplayName
            AppId                 = $App.AppId
            ObjectId              = $App.Id
            SignInAudience        = $App.SignInAudience
            CredentialName        = $Secret.DisplayName
            KeyId                 = $Secret.KeyId
            Hint                  = $Secret.Hint
            CustomKeyIdBase64     = ""
            CustomKeyIdHex        = ""
            StartDateTime         = $Start
            EndDateTime           = $End
            DaysLeft              = $StatusInfo.DaysLeft
            CreatedDateTime       = $App.CreatedDateTime
        })
    }
}

# ------------------------------------------------------------
# Enterprise Applications / Service Principals
# ------------------------------------------------------------

Write-Host "Haetaan Enterprise Applications / Service Principals..." -ForegroundColor Cyan

$ServicePrincipals = Get-MgServicePrincipal `
    -All `
    -Property Id,AppId,DisplayName,ServicePrincipalType,KeyCredentials,PasswordCredentials,AppOwnerOrganizationId,AccountEnabled,CreatedDateTime

foreach ($Sp in $ServicePrincipals) {

    foreach ($Key in $Sp.KeyCredentials) {
        if ($null -eq $Key.EndDateTime) {
            continue
        }

        $Start = [datetime]$Key.StartDateTime
        $End   = [datetime]$Key.EndDateTime

        $StatusInfo = Get-CredentialStatus `
            -EndDate $End `
            -Now $Now `
            -WarningDays $WarningDays

        $Rows.Add([PSCustomObject]@{
            Status                = $StatusInfo.Status
            SourceType            = "EnterpriseApplication"
            CredentialType        = "Certificate"
            DisplayName           = $Sp.DisplayName
            AppId                 = $Sp.AppId
            ObjectId              = $Sp.Id
            SignInAudience        = ""
            CredentialName        = $Key.DisplayName
            KeyId                 = $Key.KeyId
            Hint                  = ""
            CustomKeyIdBase64     = Convert-CustomKeyIdentifierToBase64 -CustomKeyIdentifier $Key.CustomKeyIdentifier
            CustomKeyIdHex        = Convert-CustomKeyIdentifierToHex -CustomKeyIdentifier $Key.CustomKeyIdentifier
            StartDateTime         = $Start
            EndDateTime           = $End
            DaysLeft              = $StatusInfo.DaysLeft
            CreatedDateTime       = $Sp.CreatedDateTime
        })
    }

    foreach ($Secret in $Sp.PasswordCredentials) {
        if ($null -eq $Secret.EndDateTime) {
            continue
        }

        $Start = [datetime]$Secret.StartDateTime
        $End   = [datetime]$Secret.EndDateTime

        $StatusInfo = Get-CredentialStatus `
            -EndDate $End `
            -Now $Now `
            -WarningDays $WarningDays

        $Rows.Add([PSCustomObject]@{
            Status                = $StatusInfo.Status
            SourceType            = "EnterpriseApplication"
            CredentialType        = "ClientSecret"
            DisplayName           = $Sp.DisplayName
            AppId                 = $Sp.AppId
            ObjectId              = $Sp.Id
            SignInAudience        = ""
            CredentialName        = $Secret.DisplayName
            KeyId                 = $Secret.KeyId
            Hint                  = $Secret.Hint
            CustomKeyIdBase64     = ""
            CustomKeyIdHex        = ""
            StartDateTime         = $Start
            EndDateTime           = $End
            DaysLeft              = $StatusInfo.DaysLeft
            CreatedDateTime       = $Sp.CreatedDateTime
        })
    }
}

$AllRows = $Rows |
    Sort-Object DaysLeft, SourceType, DisplayName, CredentialType

$Expired = $AllRows | Where-Object {
    $_.Status -eq "Expired"
}

$ExpiringSoon = $AllRows | Where-Object {
    $_.Status -eq "ExpiringSoon"
}

$Ok = $AllRows | Where-Object {
    $_.Status -eq "OK"
}

$AppRegRows = $AllRows | Where-Object {
    $_.SourceType -eq "AppRegistration"
}

$EnterpriseAppRows = $AllRows | Where-Object {
    $_.SourceType -eq "EnterpriseApplication"
}

$CertificateRows = $AllRows | Where-Object {
    $_.CredentialType -eq "Certificate"
}

$SecretRows = $AllRows | Where-Object {
    $_.CredentialType -eq "ClientSecret"
}

# CSV
$AllRows |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

# ------------------------------------------------------------
# HTML style
# ------------------------------------------------------------

$HtmlStyle = @"
<style>
body {
    font-family: Segoe UI, Arial, sans-serif;
    background: #f3f4f6;
    color: #111827;
    margin: 24px;
}

h1 {
    margin-bottom: 4px;
}

h2 {
    margin-top: 28px;
}

.meta {
    color: #4b5563;
    margin-bottom: 24px;
}

.summary {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 20px;
}

.card {
    background: #ffffff;
    border: 1px solid #d1d5db;
    border-radius: 10px;
    padding: 14px 18px;
    min-width: 165px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    cursor: pointer;
    transition: transform 0.08s ease, box-shadow 0.08s ease, border-color 0.08s ease;
    user-select: none;
}

.card:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 14px rgba(0,0,0,0.12);
    border-color: #9ca3af;
}

.card.active {
    outline: 2px solid #2563eb;
    border-color: #2563eb;
}

.card-title {
    font-size: 12px;
    text-transform: uppercase;
    color: #6b7280;
    margin-bottom: 4px;
}

.card-value {
    font-size: 24px;
    font-weight: 700;
}

.ok {
    color: #15803d;
    font-weight: 700;
}

.warn {
    color: #b45309;
    font-weight: 700;
}

.crit {
    color: #b91c1c;
    font-weight: 700;
}

.toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    align-items: center;
    margin: 18px 0;
}

.search-box {
    padding: 9px 11px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    min-width: 360px;
    font-size: 14px;
}

.clear-button {
    padding: 9px 13px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    background: #ffffff;
    cursor: pointer;
    font-size: 14px;
}

.clear-button:hover {
    background: #f9fafb;
}

.result-count {
    color: #4b5563;
    font-size: 14px;
}

.table-wrap {
    width: 100%;
    overflow-x: auto;
    overflow-y: visible;
    border: 1px solid #d1d5db;
    border-radius: 10px;
    background: #ffffff;
}

table {
    border-collapse: collapse;
    width: 100%;
    min-width: 0;
    background: #ffffff;
    font-size: 13px;
    table-layout: fixed;
}

th {
    background: #111827;
    color: #ffffff;
    text-align: left;
    padding: 9px 8px;
    position: sticky;
    top: 0;
    cursor: default;
    white-space: normal;
    z-index: 2;
    line-height: 1.25;
    vertical-align: top;
}

td {
    border: 1px solid #d1d5db;
    padding: 8px;
    vertical-align: top;
    word-break: normal;
    overflow-wrap: break-word;
    white-space: normal;
    line-height: 1.35;
}

#credentialTable th:nth-child(1),
#credentialTable td:nth-child(1) {
    width: 9%;
}

#credentialTable th:nth-child(2),
#credentialTable td:nth-child(2) {
    width: 14%;
}

#credentialTable th:nth-child(3),
#credentialTable td:nth-child(3) {
    width: 12%;
}

#credentialTable th:nth-child(4),
#credentialTable td:nth-child(4) {
    width: 20%;
}

#credentialTable th:nth-child(5),
#credentialTable td:nth-child(5) {
    width: 18%;
}

#credentialTable th:nth-child(6),
#credentialTable td:nth-child(6) {
    width: 14%;
    font-family: Consolas, monospace;
    font-size: 12px;
}

#credentialTable th:nth-child(7),
#credentialTable td:nth-child(7) {
    width: 9%;
}

#credentialTable th:nth-child(8),
#credentialTable td:nth-child(8) {
    width: 6%;
    text-align: right;
}

#credentialTable th:nth-child(9),
#credentialTable td:nth-child(9) {
    width: 8%;
    text-align: center;
}

tr:nth-child(even) {
    background: #f9fafb;
}

tr.hidden {
    display: none;
}

.small {
    font-size: 12px;
    color: #6b7280;
}

.badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 999px;
    font-weight: 700;
    font-size: 12px;
}

.badge-ok {
    background: #dcfce7;
    color: #166534;
}

.badge-warn {
    background: #fef3c7;
    color: #92400e;
}

.badge-crit {
    background: #fee2e2;
    color: #991b1b;
}

.details-button {
    padding: 6px 10px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    background: #ffffff;
    color: #111827;
    cursor: pointer;
    font-size: 13px;
}

.details-button:hover {
    background: #f9fafb;
    border-color: #94a3b8;
}

.modal-overlay {
    display: none;
    position: fixed;
    z-index: 9999;
    inset: 0;
    background: rgba(15, 23, 42, 0.65);
    padding: 32px;
}

.modal-overlay.open {
    display: flex;
    align-items: center;
    justify-content: center;
}

.modal-box {
    background: #ffffff;
    border-radius: 12px;
    border: 1px solid #d1d5db;
    width: min(980px, 96vw);
    max-height: 88vh;
    overflow: auto;
    box-shadow: 0 24px 80px rgba(0,0,0,0.35);
}

.modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 16px 18px;
    border-bottom: 1px solid #e5e7eb;
    position: sticky;
    top: 0;
    background: #ffffff;
    z-index: 1;
}

.modal-header h2 {
    margin: 0;
    font-size: 18px;
}

.modal-close {
    border: none;
    background: #f3f4f6;
    color: #111827;
    font-size: 24px;
    line-height: 1;
    border-radius: 8px;
    cursor: pointer;
    padding: 4px 10px;
}

.modal-close:hover {
    background: #e5e7eb;
}

.modal-content {
    padding: 18px;
}

.details-table {
    width: 100%;
    min-width: 0;
    table-layout: fixed;
    border-collapse: collapse;
}

.details-table th {
    width: 190px;
    background: #f9fafb;
    color: #111827;
    position: static;
    cursor: default;
}

.details-table td {
    background: #ffffff;
    word-break: normal;
    overflow-wrap: break-word;
}

.mono {
    font-family: Consolas, monospace;
    font-size: 12px;
    word-break: normal;
    overflow-wrap: break-word;
}
</style>
"@

# ------------------------------------------------------------
# HTML table rows
# ------------------------------------------------------------

$TableRowsHtml = foreach ($Row in $AllRows) {

    $StatusClass = switch ($Row.Status) {
        "OK"           { "badge badge-ok" }
        "ExpiringSoon" { "badge badge-warn" }
        "Expired"      { "badge badge-crit" }
        default        { "badge" }
    }

    $ModalId = "credentialModal_" + ([guid]::NewGuid().ToString("N"))
	
	$EndDateShort = ""
try {
    $EndDateShort = ([datetime]$Row.EndDateTime).ToString("yyyy-MM-dd")
}
catch {
    $EndDateShort = [string]$Row.EndDateTime
}

@"
<tr
    data-status="$(Convert-ToHtmlEncoded $Row.Status)"
    data-sourcetype="$(Convert-ToHtmlEncoded $Row.SourceType)"
    data-credentialtype="$(Convert-ToHtmlEncoded $Row.CredentialType)"
>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.Status)">
        <span class="$StatusClass">$(Convert-ToHtmlEncoded $Row.Status)</span>
    </td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.SourceType)">$(Convert-ToHtmlEncoded $Row.SourceType)</td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.CredentialType)">$(Convert-ToHtmlEncoded $Row.CredentialType)</td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.DisplayName)">$(Convert-ToHtmlEncoded $Row.DisplayName)</td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.CredentialName)">$(Convert-ToHtmlEncoded $Row.CredentialName)</td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.AppId)">$(Convert-ToHtmlEncoded $Row.AppId)</td>
    <td title="$(Convert-ToHtmlEncoded $Row.EndDateTime)">$(Convert-ToHtmlEncoded $EndDateShort)</td>
    <td data-sort="$($Row.DaysLeft)">$(Convert-ToHtmlEncoded $Row.DaysLeft)</td>
    <td>
        <button class="details-button" type="button" onclick="openModal('$ModalId')">
            Lisätiedot
        </button>

        <div id="$ModalId" class="modal-overlay">
            <div class="modal-box">
                <div class="modal-header">
                    <h2>Credential lisätiedot</h2>
                    <button class="modal-close" type="button" onclick="closeModal('$ModalId')">&times;</button>
                </div>

                <div class="modal-content">
                    <table class="details-table">
                        <tr>
                            <th>Status</th>
                            <td>$(Convert-ToHtmlEncoded $Row.Status)</td>
                        </tr>
                        <tr>
                            <th>SourceType</th>
                            <td>$(Convert-ToHtmlEncoded $Row.SourceType)</td>
                        </tr>
                        <tr>
                            <th>CredentialType</th>
                            <td>$(Convert-ToHtmlEncoded $Row.CredentialType)</td>
                        </tr>
                        <tr>
                            <th>DisplayName</th>
                            <td>$(Convert-ToHtmlEncoded $Row.DisplayName)</td>
                        </tr>
                        <tr>
                            <th>CredentialName</th>
                            <td>$(Convert-ToHtmlEncoded $Row.CredentialName)</td>
                        </tr>
                        <tr>
                            <th>AppId</th>
                            <td class="mono">$(Convert-ToHtmlEncoded $Row.AppId)</td>
                        </tr>
                        <tr>
                            <th>ObjectId</th>
                            <td class="mono">$(Convert-ToHtmlEncoded $Row.ObjectId)</td>
                        </tr>
                        <tr>
                            <th>KeyId</th>
                            <td class="mono">$(Convert-ToHtmlEncoded $Row.KeyId)</td>
                        </tr>
                        <tr>
                            <th>Hint</th>
                            <td class="mono">$(Convert-ToHtmlEncoded $Row.Hint)</td>
                        </tr>
                        <tr>
                            <th>CustomKeyIdBase64</th>
                            <td class="mono">$(Convert-ToHtmlEncoded $Row.CustomKeyIdBase64)</td>
                        </tr>
                        <tr>
                            <th>CustomKeyIdHex</th>
                            <td class="mono">$(Convert-ToHtmlEncoded $Row.CustomKeyIdHex)</td>
                        </tr>
                        <tr>
                            <th>SignInAudience</th>
                            <td>$(Convert-ToHtmlEncoded $Row.SignInAudience)</td>
                        </tr>
                        <tr>
                            <th>StartDateTime</th>
                            <td>$(Convert-ToHtmlEncoded $Row.StartDateTime)</td>
                        </tr>
                        <tr>
                            <th>EndDateTime</th>
                            <td>$(Convert-ToHtmlEncoded $Row.EndDateTime)</td>
                        </tr>
                        <tr>
                            <th>DaysLeft</th>
                            <td>$(Convert-ToHtmlEncoded $Row.DaysLeft)</td>
                        </tr>
                        <tr>
                            <th>CreatedDateTime</th>
                            <td>$(Convert-ToHtmlEncoded $Row.CreatedDateTime)</td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
    </td>
</tr>
"@
}

# ------------------------------------------------------------
# HTML body
# ------------------------------------------------------------

$HtmlSummary = @"
<h1>M365 / Entra ID Credential Expiry Audit</h1>

<div class="meta">
    Tarkistushetki: $Now<br>
    TenantId: $($Context.TenantId)<br>
    Account: $($Context.Account)<br>
    Varoitusraja: $WarningDays päivää<br>
    Raporttikansio: $OutDir<br>
    <span class="small">Audit scope: App Registrations + Enterprise Applications / Service Principals. Read-only.</span>
</div>

<div class="summary">
    <div class="card active" data-filter-type="all" data-filter-value="all">
        <div class="card-title">Yhteensä</div>
        <div class="card-value">$($AllRows.Count)</div>
    </div>

    <div class="card" data-filter-type="status" data-filter-value="OK">
        <div class="card-title">OK</div>
        <div class="card-value ok">$($Ok.Count)</div>
    </div>

    <div class="card" data-filter-type="status" data-filter-value="ExpiringSoon">
        <div class="card-title">Vanhenemassa</div>
        <div class="card-value warn">$($ExpiringSoon.Count)</div>
    </div>

    <div class="card" data-filter-type="status" data-filter-value="Expired">
        <div class="card-title">Vanhentuneet</div>
        <div class="card-value crit">$($Expired.Count)</div>
    </div>

    <div class="card" data-filter-type="sourcetype" data-filter-value="AppRegistration">
        <div class="card-title">App Registrations</div>
        <div class="card-value">$($AppRegRows.Count)</div>
    </div>

    <div class="card" data-filter-type="sourcetype" data-filter-value="EnterpriseApplication">
        <div class="card-title">Enterprise Apps</div>
        <div class="card-value">$($EnterpriseAppRows.Count)</div>
    </div>

    <div class="card" data-filter-type="credentialtype" data-filter-value="Certificate">
        <div class="card-title">Certificates</div>
        <div class="card-value">$($CertificateRows.Count)</div>
    </div>

    <div class="card" data-filter-type="credentialtype" data-filter-value="ClientSecret">
        <div class="card-title">Client Secrets</div>
        <div class="card-value">$($SecretRows.Count)</div>
    </div>
</div>

<div class="toolbar">
    <input id="searchBox" class="search-box" type="text" placeholder="Hae riveistä: app, credential, AppId, KeyId, Hint..." />
    <button id="clearFilters" class="clear-button" type="button">Näytä kaikki</button>
    <div id="resultCount" class="result-count"></div>
</div>

<div class="table-wrap">
<table id="credentialTable">
    <thead>
        <tr>
            <th data-type="text">Status</th>
            <th data-type="text">SourceType</th>
            <th data-type="text">CredentialType</th>
            <th data-type="text">DisplayName</th>
            <th data-type="text">CredentialName</th>
            <th data-type="text">AppId</th>
            <th data-type="date">EndDateTime</th>
            <th data-type="number">DaysLeft</th>
            <th data-type="text">Lisätiedot</th>
        </tr>
    </thead>
    <tbody>
        $($TableRowsHtml -join "`n")
    </tbody>
</table>
</div>
"@

# ------------------------------------------------------------
# HTML script
# ------------------------------------------------------------

$HtmlScript = @"
<script>
(function () {
    window.openModal = function(id) {
        const modal = document.getElementById(id);
        if (modal) {
            modal.classList.add("open");
        }
    };

    window.closeModal = function(id) {
        const modal = document.getElementById(id);
        if (modal) {
            modal.classList.remove("open");
        }
    };

    document.addEventListener("keydown", function(event) {
        if (event.key === "Escape") {
            document.querySelectorAll(".modal-overlay.open").forEach(function(modal) {
                modal.classList.remove("open");
            });
        }
    });

    document.addEventListener("click", function(event) {
        if (event.target.classList && event.target.classList.contains("modal-overlay")) {
            event.target.classList.remove("open");
        }
    });

    let activeFilterType = "all";
    let activeFilterValue = "all";
    let searchText = "";

    const cards = document.querySelectorAll(".card");
    const table = document.getElementById("credentialTable");
    const tbody = table.querySelector("tbody");
    const rows = Array.from(tbody.querySelectorAll("tr"));
    const searchBox = document.getElementById("searchBox");
    const clearButton = document.getElementById("clearFilters");
    const resultCount = document.getElementById("resultCount");

    function normalize(value) {
        return (value || "").toString().toLowerCase();
    }

    function rowMatchesFilter(row) {
        if (activeFilterType === "all") {
            return true;
        }

        return row.dataset[activeFilterType] === activeFilterValue;
    }

    function rowMatchesSearch(row) {
        if (!searchText) {
            return true;
        }

        return normalize(row.textContent).includes(searchText);
    }

    function applyFilters() {
        let visible = 0;

        rows.forEach(function (row) {
            const show = rowMatchesFilter(row) && rowMatchesSearch(row);

            if (show) {
                row.classList.remove("hidden");
                visible++;
            } else {
                row.classList.add("hidden");
            }
        });

        resultCount.textContent = "Näkyvissä " + visible + " / " + rows.length + " riviä";
    }

    function setActiveCard(selectedCard) {
        cards.forEach(function (card) {
            card.classList.remove("active");
        });

        selectedCard.classList.add("active");
    }

    cards.forEach(function (card) {
        card.addEventListener("click", function () {
            activeFilterType = card.dataset.filterType;
            activeFilterValue = card.dataset.filterValue;

            setActiveCard(card);
            applyFilters();
        });
    });

    searchBox.addEventListener("input", function () {
        searchText = normalize(searchBox.value);
        applyFilters();
    });

    clearButton.addEventListener("click", function () {
        activeFilterType = "all";
        activeFilterValue = "all";
        searchText = "";
        searchBox.value = "";

        const allCard = document.querySelector('.card[data-filter-type="all"]');
        if (allCard) {
            setActiveCard(allCard);
        }

        applyFilters();
    });

    applyFilters();
})();
</script>
"@

$HtmlHead = @"
<meta charset="utf-8">
$HtmlStyle
"@

$Html = ConvertTo-Html `
    -Title "M365 Entra ID Credential Expiry Audit" `
    -Head $HtmlHead `
    -Body ($HtmlSummary + $HtmlScript)

$Html | Out-File -FilePath $HtmlPath -Encoding UTF8

# Console output
Write-Host ""
Write-Host "Raportit luotu:" -ForegroundColor Cyan
Write-Host "  CSV : $CsvPath"
Write-Host "  HTML: $HtmlPath"
Write-Host ""

Write-Host "Yhteenveto:" -ForegroundColor Cyan
Write-Host "  Yhteensä       : $($AllRows.Count)"
Write-Host "  OK             : $($Ok.Count)" -ForegroundColor Green
Write-Host "  Vanhenemassa   : $($ExpiringSoon.Count)" -ForegroundColor Yellow
Write-Host "  Vanhentuneet   : $($Expired.Count)" -ForegroundColor Red
Write-Host ""
Write-Host "  App Registrations : $($AppRegRows.Count)"
Write-Host "  Enterprise Apps   : $($EnterpriseAppRows.Count)"
Write-Host "  Certificates      : $($CertificateRows.Count)"
Write-Host "  Client Secrets    : $($SecretRows.Count)"
Write-Host ""

if ($Expired.Count -gt 0) {
    Write-Host "CRITICAL: Vanhentuneita credentialeja löytyi: $($Expired.Count)" -ForegroundColor Red

    $Expired |
        Select-Object Status, SourceType, CredentialType, DisplayName, CredentialName, EndDateTime, DaysLeft |
        Format-Table -AutoSize

    exit 2
}

if ($ExpiringSoon.Count -gt 0) {
    Write-Host "WARNING: $WarningDays päivän sisällä vanhenevia credentialeja löytyi: $($ExpiringSoon.Count)" -ForegroundColor Yellow

    $ExpiringSoon |
        Select-Object Status, SourceType, CredentialType, DisplayName, CredentialName, EndDateTime, DaysLeft |
        Format-Table -AutoSize

    exit 1
}

Write-Host "OK: Ei vanhentuneita tai pian vanhenevia App Registration / Enterprise Application credentialeja." -ForegroundColor Green
exit 0
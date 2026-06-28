#requires -version 5.1
<#
.SYNOPSIS
    Audits selected Intune Apple/certificate items and Exchange Online connector TLS settings.

.DESCRIPTION
    Read-only audit for Intune and Exchange Online.
    
    Checks Apple MDM Push Certificate, Apple ADE/DEP tokens, Apple VPP tokens, certificate-related Intune device configuration profiles, and Exchange Online inbound/outbound connector TLS-related settings. Detail, Recommendation and RawId values are shown in an HTML details modal to keep the report readable.

.OUTPUTS
    CSV and HTML reports are written to the selected output directory.

.REQUIREMENTS
      - Microsoft.Graph PowerShell module
      - ExchangeOnlineManagement PowerShell module
      - Graph scopes: DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All
      - Exchange Online read permissions / suitable admin role

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

    [int]$CriticalDays = 7,

    [string]$OutDir = "$env:TEMP\NOC-Audit\Intune-Exchange",

    [switch]$SkipGraphConnect,

    [switch]$SkipExchangeConnect,

    [switch]$SkipIntune,

    [switch]$SkipExchange
)

$ErrorActionPreference = "Stop"

$Now = Get-Date
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

$CsvPath  = Join-Path $OutDir "intune-exchange-readonly-audit-$Timestamp.csv"
$HtmlPath = Join-Path $OutDir "intune-exchange-readonly-audit-$Timestamp.html"

$Rows = New-Object System.Collections.Generic.List[object]

function Get-AuditStatus {
    param(
        [AllowNull()]
        [object]$EndDate,

        [int]$WarningDays,

        [int]$CriticalDays
    )

    if ($null -eq $EndDate -or [string]::IsNullOrWhiteSpace([string]$EndDate)) {
        return [PSCustomObject]@{
            Status   = "Info"
            DaysLeft = $null
        }
    }

    try {
        $ParsedEndDate = [datetime]$EndDate
    }
    catch {
        return [PSCustomObject]@{
            Status   = "Info"
            DaysLeft = $null
        }
    }

    if ($ParsedEndDate -eq [datetime]::MinValue) {
        return [PSCustomObject]@{
            Status   = "Info"
            DaysLeft = $null
        }
    }

    $DaysLeft = [math]::Floor(($ParsedEndDate - (Get-Date)).TotalDays)

    $Status = if ($DaysLeft -lt 0) {
        "Expired"
    }
    elseif ($DaysLeft -le $CriticalDays) {
        "Critical"
    }
    elseif ($DaysLeft -le $WarningDays) {
        "Warning"
    }
    else {
        "OK"
    }

    [PSCustomObject]@{
        Status   = $Status
        DaysLeft = $DaysLeft
    }
}

function Add-AuditRow {
    param(
        [string]$Area,
        [string]$Category,
        [string]$Name,
        [string]$ItemType,
        [string]$Status,
        [AllowNull()]$EndDate,
        [AllowNull()]$DaysLeft,
        [string]$Detail,
        [string]$Recommendation,
        [string]$RawId
    )

    $script:Rows.Add([PSCustomObject]@{
        Area           = $Area
        Category       = $Category
        Name           = $Name
        ItemType       = $ItemType
        Status         = $Status
        EndDate        = $EndDate
        DaysLeft       = $DaysLeft
        Detail         = $Detail
        Recommendation = $Recommendation
        RawId          = $RawId
    })
}

function Invoke-GraphGetSafe {
    param(
        [string]$Uri,
        [string]$Description
    )

    try {
        return Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
    }
    catch {
        Add-AuditRow `
            -Area "Intune" `
            -Category "Graph query" `
            -Name $Description `
            -ItemType "GraphEndpoint" `
            -Status "Info" `
            -EndDate $null `
            -DaysLeft $null `
            -Detail "Graph endpointin haku epäonnistui tai ominaisuus ei ole käytössä tässä tenantissa. URI: $Uri. Virhe: $($_.Exception.Message)" `
            -Recommendation "Tarkista oikeudet ja onko kyseinen Intune/Apple-toiminto käytössä tenantissa." `
            -RawId $Uri

        return $null
    }
}

function Convert-GraphDate {
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    try {
        return [datetime]$Value
    }
    catch {
        return $null
    }
}

function Try-ParseCertificateFromBase64 {
    param(
        [AllowNull()]
        [string]$Base64
    )

    if ([string]::IsNullOrWhiteSpace($Base64)) {
        return $null
    }

    try {
        $bytes = [System.Convert]::FromBase64String($Base64)
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
    }
    catch {
        return $null
    }
}

Write-Host ""
Write-Host "=== Intune + Exchange Online Read-only Audit ===" -ForegroundColor Cyan
Write-Host "Tarkistushetki : $Now"
Write-Host "WarningDays    : $WarningDays"
Write-Host "CriticalDays   : $CriticalDays"
Write-Host "Raporttikansio : $OutDir"
Write-Host ""

# ------------------------------------------------------------
# Intune / Microsoft Graph
# ------------------------------------------------------------

if (-not $SkipIntune) {

    $GraphModules = @(
        "Microsoft.Graph.Authentication"
    )

    foreach ($ModuleName in $GraphModules) {
        if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
            Write-Host "Puuttuva moduuli: $ModuleName" -ForegroundColor Yellow
            Write-Host "Asenna:" -ForegroundColor Yellow
            Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Cyan
            exit 2
        }
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    if (-not $SkipGraphConnect) {
        Write-Host "Yhdistetään Microsoft Graphiin Intune read-only scopeilla..." -ForegroundColor Cyan

        Connect-MgGraph `
            -Scopes "DeviceManagementConfiguration.Read.All","DeviceManagementServiceConfig.Read.All" `
            -NoWelcome
    }

    $MgContext = Get-MgContext

    if (-not $MgContext) {
        Write-Host "Microsoft Graph -yhteyttä ei ole." -ForegroundColor Red
        exit 2
    }

    Write-Host "Graph tenant: $($MgContext.TenantId)" -ForegroundColor DarkGray
    Write-Host "Graph account: $($MgContext.Account)" -ForegroundColor DarkGray
    Write-Host ""

    # Apple MDM Push Certificate
    Write-Host "Haetaan Intune Apple MDM Push Certificate..." -ForegroundColor Cyan

    $ApplePush = Invoke-GraphGetSafe `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/applePushNotificationCertificate" `
        -Description "Apple MDM Push Certificate"

    if ($ApplePush) {
        $Expiration = Convert-GraphDate $ApplePush.expirationDateTime
        $StatusInfo = Get-AuditStatus -EndDate $Expiration -WarningDays $WarningDays -CriticalDays $CriticalDays

        Add-AuditRow `
            -Area "Intune" `
            -Category "Apple" `
            -Name "Apple MDM Push Certificate" `
            -ItemType "ApplePushNotificationCertificate" `
            -Status $StatusInfo.Status `
            -EndDate $Expiration `
            -DaysLeft $StatusInfo.DaysLeft `
            -Detail "AppleIdentifier: $($ApplePush.appleIdentifier); TopicIdentifier: $($ApplePush.topicIdentifier); LastModified: $($ApplePush.lastModifiedDateTime)" `
            -Recommendation "Uusi Apple MDM Push Certificate ajoissa samalla Apple ID:llä. Älä luo uutta, jos tarkoitus on uusia nykyinen." `
            -RawId "applePushNotificationCertificate"
    }

    # DEP / ADE enrollment tokens
    Write-Host "Haetaan Intune Apple ADE/DEP tokens..." -ForegroundColor Cyan

    $DepTokens = Invoke-GraphGetSafe `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings" `
        -Description "Apple ADE / DEP enrollment tokens"

    if ($DepTokens -and $DepTokens.value) {
        foreach ($Token in $DepTokens.value) {
            $Expiration = Convert-GraphDate $Token.tokenExpirationDateTime
            $StatusInfo = Get-AuditStatus -EndDate $Expiration -WarningDays $WarningDays -CriticalDays $CriticalDays

            Add-AuditRow `
                -Area "Intune" `
                -Category "Apple" `
                -Name $Token.displayName `
                -ItemType "ADE_DEP_Token" `
                -Status $StatusInfo.Status `
                -EndDate $Expiration `
                -DaysLeft $StatusInfo.DaysLeft `
                -Detail "TokenType: $($Token.tokenType); AppleIdentifier: $($Token.appleIdentifier); LastSync: $($Token.lastSyncDateTime); LastModified: $($Token.lastModifiedDateTime)" `
                -Recommendation "Uusi ADE/DEP token vuosittain Apple Business Managerista / Apple School Managerista ja tallenna Intuneen." `
                -RawId $Token.id
        }
    }

    # VPP tokens
    Write-Host "Haetaan Intune Apple VPP tokens..." -ForegroundColor Cyan

    $VppTokens = Invoke-GraphGetSafe `
        -Uri "https://graph.microsoft.com/beta/deviceAppManagement/vppTokens" `
        -Description "Apple VPP tokens"

    if ($VppTokens -and $VppTokens.value) {
        foreach ($Token in $VppTokens.value) {
            $Expiration = Convert-GraphDate $Token.expirationDateTime
            $StatusInfo = Get-AuditStatus -EndDate $Expiration -WarningDays $WarningDays -CriticalDays $CriticalDays

            Add-AuditRow `
                -Area "Intune" `
                -Category "Apple" `
                -Name $Token.displayName `
                -ItemType "VPP_Token" `
                -Status $StatusInfo.Status `
                -EndDate $Expiration `
                -DaysLeft $StatusInfo.DaysLeft `
                -Detail "AppleId: $($Token.appleId); OrganizationName: $($Token.organizationName); State: $($Token.state); LastSync: $($Token.lastSyncDateTime)" `
                -Recommendation "Uusi VPP token ajoissa, jos Apple-sovellusten hallinta on käytössä." `
                -RawId $Token.id
        }
    }

    # Intune certificate related configuration profiles
    Write-Host "Haetaan Intune certificate related configuration profiles..." -ForegroundColor Cyan

    $DeviceConfigurations = Invoke-GraphGetSafe `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" `
        -Description "Intune device configuration profiles"

    if ($DeviceConfigurations -and $DeviceConfigurations.value) {

        $CertProfiles = $DeviceConfigurations.value | Where-Object {
            $_.'@odata.type' -match "certificate|scep|pkcs|trusted"
        }

        foreach ($Profile in $CertProfiles) {

            $ODataType = [string]$Profile.'@odata.type'
            $ProfileName = if ($Profile.displayName) { $Profile.displayName } else { $Profile.id }

            $Cert = $null
            $CertEndDate = $null
            $CertDetail = ""

            if ($Profile.trustedRootCertificate) {
                $Cert = Try-ParseCertificateFromBase64 -Base64 $Profile.trustedRootCertificate

                if ($Cert) {
                    $CertEndDate = $Cert.NotAfter
                    $CertDetail = "Certificate Subject: $($Cert.Subject); Issuer: $($Cert.Issuer); Thumbprint: $($Cert.Thumbprint)"
                }
            }

            $StatusInfo = Get-AuditStatus -EndDate $CertEndDate -WarningDays $WarningDays -CriticalDays $CriticalDays

            $Status = if ($CertEndDate) {
                $StatusInfo.Status
            }
            else {
                "Info"
            }

            $Detail = "ProfileType: $ODataType; Platform/profile id: $($Profile.id); Created: $($Profile.createdDateTime); LastModified: $($Profile.lastModifiedDateTime)"

            if ($CertDetail) {
                $Detail = "$Detail; $CertDetail"
            }

            Add-AuditRow `
                -Area "Intune" `
                -Category "CertificateProfile" `
                -Name $ProfileName `
                -ItemType $ODataType `
                -Status $Status `
                -EndDate $CertEndDate `
                -DaysLeft $StatusInfo.DaysLeft `
                -Detail $Detail `
                -Recommendation "Jos profiili liittyy SCEP/PKCS/Trusted cert -jakeluun, tarkista myös NDES/Intune Certificate Connector/CA-palvelimien LocalMachine-sertifikaatit." `
                -RawId $Profile.id
        }
    }
}

# ------------------------------------------------------------
# Exchange Online
# ------------------------------------------------------------

if (-not $SkipExchange) {

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Host "Puuttuva moduuli: ExchangeOnlineManagement" -ForegroundColor Yellow
        Write-Host "Asenna:" -ForegroundColor Yellow
        Write-Host "Install-Module ExchangeOnlineManagement -Scope CurrentUser" -ForegroundColor Cyan
        exit 2
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    if (-not $SkipExchangeConnect) {
        Write-Host "Yhdistetään Exchange Onlineen read-only auditia varten..." -ForegroundColor Cyan
        Connect-ExchangeOnline -ShowBanner:$false
    }

    Write-Host "Haetaan Exchange Online inbound connectors..." -ForegroundColor Cyan

    try {
        $InboundConnectors = Get-InboundConnector -ErrorAction Stop

        foreach ($Connector in $InboundConnectors) {

            $Status = "Info"
            $Recommendation = "Tarkista, että TLS/certificate-vaatimukset vastaavat lähettävän järjestelmän todellista sertifikaattia."

            if ($Connector.Enabled -eq $true -and $Connector.RequireTls -eq $true -and [string]::IsNullOrWhiteSpace([string]$Connector.TlsSenderCertificateName)) {
                $Status = "Warning"
                $Recommendation = "Connector vaatii TLS:n, mutta TlsSenderCertificateName on tyhjä. Tarkista onko tämä tarkoituksellista."
            }

            Add-AuditRow `
                -Area "Exchange Online" `
                -Category "Connector" `
                -Name $Connector.Name `
                -ItemType "InboundConnector" `
                -Status $Status `
                -EndDate $null `
                -DaysLeft $null `
                -Detail "Enabled: $($Connector.Enabled); ConnectorType: $($Connector.ConnectorType); RequireTls: $($Connector.RequireTls); TlsSenderCertificateName: $($Connector.TlsSenderCertificateName); SenderDomains: $($Connector.SenderDomains -join ', '); SenderIPAddresses: $($Connector.SenderIPAddresses -join ', '); CloudServicesMailEnabled: $($Connector.CloudServicesMailEnabled)" `
                -Recommendation $Recommendation `
                -RawId $Connector.Identity
        }
    }
    catch {
        Add-AuditRow `
            -Area "Exchange Online" `
            -Category "Connector" `
            -Name "Inbound connectors" `
            -ItemType "QueryError" `
            -Status "Warning" `
            -EndDate $null `
            -DaysLeft $null `
            -Detail "Get-InboundConnector epäonnistui: $($_.Exception.Message)" `
            -Recommendation "Tarkista Exchange Online -yhteys ja roolioikeudet." `
            -RawId ""
    }

    Write-Host "Haetaan Exchange Online outbound connectors..." -ForegroundColor Cyan

    try {
        $OutboundConnectors = Get-OutboundConnector -ErrorAction Stop

        foreach ($Connector in $OutboundConnectors) {

            $Status = "Info"
            $Recommendation = "Tarkista, että TlsDomain vastaa vastaanottavan smarthostin / gatewayn sertifikaattia."

            if ($Connector.Enabled -eq $true -and $Connector.TlsSettings -match "Certificate" -and [string]::IsNullOrWhiteSpace([string]$Connector.TlsDomain)) {
                $Status = "Warning"
                $Recommendation = "Connector käyttää certificate/TLS-domain-tyyppistä tarkistusta, mutta TlsDomain näyttää tyhjältä. Tarkista asetukset."
            }

            Add-AuditRow `
                -Area "Exchange Online" `
                -Category "Connector" `
                -Name $Connector.Name `
                -ItemType "OutboundConnector" `
                -Status $Status `
                -EndDate $null `
                -DaysLeft $null `
                -Detail "Enabled: $($Connector.Enabled); ConnectorType: $($Connector.ConnectorType); TlsSettings: $($Connector.TlsSettings); TlsDomain: $($Connector.TlsDomain); RecipientDomains: $($Connector.RecipientDomains -join ', '); SmartHosts: $($Connector.SmartHosts -join ', '); RouteAllMessagesViaOnPremises: $($Connector.RouteAllMessagesViaOnPremises); CloudServicesMailEnabled: $($Connector.CloudServicesMailEnabled)" `
                -Recommendation $Recommendation `
                -RawId $Connector.Identity
        }
    }
    catch {
        Add-AuditRow `
            -Area "Exchange Online" `
            -Category "Connector" `
            -Name "Outbound connectors" `
            -ItemType "QueryError" `
            -Status "Warning" `
            -EndDate $null `
            -DaysLeft $null `
            -Detail "Get-OutboundConnector epäonnistui: $($_.Exception.Message)" `
            -Recommendation "Tarkista Exchange Online -yhteys ja roolioikeudet." `
            -RawId ""
    }
}

# ------------------------------------------------------------
# Report generation
# ------------------------------------------------------------

$AllRows = $Rows | Sort-Object Area, Category, Status, DaysLeft, Name

$ExpiredRows  = $AllRows | Where-Object { $_.Status -eq "Expired" }
$CriticalRows = $AllRows | Where-Object { $_.Status -eq "Critical" }
$WarningRows  = $AllRows | Where-Object { $_.Status -eq "Warning" }
$OkRows       = $AllRows | Where-Object { $_.Status -eq "OK" }
$InfoRows     = $AllRows | Where-Object { $_.Status -eq "Info" }

$IntuneRows   = $AllRows | Where-Object { $_.Area -eq "Intune" }
$ExchangeRows = $AllRows | Where-Object { $_.Area -eq "Exchange Online" }

$AllRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

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
    cursor: default;
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

.ok { color: #15803d; font-weight: 700; }
.info { color: #2563eb; font-weight: 700; }
.warn { color: #b45309; font-weight: 700; }
.crit { color: #b91c1c; font-weight: 700; }

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
    min-width: 340px;
    font-size: 14px;
}

.clear-button {
    padding: 9px 13px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    background: #ffffff;
    cursor: default;
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

tr:nth-child(even) {
    background: #f9fafb;
}

tr.hidden {
    display: none;
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

.badge-info {
    background: #dbeafe;
    color: #1d4ed8;
}

.badge-warn {
    background: #fef3c7;
    color: #92400e;
}

.badge-crit {
    background: #fee2e2;
    color: #991b1b;
}

#auditTable th:nth-child(1),
#auditTable td:nth-child(1) {
    width: 13%;
}

#auditTable th:nth-child(2),
#auditTable td:nth-child(2) {
    width: 15%;
}

#auditTable th:nth-child(3),
#auditTable td:nth-child(3) {
    width: 18%;
}

#auditTable th:nth-child(4),
#auditTable td:nth-child(4) {
    width: 28%;
}

#auditTable th:nth-child(5),
#auditTable td:nth-child(5) {
    width: 10%;
}

#auditTable th:nth-child(6),
#auditTable td:nth-child(6) {
    width: 10%;
}

#auditTable th:nth-child(7),
#auditTable td:nth-child(7) {
    width: 6%;
    text-align: right;
}

#auditTable th:nth-child(8),
#auditTable td:nth-child(8) {
    width: 10%;
    text-align: center;
}
.details-button {
    padding: 6px 10px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    background: #ffffff;
    color: #111827;
    cursor: default;
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
    width: min(1040px, 96vw);
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
    cursor: default;
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

.detail-text {
    white-space: normal;
    line-height: 1.45;
}
</style>
"@

$TableRowsHtml = foreach ($Row in $AllRows) {

    $BadgeClass = switch ($Row.Status) {
        "OK"       { "badge badge-ok" }
        "Info"     { "badge badge-info" }
        "Warning"  { "badge badge-warn" }
        "Critical" { "badge badge-crit" }
        "Expired"  { "badge badge-crit" }
        default    { "badge badge-info" }
    }

    $ModalId = "auditModal_" + ([guid]::NewGuid().ToString("N"))

    $EndDateShort = ""
    if ($null -ne $Row.EndDate -and -not [string]::IsNullOrWhiteSpace([string]$Row.EndDate)) {
        try {
            $EndDateShort = ([datetime]$Row.EndDate).ToString("yyyy-MM-dd")
        }
        catch {
            $EndDateShort = [string]$Row.EndDate
        }
    }

    $DetailModalHtml = Convert-ToHtmlEncoded $Row.Detail
    $DetailModalHtml = $DetailModalHtml -replace '; ', '<br>'

@"
<tr
    data-area="$(Convert-ToHtmlEncoded $Row.Area)"
    data-status="$(Convert-ToHtmlEncoded $Row.Status)"
    data-category="$(Convert-ToHtmlEncoded $Row.Category)"
>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.Area)">$(Convert-ToHtmlEncoded $Row.Area)</td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.Category)">$(Convert-ToHtmlEncoded $Row.Category)</td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.ItemType)">$(Convert-ToHtmlEncoded $Row.ItemType)</td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.Name)">$(Convert-ToHtmlEncoded $Row.Name)</td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.Status)">
        <span class="$BadgeClass">$(Convert-ToHtmlEncoded $Row.Status)</span>
    </td>
    <td data-sort="$(Convert-ToHtmlEncoded $Row.EndDate)" title="$(Convert-ToHtmlEncoded $Row.EndDate)">$(Convert-ToHtmlEncoded $EndDateShort)</td>
    <td data-sort="$($Row.DaysLeft)">$(Convert-ToHtmlEncoded $Row.DaysLeft)</td>
    <td>
        <button class="details-button" type="button" onclick="openModal('$ModalId')">
            Lisätiedot
        </button>

        <div id="$ModalId" class="modal-overlay">
            <div class="modal-box">
                <div class="modal-header">
                    <h2>Audit-rivin lisätiedot</h2>
                    <button class="modal-close" type="button" onclick="closeModal('$ModalId')">&times;</button>
                </div>

                <div class="modal-content">
                    <table class="details-table">
                        <tr>
                            <th>Area</th>
                            <td>$(Convert-ToHtmlEncoded $Row.Area)</td>
                        </tr>
                        <tr>
                            <th>Category</th>
                            <td>$(Convert-ToHtmlEncoded $Row.Category)</td>
                        </tr>
                        <tr>
                            <th>ItemType</th>
                            <td>$(Convert-ToHtmlEncoded $Row.ItemType)</td>
                        </tr>
                        <tr>
                            <th>Name</th>
                            <td>$(Convert-ToHtmlEncoded $Row.Name)</td>
                        </tr>
                        <tr>
                            <th>Status</th>
                            <td>$(Convert-ToHtmlEncoded $Row.Status)</td>
                        </tr>
                        <tr>
                            <th>EndDate</th>
                            <td>$(Convert-ToHtmlEncoded $Row.EndDate)</td>
                        </tr>
                        <tr>
                            <th>DaysLeft</th>
                            <td>$(Convert-ToHtmlEncoded $Row.DaysLeft)</td>
                        </tr>
                        <tr>
                            <th>Detail</th>
                            <td class="detail-text">$DetailModalHtml</td>
                        </tr>
                        <tr>
                            <th>Recommendation</th>
                            <td class="detail-text">$(Convert-ToHtmlEncoded $Row.Recommendation)</td>
                        </tr>
                        <tr>
                            <th>RawId</th>
                            <td class="mono">$(Convert-ToHtmlEncoded $Row.RawId)</td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
    </td>
</tr>
"@
}

$HtmlSummary = @"
<h1>Intune + Exchange Online Read-only Audit</h1>

<div class="meta">
    Tarkistushetki: $Now<br>
    Varoitusraja: $WarningDays päivää<br>
    Kriittinen raja: $CriticalDays päivää<br>
    Raporttikansio: $OutDir<br>
    Scope: Intune Apple/certificate related items + Exchange Online connector TLS settings. Read-only.
</div>

<div class="summary">
    <div class="card active" data-filter-type="all" data-filter-value="all">
        <div class="card-title">Yhteensä</div>
        <div class="card-value">$($AllRows.Count)</div>
    </div>

    <div class="card" data-filter-type="area" data-filter-value="Intune">
        <div class="card-title">Intune</div>
        <div class="card-value">$($IntuneRows.Count)</div>
    </div>

    <div class="card" data-filter-type="area" data-filter-value="Exchange Online">
        <div class="card-title">Exchange Online</div>
        <div class="card-value">$($ExchangeRows.Count)</div>
    </div>

    <div class="card" data-filter-type="status" data-filter-value="OK">
        <div class="card-title">OK</div>
        <div class="card-value ok">$($OkRows.Count)</div>
    </div>

    <div class="card" data-filter-type="status" data-filter-value="Info">
        <div class="card-title">Info</div>
        <div class="card-value info">$($InfoRows.Count)</div>
    </div>

    <div class="card" data-filter-type="status" data-filter-value="Warning">
        <div class="card-title">Warning</div>
        <div class="card-value warn">$($WarningRows.Count)</div>
    </div>

    <div class="card" data-filter-type="status" data-filter-value="Critical">
        <div class="card-title">Critical</div>
        <div class="card-value crit">$($CriticalRows.Count)</div>
    </div>

    <div class="card" data-filter-type="status" data-filter-value="Expired">
        <div class="card-title">Expired</div>
        <div class="card-value crit">$($ExpiredRows.Count)</div>
    </div>
</div>

<div class="toolbar">
    <input id="searchBox" class="search-box" type="text" placeholder="Hae riveistä: Intune, Exchange, connector, token, TLS, RawId, Recommendation..." />
    <button id="clearFilters" class="clear-button" type="button">Näytä kaikki</button>
    <div id="resultCount" class="result-count"></div>
</div>

<div class="table-wrap">
<table id="auditTable">
    <thead>
<tr>
    <th data-type="text">Area</th>
    <th data-type="text">Category</th>
    <th data-type="text">ItemType</th>
    <th data-type="text">Name</th>
    <th data-type="text">Status</th>
    <th data-type="date">EndDate</th>
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
            return;
        }
    });

    let activeFilterType = "all";
    let activeFilterValue = "all";
    let searchText = "";

    const cards = document.querySelectorAll(".card");
    const table = document.getElementById("auditTable");
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

        rows.forEach(function(row) {
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
        cards.forEach(function(card) {
            card.classList.remove("active");
        });

        selectedCard.classList.add("active");
    }

    cards.forEach(function(card) {
        card.addEventListener("click", function() {
            activeFilterType = card.dataset.filterType;
            activeFilterValue = card.dataset.filterValue;

            setActiveCard(card);
            applyFilters();
        });
    });

    searchBox.addEventListener("input", function() {
        searchText = normalize(searchBox.value);
        applyFilters();
    });

    clearButton.addEventListener("click", function() {
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
    -Title "Intune Exchange Read-only Audit" `
    -Head $HtmlHead `
    -Body ($HtmlSummary + $HtmlScript)

$Html | Out-File -FilePath $HtmlPath -Encoding UTF8

Write-Host ""
Write-Host "Raportit luotu:" -ForegroundColor Cyan
Write-Host "  CSV : $CsvPath"
Write-Host "  HTML: $HtmlPath"
Write-Host ""

Write-Host "Yhteenveto:" -ForegroundColor Cyan
Write-Host "  Yhteensä        : $($AllRows.Count)"
Write-Host "  Intune          : $($IntuneRows.Count)"
Write-Host "  Exchange Online : $($ExchangeRows.Count)"
Write-Host "  OK              : $($OkRows.Count)" -ForegroundColor Green
Write-Host "  Info            : $($InfoRows.Count)" -ForegroundColor Cyan
Write-Host "  Warning         : $($WarningRows.Count)" -ForegroundColor Yellow
Write-Host "  Critical        : $($CriticalRows.Count)" -ForegroundColor Red
Write-Host "  Expired         : $($ExpiredRows.Count)" -ForegroundColor Red
Write-Host ""

if ($ExpiredRows.Count -gt 0 -or $CriticalRows.Count -gt 0) {
    Write-Host "CRITICAL: Vanhentuneita tai kriittisen lähellä olevia kohteita löytyi." -ForegroundColor Red

    $AllRows |
        Where-Object { $_.Status -in @("Expired", "Critical") } |
        Select-Object Area, Category, Name, ItemType, Status, EndDate, DaysLeft |
        Format-Table -AutoSize

    exit 2
}

if ($WarningRows.Count -gt 0) {
    Write-Host "WARNING: Varoitettavia kohteita löytyi." -ForegroundColor Yellow

    $WarningRows |
        Select-Object Area, Category, Name, ItemType, Status, EndDate, DaysLeft |
        Format-Table -AutoSize

    exit 1
}

Write-Host "OK: Ei kriittisiä tai varoitettavia Intune / Exchange Online -kohteita." -ForegroundColor Green
exit 0
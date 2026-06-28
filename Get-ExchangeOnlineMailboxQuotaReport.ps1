<#
.SYNOPSIS
    Exchange Online Mailbox Quota and Capacity Report.

.DESCRIPTION
    Raportoi Exchange Online -postilaatikoiden koot, quotat, käyttöasteen, arkistotiedot ja kapasiteettiriskit.

.REQUIREMENTS
    - ExchangeOnlineManagement-moduuli ja postilaatikoiden tilastojen lukuoikeudet

.OUTPUTS
    - CSV/HTML-raportti postilaatikoiden kapasiteetista

.EXAMPLE
    .\Get-ExchangeOnlineMailboxQuotaReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Get-ExchangeOnlineMailboxQuotaReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

<#
.SYNOPSIS
    M365 / Exchange Online mailbox quota and capacity report v1.2.

.DESCRIPTION
    Fully read-only Exchange Online / Microsoft 365 mailbox quota audit.

    Collects:
    - Mailbox size
    - Mailbox quota limits
    - Remaining quota
    - Used percentage
    - Item count
    - Deleted item count
    - Last logon time
    - Archive mailbox size, optional
    - Microsoft 365 license details via Graph, optional
    - Folder breakdown for problem mailboxes, optional
    - RiskScore 0-100
    - Recommendation
    - Trend from previous run using local history.csv

    Outputs:
    - CSV
    - HTML dashboard
    - JSON summary
    - history.csv
    - folder-breakdown CSV, optional

    This script does NOT modify anything in Microsoft 365.

.REQUIREMENTS
    PowerShell 5.1 or PowerShell 7+
    ExchangeOnlineManagement module
    Microsoft.Graph.Users module, optional for license details
    Microsoft.Graph.Authentication module, optional for license details

.EXAMPLES
    .\Get-ExchangeOnlineMailboxQuotaReport.ps1

    .\Get-ExchangeOnlineMailboxQuotaReport.ps1 -IncludeSharedMailboxes

    .\Get-ExchangeOnlineMailboxQuotaReport.ps1 -IncludeSharedMailboxes -IncludeArchiveStats

    .\Get-ExchangeOnlineMailboxQuotaReport.ps1 -IncludeSharedMailboxes -IncludeArchiveStats -IncludeLicenseDetails

    .\Get-ExchangeOnlineMailboxQuotaReport.ps1 -IncludeSharedMailboxes -IncludeArchiveStats -IncludeLicenseDetails -IncludeFolderBreakdown

    .\Get-ExchangeOnlineMailboxQuotaReport.ps1 -DisableWAM

.NOTES
    Version: 1.2
    Mode: Read-only
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot "output\m365-mailbox-quota"),

    [switch]$IncludeSharedMailboxes,

    [switch]$IncludeArchiveStats,

    [switch]$IncludeLicenseDetails,

    [switch]$IncludeFolderBreakdown,

    [switch]$DisconnectWhenDone,

    [switch]$DisableWAM,

    [int]$WatchPercent = 80,

    [int]$WarningPercent = 90,

    [int]$CriticalPercent = 95,

    [double]$WatchRemainingGB = 5,

    [double]$WarningRemainingGB = 3,

    [double]$CriticalRemainingGB = 1,

    [int]$StaleLastLogonDays = 180,

    [int]$LargeMailboxGB = 40,

    [int]$FolderBreakdownTop = 8,

    [int]$FolderBreakdownMinRiskScore = 50
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

function New-SafeHtml {
    param([AllowNull()][object]$Text)

    if ($null -eq $Text) {
        return ""
    }

    return $Text.ToString().
        Replace("&", "&amp;").
        Replace("<", "&lt;").
        Replace(">", "&gt;").
        Replace('"', "&quot;").
        Replace("'", "&#39;")
}

function Convert-ByteQuantifiedSizeToBytes {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = $Value.ToString()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    if ($text -match "Unlimited") {
        return $null
    }

    if ($text -match "\(([\d\s,\.]+)\s+bytes\)") {
        $bytesText = $matches[1] -replace "[^\d]", ""
        if (-not [string]::IsNullOrWhiteSpace($bytesText)) {
            return [int64]$bytesText
        }
    }

    $normalized = $text.Replace(",", ".").Trim()

    if ($normalized -match "([\d\.]+)\s*(TB|GB|MB|KB|B)") {
        $number = [double]$matches[1]
        $unit   = $matches[2].ToUpperInvariant()

        switch ($unit) {
            "TB" { return [int64]($number * 1TB) }
            "GB" { return [int64]($number * 1GB) }
            "MB" { return [int64]($number * 1MB) }
            "KB" { return [int64]($number * 1KB) }
            "B"  { return [int64]($number) }
        }
    }

    return $null
}

function Convert-BytesToGB {
    param([AllowNull()][Nullable[Int64]]$Bytes)

    if ($null -eq $Bytes) {
        return $null
    }

    return [math]::Round(($Bytes / 1GB), 2)
}

function Format-NullableNumber {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return ""
    }

    return $Value
}

function Get-UsageStatus {
    param(
        [AllowNull()][Nullable[Double]]$UsedPercent,
        [AllowNull()][Nullable[Double]]$RemainingGB
    )

    if ($null -eq $UsedPercent) {
        return "UNKNOWN"
    }

    if ($UsedPercent -ge $CriticalPercent -or ($null -ne $RemainingGB -and $RemainingGB -le $CriticalRemainingGB)) {
        return "CRITICAL"
    }

    if ($UsedPercent -ge $WarningPercent -or ($null -ne $RemainingGB -and $RemainingGB -le $WarningRemainingGB)) {
        return "WARNING"
    }

    if ($UsedPercent -ge $WatchPercent -or ($null -ne $RemainingGB -and $RemainingGB -le $WatchRemainingGB)) {
        return "WATCH"
    }

    return "OK"
}

function Get-StatusSortOrder {
    param([string]$Status)

    switch ($Status) {
        "CRITICAL" { return 1 }
        "WARNING"  { return 2 }
        "WATCH"    { return 3 }
        "ERROR"    { return 4 }
        "UNKNOWN"  { return 5 }
        "OK"       { return 6 }
        default    { return 9 }
    }
}

function Get-BadgeClass {
    param([string]$Status)

    switch ($Status) {
        "CRITICAL" { return "badge bad" }
        "WARNING"  { return "badge warn" }
        "WATCH"    { return "badge watch" }
        "OK"       { return "badge ok" }
        "ERROR"    { return "badge bad" }
        default    { return "badge neutral" }
    }
}

function Get-RiskBadgeClass {
    param([AllowNull()][Nullable[Int32]]$RiskScore)

    if ($null -eq $RiskScore) {
        return "badge neutral"
    }

    if ($RiskScore -ge 80) {
        return "badge bad"
    }

    if ($RiskScore -ge 60) {
        return "badge warn"
    }

    if ($RiskScore -ge 35) {
        return "badge watch"
    }

    return "badge ok"
}

function Get-MailboxStatsSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [switch]$Archive
    )

    if ($Archive) {
        return Get-EXOMailboxStatistics -Identity $Identity -Archive -ErrorAction Stop
    }

    return Get-EXOMailboxStatistics -Identity $Identity -ErrorAction Stop
}

function Get-Recommendation {
    param(
        [string]$Status,
        [string]$RecipientTypeDetails,
        [AllowNull()][Nullable[Double]]$UsedGB,
        [AllowNull()][Nullable[Double]]$RemainingGB,
        [AllowNull()][Nullable[Double]]$UsedPercent,
        [string]$ArchiveStatus,
        [AllowNull()][Nullable[Double]]$ArchiveUsedGB,
        [AllowNull()][Nullable[Double]]$GrowthSincePreviousGB,
        [AllowNull()]$LastLogonTime
    )

    $isStale = $false

    if ($null -ne $LastLogonTime -and $LastLogonTime -is [datetime]) {
        if ($LastLogonTime -lt (Get-Date).AddDays(-1 * $StaleLastLogonDays)) {
            $isStale = $true
        }
    }

    if ($Status -eq "ERROR") {
        return "Review collection error"
    }

    if ($Status -eq "CRITICAL") {
        if ($ArchiveStatus -ne "Active") {
            return "Critical: enable/archive review or immediate cleanup"
        }

        return "Critical: cleanup or quota/archive policy review"
    }

    if ($Status -eq "WARNING") {
        if ($ArchiveStatus -ne "Active") {
            return "Warning: consider archive enablement and cleanup"
        }

        return "Warning: monitor and review large folders"
    }

    if ($Status -eq "WATCH") {
        if ($null -ne $GrowthSincePreviousGB -and $GrowthSincePreviousGB -gt 1) {
            return "Watch: growing mailbox, monitor trend"
        }

        return "Watch: monitor growth and user cleanup"
    }

    if ($RecipientTypeDetails -eq "SharedMailbox" -and $null -ne $UsedGB -and $UsedGB -ge $LargeMailboxGB) {
        return "Shared mailbox large: review ownership and retention"
    }

    if ($isStale -and $null -ne $UsedGB -and $UsedGB -ge 10) {
        return "Stale but large: review account/mailbox lifecycle"
    }

    if ($ArchiveStatus -eq "Active" -and ($null -eq $ArchiveUsedGB -or $ArchiveUsedGB -eq 0) -and $null -ne $UsedGB -and $UsedGB -ge $LargeMailboxGB) {
        return "Archive active but unused: review archive policy"
    }

    return "No action"
}

function Get-RiskScore {
    param(
        [string]$Status,
        [string]$RecipientTypeDetails,
        [AllowNull()][Nullable[Double]]$UsedGB,
        [AllowNull()][Nullable[Double]]$RemainingGB,
        [AllowNull()][Nullable[Double]]$UsedPercent,
        [string]$ArchiveStatus,
        [AllowNull()][Nullable[Double]]$ArchiveUsedGB,
        [AllowNull()][Nullable[Double]]$GrowthSincePreviousGB,
        [AllowNull()]$LastLogonTime,
        [string]$LicenseSkuPartNumbers
    )

    $score = 0

    switch ($Status) {
        "CRITICAL" { $score += 75 }
        "WARNING"  { $score += 55 }
        "WATCH"    { $score += 35 }
        "UNKNOWN"  { $score += 20 }
        "ERROR"    { $score += 50 }
        "OK"       { $score += 0 }
        default    { $score += 10 }
    }

    if ($null -ne $RemainingGB -and $RemainingGB -le 1) {
        $score += 10
    }
    elseif ($null -ne $RemainingGB -and $RemainingGB -le 3) {
        $score += 7
    }
    elseif ($null -ne $RemainingGB -and $RemainingGB -le 5) {
        $score += 4
    }

    if ($ArchiveStatus -ne "Active" -and $null -ne $UsedPercent -and $UsedPercent -ge $WarningPercent) {
        $score += 10
    }

    if ($RecipientTypeDetails -eq "SharedMailbox" -and $null -ne $UsedGB -and $UsedGB -ge $LargeMailboxGB) {
        $score += 10
    }

    if ($null -ne $GrowthSincePreviousGB) {
        if ($GrowthSincePreviousGB -ge 5) {
            $score += 12
        }
        elseif ($GrowthSincePreviousGB -ge 2) {
            $score += 8
        }
        elseif ($GrowthSincePreviousGB -gt 1) {
            $score += 5
        }
    }

    if ($null -ne $LastLogonTime -and $LastLogonTime -is [datetime]) {
        if ($LastLogonTime -lt (Get-Date).AddDays(-1 * $StaleLastLogonDays) -and $null -ne $UsedGB -and $UsedGB -ge 10) {
            $score += 8
        }
    }

    if ([string]::IsNullOrWhiteSpace($LicenseSkuPartNumbers)) {
        $score += 3
    }

    if ($score -gt 100) {
        $score = 100
    }

    if ($score -lt 0) {
        $score = 0
    }

    return [int]$score
}

function Get-RiskLevel {
    param([int]$RiskScore)

    if ($RiskScore -ge 80) {
        return "HIGH"
    }

    if ($RiskScore -ge 60) {
        return "ELEVATED"
    }

    if ($RiskScore -ge 35) {
        return "MEDIUM"
    }

    return "LOW"
}

function Get-LicenseDetailsSafe {
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    try {
        $licenses = Get-MgUserLicenseDetail -UserId $UserPrincipalName -ErrorAction Stop

        if ($null -eq $licenses) {
            return [pscustomobject]@{
                SkuPartNumbers = ""
                SkuIds         = ""
                Error          = ""
            }
        }

        $skuPartNumbers = @($licenses | ForEach-Object { $_.SkuPartNumber }) -join "; "
        $skuIds = @($licenses | ForEach-Object { $_.SkuId }) -join "; "

        return [pscustomobject]@{
            SkuPartNumbers = $skuPartNumbers
            SkuIds         = $skuIds
            Error          = ""
        }
    }
    catch {
        return [pscustomobject]@{
            SkuPartNumbers = ""
            SkuIds         = ""
            Error          = $_.Exception.Message
        }
    }
}

function Get-MailboxFolderBreakdownSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$RunId,

        [Parameter(Mandatory)]
        [string]$RunDate
    )

    $folderRows = New-Object System.Collections.Generic.List[object]

    try {
        $folders = Get-EXOMailboxFolderStatistics -Identity $Identity -ErrorAction Stop

        $topFolders = $folders |
            Where-Object {
                $_.FolderPath -and
                $_.FolderAndSubfolderSize -and
                $_.FolderPath -notmatch "Audits|Calendar Logging|Recoverable Items|Deletions|Purges|Versions|DiscoveryHolds|SubstrateHolds|Top of Information Store"
            } |
            ForEach-Object {
                $folderBytes = Convert-ByteQuantifiedSizeToBytes -Value $_.FolderAndSubfolderSize

                [pscustomobject]@{
                    RunId                       = $RunId
                    RunDate                     = $RunDate
                    UserPrincipalName           = $UserPrincipalName
                    FolderPath                  = $_.FolderPath
                    FolderType                  = $_.FolderType
                    ItemsInFolder               = $_.ItemsInFolder
                    ItemsInFolderAndSubfolders  = $_.ItemsInFolderAndSubfolders
                    FolderSizeGB                = Convert-BytesToGB -Bytes $folderBytes
                    RawFolderAndSubfolderSize   = $_.FolderAndSubfolderSize.ToString()
                    Error                       = ""
                }
            } |
            Sort-Object FolderSizeGB -Descending |
            Select-Object -First $FolderBreakdownTop

        foreach ($f in $topFolders) {
            $folderRows.Add($f)
        }
    }
    catch {
        $folderRows.Add([pscustomobject]@{
            RunId                       = $RunId
            RunDate                     = $RunDate
            UserPrincipalName           = $UserPrincipalName
            FolderPath                  = ""
            FolderType                  = ""
            ItemsInFolder               = ""
            ItemsInFolderAndSubfolders  = ""
            FolderSizeGB                = ""
            RawFolderAndSubfolderSize   = ""
            Error                       = $_.Exception.Message
        })
    }

    return $folderRows
}

# ------------------------------------------------------------
# Prepare output
# ------------------------------------------------------------

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runId = [guid]::NewGuid().ToString()
$runDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

$csvPath             = Join-Path $OutputPath "m365-mailbox-quota-$timestamp.csv"
$htmlPath            = Join-Path $OutputPath "index.html"
$jsonPath            = Join-Path $OutputPath "summary-$timestamp.json"
$historyPath         = Join-Path $OutputPath "history.csv"
$folderBreakdownPath = Join-Path $OutputPath "folder-breakdown-$timestamp.csv"

# ------------------------------------------------------------
# Header
# ------------------------------------------------------------

Write-Host ""
Write-Host "=== M365 Mailbox Quota Report v1.2 ===" -ForegroundColor Cyan
Write-Host "Mode      : READ-ONLY" -ForegroundColor Green
Write-Host "Output    : $OutputPath" -ForegroundColor Gray
Write-Host "Timestamp : $timestamp" -ForegroundColor Gray
Write-Host "RunId     : $runId" -ForegroundColor Gray
Write-Host ""

# ------------------------------------------------------------
# Module and connection
# ------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    throw "ExchangeOnlineManagement module is not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
}

Import-Module ExchangeOnlineManagement

Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow

if ($DisableWAM) {
    Connect-ExchangeOnline -ShowBanner:$false -DisableWAM
}
else {
    Connect-ExchangeOnline -ShowBanner:$false
}

$graphConnected = $false

if ($IncludeLicenseDetails) {
    Write-Host "License details requested. Checking Microsoft Graph modules..." -ForegroundColor Yellow

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft.Graph.Authentication module is not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
        throw "Microsoft.Graph.Users module is not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Users

    Write-Host "Connecting to Microsoft Graph with read scopes..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All" -NoWelcome
    $graphConnected = $true
}

# ------------------------------------------------------------
# Previous history snapshot
# ------------------------------------------------------------

$previousLatestByUpn = @{}

if (Test-Path $historyPath) {
    try {
        $history = Import-Csv -Path $historyPath

        $previousLatest = $history |
            Where-Object { $_.UserPrincipalName -and $_.UsedGB } |
            Sort-Object UserPrincipalName, RunDate |
            Group-Object UserPrincipalName |
            ForEach-Object {
                $_.Group | Sort-Object RunDate -Descending | Select-Object -First 1
            }

        foreach ($h in $previousLatest) {
            $previousLatestByUpn[$h.UserPrincipalName.ToLowerInvariant()] = $h
        }

        Write-Host "Previous history found: $historyPath" -ForegroundColor Green
    }
    catch {
        Write-Host "History file exists, but could not be read. Continuing without trend. Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
else {
    Write-Host "No previous history found. First run will create it." -ForegroundColor Gray
}

# ------------------------------------------------------------
# Collect mailbox list
# ------------------------------------------------------------

Write-Host "Collecting mailbox list..." -ForegroundColor Yellow

$recipientTypes = @("UserMailbox")

if ($IncludeSharedMailboxes) {
    $recipientTypes += "SharedMailbox"
}

$mailboxes = Get-EXOMailbox `
    -ResultSize Unlimited `
    -RecipientTypeDetails $recipientTypes `
    -Properties DisplayName,UserPrincipalName,PrimarySmtpAddress,RecipientTypeDetails,IssueWarningQuota,ProhibitSendQuota,ProhibitSendReceiveQuota,ArchiveStatus,ArchiveName,WhenCreated |
    Sort-Object DisplayName

$total = @($mailboxes).Count

Write-Host "Mailboxes found: $total" -ForegroundColor Green
Write-Host ""

# ------------------------------------------------------------
# Collect statistics
# ------------------------------------------------------------

$results = New-Object System.Collections.Generic.List[object]
$i = 0
$startTime = Get-Date

foreach ($mb in $mailboxes) {
    $i++

    $elapsed = (Get-Date) - $startTime

    if ($i -gt 0) {
        $avgSecondsPerMailbox = $elapsed.TotalSeconds / $i
        $remainingItems = $total - $i
        $etaSeconds = [math]::Round($avgSecondsPerMailbox * $remainingItems, 0)
        $eta = [TimeSpan]::FromSeconds($etaSeconds)
    }
    else {
        $eta = [TimeSpan]::Zero
    }

    $percent = [math]::Round((($i / [math]::Max($total, 1)) * 100), 1)

    Write-Progress `
        -Activity "M365 mailbox quota audit v1.2" `
        -Status "$i / $total | $percent% | Current: $($mb.UserPrincipalName) | ETA: $($eta.ToString('hh\:mm\:ss'))" `
        -PercentComplete $percent

    try {
        $stats = Get-MailboxStatsSafe -Identity $mb.UserPrincipalName

        $usedBytes = Convert-ByteQuantifiedSizeToBytes -Value $stats.TotalItemSize
        $warnBytes = Convert-ByteQuantifiedSizeToBytes -Value $mb.IssueWarningQuota
        $sendBytes = Convert-ByteQuantifiedSizeToBytes -Value $mb.ProhibitSendQuota
        $hardBytes = Convert-ByteQuantifiedSizeToBytes -Value $mb.ProhibitSendReceiveQuota

        $usedGB = Convert-BytesToGB -Bytes $usedBytes
        $warnGB = Convert-BytesToGB -Bytes $warnBytes
        $sendGB = Convert-BytesToGB -Bytes $sendBytes
        $hardGB = Convert-BytesToGB -Bytes $hardBytes

        $remainingGB = $null
        $usedPercent = $null

        if ($null -ne $usedBytes -and $null -ne $hardBytes -and $hardBytes -gt 0) {
            $remainingGB = [math]::Round((($hardBytes - $usedBytes) / 1GB), 2)
            $usedPercent = [math]::Round((($usedBytes / $hardBytes) * 100), 1)
        }

        $archiveUsedGB = $null
        $archiveItemCount = $null
        $archiveRawTotalItemSize = ""
        $archiveError = ""

        if ($IncludeArchiveStats -and $mb.ArchiveStatus -eq "Active") {
            try {
                $archiveStats = Get-MailboxStatsSafe -Identity $mb.UserPrincipalName -Archive
                $archiveUsedBytes = Convert-ByteQuantifiedSizeToBytes -Value $archiveStats.TotalItemSize
                $archiveUsedGB = Convert-BytesToGB -Bytes $archiveUsedBytes
                $archiveItemCount = $archiveStats.ItemCount
                $archiveRawTotalItemSize = $archiveStats.TotalItemSize.ToString()
            }
            catch {
                $archiveError = $_.Exception.Message
            }
        }

        $licenseSkuPartNumbers = ""
        $licenseSkuIds = ""
        $licenseError = ""

        if ($IncludeLicenseDetails) {
            $licenseResult = Get-LicenseDetailsSafe -UserPrincipalName $mb.UserPrincipalName
            $licenseSkuPartNumbers = $licenseResult.SkuPartNumbers
            $licenseSkuIds = $licenseResult.SkuIds
            $licenseError = $licenseResult.Error
        }

        $status = Get-UsageStatus -UsedPercent $usedPercent -RemainingGB $remainingGB

        $previousUsedGB = $null
        $growthSincePreviousGB = $null
        $previousRunDate = ""

        $upnKey = $mb.UserPrincipalName.ToString().ToLowerInvariant()

        if ($previousLatestByUpn.ContainsKey($upnKey)) {
            $prev = $previousLatestByUpn[$upnKey]
            $previousRunDate = $prev.RunDate

            if ($prev.UsedGB -ne "") {
                $previousUsedGB = [double]$prev.UsedGB
            }

            if ($null -ne $previousUsedGB -and $null -ne $usedGB) {
                $growthSincePreviousGB = [math]::Round(($usedGB - $previousUsedGB), 2)
            }
        }

        $recommendation = Get-Recommendation `
            -Status $status `
            -RecipientTypeDetails $mb.RecipientTypeDetails `
            -UsedGB $usedGB `
            -RemainingGB $remainingGB `
            -UsedPercent $usedPercent `
            -ArchiveStatus $mb.ArchiveStatus `
            -ArchiveUsedGB $archiveUsedGB `
            -GrowthSincePreviousGB $growthSincePreviousGB `
            -LastLogonTime $stats.LastLogonTime

        $riskScore = Get-RiskScore `
            -Status $status `
            -RecipientTypeDetails $mb.RecipientTypeDetails `
            -UsedGB $usedGB `
            -RemainingGB $remainingGB `
            -UsedPercent $usedPercent `
            -ArchiveStatus $mb.ArchiveStatus `
            -ArchiveUsedGB $archiveUsedGB `
            -GrowthSincePreviousGB $growthSincePreviousGB `
            -LastLogonTime $stats.LastLogonTime `
            -LicenseSkuPartNumbers $licenseSkuPartNumbers

        $riskLevel = Get-RiskLevel -RiskScore $riskScore

        $results.Add([pscustomobject]@{
            RunId                        = $runId
            RunDate                      = $runDate
            RiskScore                    = $riskScore
            RiskLevel                    = $riskLevel
            Status                       = $status
            Recommendation               = $recommendation
            DisplayName                  = $mb.DisplayName
            UserPrincipalName            = $mb.UserPrincipalName
            PrimarySmtpAddress           = $mb.PrimarySmtpAddress
            RecipientTypeDetails         = $mb.RecipientTypeDetails
            LicenseSkuPartNumbers        = $licenseSkuPartNumbers
            LicenseSkuIds                = $licenseSkuIds
            LicenseError                 = $licenseError
            UsedGB                       = $usedGB
            PreviousUsedGB               = $previousUsedGB
            GrowthSincePreviousGB        = $growthSincePreviousGB
            PreviousRunDate              = $previousRunDate
            IssueWarningQuotaGB          = $warnGB
            ProhibitSendQuotaGB          = $sendGB
            ProhibitSendReceiveQuotaGB   = $hardGB
            RemainingQuotaGB             = $remainingGB
            UsedPercent                  = $usedPercent
            ItemCount                    = $stats.ItemCount
            DeletedItemCount             = $stats.DeletedItemCount
            TotalDeletedItemSize         = $stats.TotalDeletedItemSize.ToString()
            LastLogonTime                = $stats.LastLogonTime
            MailboxCreated               = $mb.WhenCreated
            ArchiveStatus                = $mb.ArchiveStatus
            ArchiveUsedGB                = $archiveUsedGB
            ArchiveItemCount             = $archiveItemCount
            ArchiveRawTotalItemSize      = $archiveRawTotalItemSize
            ArchiveError                 = $archiveError
            RawTotalItemSize             = $stats.TotalItemSize.ToString()
            RawIssueWarningQuota         = $mb.IssueWarningQuota.ToString()
            RawProhibitSendQuota         = $mb.ProhibitSendQuota.ToString()
            RawProhibitSendReceiveQuota  = $mb.ProhibitSendReceiveQuota.ToString()
            Error                        = ""
        })
    }
    catch {
        $results.Add([pscustomobject]@{
            RunId                        = $runId
            RunDate                      = $runDate
            RiskScore                    = 50
            RiskLevel                    = "ELEVATED"
            Status                       = "ERROR"
            Recommendation               = "Review collection error"
            DisplayName                  = $mb.DisplayName
            UserPrincipalName            = $mb.UserPrincipalName
            PrimarySmtpAddress           = $mb.PrimarySmtpAddress
            RecipientTypeDetails         = $mb.RecipientTypeDetails
            LicenseSkuPartNumbers        = ""
            LicenseSkuIds                = ""
            LicenseError                 = ""
            UsedGB                       = $null
            PreviousUsedGB               = $null
            GrowthSincePreviousGB        = $null
            PreviousRunDate              = ""
            IssueWarningQuotaGB          = $null
            ProhibitSendQuotaGB          = $null
            ProhibitSendReceiveQuotaGB   = $null
            RemainingQuotaGB             = $null
            UsedPercent                  = $null
            ItemCount                    = $null
            DeletedItemCount             = $null
            TotalDeletedItemSize         = ""
            LastLogonTime                = $null
            MailboxCreated               = $mb.WhenCreated
            ArchiveStatus                = $mb.ArchiveStatus
            ArchiveUsedGB                = $null
            ArchiveItemCount             = $null
            ArchiveRawTotalItemSize      = ""
            ArchiveError                 = ""
            RawTotalItemSize             = ""
            RawIssueWarningQuota         = $mb.IssueWarningQuota.ToString()
            RawProhibitSendQuota         = $mb.ProhibitSendQuota.ToString()
            RawProhibitSendReceiveQuota  = $mb.ProhibitSendReceiveQuota.ToString()
            Error                        = $_.Exception.Message
        })
    }
}

Write-Progress -Activity "M365 mailbox quota audit v1.2" -Completed

# ------------------------------------------------------------
# Folder breakdown for problem mailboxes
# ------------------------------------------------------------

$folderBreakdownRows = New-Object System.Collections.Generic.List[object]

if ($IncludeFolderBreakdown) {
    $problemMailboxes = $results |
        Where-Object {
            $_.RiskScore -ge $FolderBreakdownMinRiskScore -and
            $_.Status -ne "ERROR" -and
            $_.UserPrincipalName
        } |
        Sort-Object RiskScore -Descending

    $folderTotal = @($problemMailboxes).Count
    $folderIndex = 0

    Write-Host "Folder breakdown requested. Problem mailboxes selected: $folderTotal" -ForegroundColor Yellow

    foreach ($pm in $problemMailboxes) {
        $folderIndex++

        $folderPercent = [math]::Round((($folderIndex / [math]::Max($folderTotal, 1)) * 100), 1)

        Write-Progress `
            -Activity "Folder breakdown for problem mailboxes" `
            -Status "$folderIndex / $folderTotal | $folderPercent% | $($pm.UserPrincipalName)" `
            -PercentComplete $folderPercent

        $rows = Get-MailboxFolderBreakdownSafe `
            -Identity $pm.UserPrincipalName `
            -UserPrincipalName $pm.UserPrincipalName `
            -RunId $runId `
            -RunDate $runDate

        foreach ($row in $rows) {
            $folderBreakdownRows.Add($row)
        }
    }

    Write-Progress -Activity "Folder breakdown for problem mailboxes" -Completed

    $folderBreakdownRows |
        Export-Csv -Path $folderBreakdownPath -NoTypeInformation -Encoding UTF8
}

# ------------------------------------------------------------
# Sort results
# ------------------------------------------------------------

$sortedResults = $results |
    Sort-Object `
        @{ Expression = "RiskScore"; Descending = $true },
        @{ Expression = { Get-StatusSortOrder -Status $_.Status } },
        @{ Expression = "UsedPercent"; Descending = $true },
        DisplayName

# ------------------------------------------------------------
# Export current CSV
# ------------------------------------------------------------

$sortedResults |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# ------------------------------------------------------------
# Append history
# ------------------------------------------------------------

$historyRows = $results | Select-Object `
    RunId,
    RunDate,
    RiskScore,
    RiskLevel,
    Status,
    Recommendation,
    DisplayName,
    UserPrincipalName,
    PrimarySmtpAddress,
    RecipientTypeDetails,
    LicenseSkuPartNumbers,
    UsedGB,
    PreviousUsedGB,
    GrowthSincePreviousGB,
    ProhibitSendReceiveQuotaGB,
    RemainingQuotaGB,
    UsedPercent,
    ItemCount,
    LastLogonTime,
    ArchiveStatus,
    ArchiveUsedGB,
    Error

if (Test-Path $historyPath) {
    $historyRows | Export-Csv -Path $historyPath -NoTypeInformation -Encoding UTF8 -Append
}
else {
    $historyRows | Export-Csv -Path $historyPath -NoTypeInformation -Encoding UTF8
}

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

$countTotal    = $results.Count
$countCritical = ($results | Where-Object Status -eq "CRITICAL").Count
$countWarning  = ($results | Where-Object Status -eq "WARNING").Count
$countWatch    = ($results | Where-Object Status -eq "WATCH").Count
$countOk       = ($results | Where-Object Status -eq "OK").Count
$countUnknown  = ($results | Where-Object Status -eq "UNKNOWN").Count
$countError    = ($results | Where-Object Status -eq "ERROR").Count

$countHighRisk = ($results | Where-Object { $_.RiskScore -ge 80 }).Count
$countElevatedRisk = ($results | Where-Object { $_.RiskScore -ge 60 -and $_.RiskScore -lt 80 }).Count

$countUnder1GB = ($results | Where-Object { $_.RemainingQuotaGB -ne $null -and $_.RemainingQuotaGB -le 1 }).Count
$countUnder3GB = ($results | Where-Object { $_.RemainingQuotaGB -ne $null -and $_.RemainingQuotaGB -le 3 }).Count
$countUnder5GB = ($results | Where-Object { $_.RemainingQuotaGB -ne $null -and $_.RemainingQuotaGB -le 5 }).Count

$countSharedLarge = ($results | Where-Object {
    $_.RecipientTypeDetails -eq "SharedMailbox" -and
    $_.UsedGB -ne $null -and
    $_.UsedGB -ge $LargeMailboxGB
}).Count

$countArchiveMissingNearFull = ($results | Where-Object {
    $_.ArchiveStatus -ne "Active" -and
    $_.UsedPercent -ne $null -and
    $_.UsedPercent -ge $WarningPercent
}).Count

$countGrowing = ($results | Where-Object {
    $_.GrowthSincePreviousGB -ne $null -and
    $_.GrowthSincePreviousGB -gt 1
}).Count

$countLicenseErrors = ($results | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_.LicenseError)
}).Count

$totalUsedGB = [math]::Round((($results | Where-Object { $_.UsedGB -ne $null } | Measure-Object -Property UsedGB -Sum).Sum), 2)

$topRisk = $results |
    Sort-Object RiskScore -Descending |
    Select-Object -First 10

$topUsed = $results |
    Where-Object { $_.UsedGB -ne $null } |
    Sort-Object UsedGB -Descending |
    Select-Object -First 10

$topRemainingLow = $results |
    Where-Object { $_.RemainingQuotaGB -ne $null } |
    Sort-Object RemainingQuotaGB |
    Select-Object -First 10

$topGrowth = $results |
    Where-Object { $_.GrowthSincePreviousGB -ne $null } |
    Sort-Object GrowthSincePreviousGB -Descending |
    Select-Object -First 10

$generated = Get-Date -Format "dd.MM.yyyy HH:mm:ss"

$summary = [pscustomobject]@{
    Version                       = "1.2"
    Generated                     = $generated
    RunId                         = $runId
    OutputPath                    = $OutputPath
    CsvPath                       = $csvPath
    HtmlPath                      = $htmlPath
    HistoryPath                   = $historyPath
    FolderBreakdownPath           = $folderBreakdownPath
    TotalMailboxes                = $countTotal
    TotalUsedGB                   = $totalUsedGB
    HighRisk                      = $countHighRisk
    ElevatedRisk                  = $countElevatedRisk
    Critical                      = $countCritical
    Warning                       = $countWarning
    Watch                         = $countWatch
    Ok                            = $countOk
    Unknown                       = $countUnknown
    Error                         = $countError
    Under1GBRemaining             = $countUnder1GB
    Under3GBRemaining             = $countUnder3GB
    Under5GBRemaining             = $countUnder5GB
    SharedMailboxesOverLargeLimit = $countSharedLarge
    ArchiveMissingNearFull        = $countArchiveMissingNearFull
    GrowingOver1GBSincePrevious   = $countGrowing
    LicenseErrors                 = $countLicenseErrors
    IncludeSharedMailboxes        = [bool]$IncludeSharedMailboxes
    IncludeArchiveStats           = [bool]$IncludeArchiveStats
    IncludeLicenseDetails         = [bool]$IncludeLicenseDetails
    IncludeFolderBreakdown        = [bool]$IncludeFolderBreakdown
    WatchPercent                  = $WatchPercent
    WarningPercent                = $WarningPercent
    CriticalPercent               = $CriticalPercent
    WatchRemainingGB              = $WatchRemainingGB
    WarningRemainingGB            = $WarningRemainingGB
    CriticalRemainingGB           = $CriticalRemainingGB
    FolderBreakdownMinRiskScore   = $FolderBreakdownMinRiskScore
}

$summary | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8

# ------------------------------------------------------------
# HTML helper rows
# ------------------------------------------------------------

function New-TopTableRows {
    param(
        [AllowEmptyCollection()]
        [AllowNull()]
        [array]$Rows = @(),

        [Parameter(Mandatory)]
        [ValidateSet("Risk", "Used", "Remaining", "Growth")]
        [string]$Mode
    )

    if ($null -eq $Rows -or @($Rows).Count -eq 0) {
        if ($Mode -eq "Risk") {
            return @('<tr><td colspan="8">No rows found.</td></tr>')
        }

        if ($Mode -eq "Used") {
            return @('<tr><td colspan="6">No rows found.</td></tr>')
        }

        if ($Mode -eq "Remaining") {
            return @('<tr><td colspan="6">No rows found.</td></tr>')
        }

        if ($Mode -eq "Growth") {
            return @('<tr><td colspan="6">No previous history yet. Growth data will appear from the second successful run.</td></tr>')
        }
    }

    $htmlRows = New-Object System.Collections.Generic.List[string]

    foreach ($r in $Rows) {
        if ($Mode -eq "Risk") {
            $riskClass = Get-RiskBadgeClass -RiskScore $r.RiskScore

            $htmlRows.Add(@"
<tr>
  <td><span class="$riskClass">$(New-SafeHtml $r.RiskScore)</span></td>
  <td>$(New-SafeHtml $r.RiskLevel)</td>
  <td>$(New-SafeHtml $r.Status)</td>
  <td>$(New-SafeHtml $r.DisplayName)</td>
  <td>$(New-SafeHtml $r.UserPrincipalName)</td>
  <td class="num">$(New-SafeHtml $r.UsedGB)</td>
  <td class="num">$(New-SafeHtml $r.RemainingQuotaGB)</td>
  <td>$(New-SafeHtml $r.Recommendation)</td>
</tr>
"@)
        }
        elseif ($Mode -eq "Used") {
            $htmlRows.Add(@"
<tr>
  <td>$(New-SafeHtml $r.DisplayName)</td>
  <td>$(New-SafeHtml $r.UserPrincipalName)</td>
  <td class="num">$(New-SafeHtml $r.UsedGB)</td>
  <td class="num">$(New-SafeHtml $r.ProhibitSendReceiveQuotaGB)</td>
  <td class="num">$(New-SafeHtml $r.UsedPercent)</td>
  <td>$(New-SafeHtml $r.Recommendation)</td>
</tr>
"@)
        }
        elseif ($Mode -eq "Remaining") {
            $htmlRows.Add(@"
<tr>
  <td>$(New-SafeHtml $r.DisplayName)</td>
  <td>$(New-SafeHtml $r.UserPrincipalName)</td>
  <td class="num">$(New-SafeHtml $r.RemainingQuotaGB)</td>
  <td class="num">$(New-SafeHtml $r.UsedGB)</td>
  <td class="num">$(New-SafeHtml $r.ProhibitSendReceiveQuotaGB)</td>
  <td class="num">$(New-SafeHtml $r.UsedPercent)</td>
</tr>
"@)
        }
        elseif ($Mode -eq "Growth") {
            $htmlRows.Add(@"
<tr>
  <td>$(New-SafeHtml $r.DisplayName)</td>
  <td>$(New-SafeHtml $r.UserPrincipalName)</td>
  <td class="num">$(New-SafeHtml $r.GrowthSincePreviousGB)</td>
  <td class="num">$(New-SafeHtml $r.PreviousUsedGB)</td>
  <td class="num">$(New-SafeHtml $r.UsedGB)</td>
  <td>$(New-SafeHtml $r.PreviousRunDate)</td>
</tr>
"@)
        }
    }

    return $htmlRows
}

# ------------------------------------------------------------
# Main HTML rows
# ------------------------------------------------------------

$rowsHtml = foreach ($r in $sortedResults) {
    $badgeClass = Get-BadgeClass -Status $r.Status
    $riskClass = Get-RiskBadgeClass -RiskScore $r.RiskScore

@"
<tr data-status="$(New-SafeHtml $r.Status)" data-type="$(New-SafeHtml $r.RecipientTypeDetails)" data-recommendation="$(New-SafeHtml $r.Recommendation)" data-risk="$(New-SafeHtml $r.RiskScore)">
  <td><span class="$riskClass">$(New-SafeHtml $r.RiskScore)</span></td>
  <td>$(New-SafeHtml $r.RiskLevel)</td>
  <td><span class="$badgeClass">$(New-SafeHtml $r.Status)</span></td>
  <td>$(New-SafeHtml $r.Recommendation)</td>
  <td>$(New-SafeHtml $r.DisplayName)</td>
  <td>$(New-SafeHtml $r.UserPrincipalName)</td>
  <td>$(New-SafeHtml $r.PrimarySmtpAddress)</td>
  <td>$(New-SafeHtml $r.RecipientTypeDetails)</td>
  <td>$(New-SafeHtml $r.LicenseSkuPartNumbers)</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.UsedGB))</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.PreviousUsedGB))</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.GrowthSincePreviousGB))</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.ProhibitSendReceiveQuotaGB))</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.RemainingQuotaGB))</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.UsedPercent))</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.ItemCount))</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.DeletedItemCount))</td>
  <td>$(New-SafeHtml $r.TotalDeletedItemSize)</td>
  <td>$(New-SafeHtml $r.LastLogonTime)</td>
  <td>$(New-SafeHtml $r.ArchiveStatus)</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.ArchiveUsedGB))</td>
  <td class="num">$(New-SafeHtml (Format-NullableNumber $r.ArchiveItemCount))</td>
  <td>$(New-SafeHtml $r.LicenseError)</td>
  <td>$(New-SafeHtml $r.ArchiveError)</td>
  <td>$(New-SafeHtml $r.Error)</td>
</tr>
"@
}

$topRiskHtml = New-TopTableRows -Rows @($topRisk) -Mode "Risk"
$topUsedHtml = New-TopTableRows -Rows @($topUsed) -Mode "Used"
$topRemainingLowHtml = New-TopTableRows -Rows @($topRemainingLow) -Mode "Remaining"
$topGrowthHtml = New-TopTableRows -Rows @($topGrowth) -Mode "Growth"

# ------------------------------------------------------------
# HTML report
# ------------------------------------------------------------

$html = @"
<!doctype html>
<html lang="fi">
<head>
<meta charset="utf-8">
<title>M365 Mailbox Quota Report v1.2</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
  --bg: #f4f7fb;
  --card: #ffffff;
  --text: #172033;
  --muted: #667085;
  --border: #d9e2ec;
  --ok: #16a34a;
  --watch: #2563eb;
  --warn: #ca8a04;
  --bad: #dc2626;
  --neutral: #64748b;
  --shadow: rgba(16,24,40,.06);
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Segoe UI, Arial, sans-serif;
  font-size: 14px;
}

.wrap {
  max-width: 1920px;
  margin: 0 auto;
  padding: 24px;
}

h1 {
  margin: 0 0 6px;
  font-size: 28px;
}

h2 {
  margin: 0 0 12px;
  font-size: 18px;
}

.sub {
  color: var(--muted);
  margin-bottom: 24px;
  line-height: 1.5;
}

.cards {
  display: grid;
  grid-template-columns: repeat(6, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}

.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 16px;
  box-shadow: 0 1px 2px var(--shadow);
  cursor: pointer;
}

.card:hover {
  outline: 2px solid #bfdbfe;
}

.card .label {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: .04em;
}

.card .value {
  margin-top: 8px;
  font-size: 28px;
  font-weight: 700;
}

.toolbar {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 12px;
  margin-bottom: 16px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
  box-shadow: 0 1px 2px var(--shadow);
}

button {
  border: 1px solid var(--border);
  background: #fff;
  color: var(--text);
  border-radius: 10px;
  padding: 8px 12px;
  cursor: pointer;
  font-weight: 600;
}

button:hover {
  background: #f1f5f9;
}

input {
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 9px 12px;
  min-width: 360px;
}

.section {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 16px;
  margin-bottom: 20px;
  overflow-x: auto;
  box-shadow: 0 1px 2px var(--shadow);
}

table {
  width: 100%;
  border-collapse: collapse;
  white-space: nowrap;
}

th, td {
  border-bottom: 1px solid var(--border);
  padding: 9px 10px;
  text-align: left;
  vertical-align: top;
}

th {
  background: #f8fafc;
  font-size: 12px;
  text-transform: uppercase;
  color: var(--muted);
  letter-spacing: .03em;
  position: sticky;
  top: 0;
  z-index: 1;
  cursor: pointer;
}

th:hover {
  color: var(--text);
}

tr:hover td {
  background: #f8fafc;
}

.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}

.badge {
  display: inline-block;
  border-radius: 999px;
  padding: 4px 9px;
  font-size: 12px;
  font-weight: 700;
  color: #fff;
}

.badge.ok { background: var(--ok); }
.badge.watch { background: var(--watch); }
.badge.warn { background: var(--warn); }
.badge.bad { background: var(--bad); }
.badge.neutral { background: var(--neutral); }

.small {
  color: var(--muted);
  font-size: 12px;
  line-height: 1.5;
}

.note {
  background: #f8fafc;
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 12px;
  color: var(--muted);
  margin-bottom: 12px;
}

@media (max-width: 1200px) {
  .cards {
    grid-template-columns: repeat(2, minmax(140px, 1fr));
  }

  input {
    min-width: 100%;
  }
}
</style>
</head>
<body>
<div class="wrap">

  <h1>M365 Mailbox Quota Report v1.2</h1>
  <div class="sub">
    Generated: $generated<br>
    Mode: READ-ONLY<br>
    RunId: $(New-SafeHtml $runId)<br>
    CSV: $(New-SafeHtml $csvPath)<br>
    History: $(New-SafeHtml $historyPath)<br>
    Folder breakdown: $(New-SafeHtml $folderBreakdownPath)<br>
    JSON summary: $(New-SafeHtml $jsonPath)
  </div>

  <div class="cards">
    <div class="card" onclick="resetFilters()">
      <div class="label">Mailboxes</div>
      <div class="value">$countTotal</div>
    </div>
    <div class="card" onclick="filterRisk(80)">
      <div class="label">High risk</div>
      <div class="value">$countHighRisk</div>
    </div>
    <div class="card" onclick="filterRisk(60)">
      <div class="label">Risk ≥ 60</div>
      <div class="value">$countElevatedRisk</div>
    </div>
    <div class="card" onclick="filterStatus('CRITICAL')">
      <div class="label">Critical</div>
      <div class="value">$countCritical</div>
    </div>
    <div class="card" onclick="filterStatus('WARNING')">
      <div class="label">Warning</div>
      <div class="value">$countWarning</div>
    </div>
    <div class="card" onclick="filterRemaining(3)">
      <div class="label">≤ 3 GB left</div>
      <div class="value">$countUnder3GB</div>
    </div>
  </div>

  <div class="cards">
    <div class="card" onclick="filterGrowth()">
      <div class="label">Growth > 1 GB</div>
      <div class="value">$countGrowing</div>
    </div>
    <div class="card" onclick="filterSharedLarge()">
      <div class="label">Large shared</div>
      <div class="value">$countSharedLarge</div>
    </div>
    <div class="card" onclick="filterArchiveMissingNearFull()">
      <div class="label">Near full, no archive</div>
      <div class="value">$countArchiveMissingNearFull</div>
    </div>
    <div class="card" onclick="filterLicenseErrors()">
      <div class="label">License errors</div>
      <div class="value">$countLicenseErrors</div>
    </div>
    <div class="card">
      <div class="label">Total used GB</div>
      <div class="value">$totalUsedGB</div>
    </div>
    <div class="card" onclick="filterStatus('ERROR')">
      <div class="label">Collection errors</div>
      <div class="value">$countError</div>
    </div>
  </div>

  <div class="toolbar">
    <button onclick="resetFilters()">Reset</button>
    <button onclick="filterStatus('ALL')">All</button>
    <button onclick="filterStatus('CRITICAL')">Critical</button>
    <button onclick="filterStatus('WARNING')">Warning</button>
    <button onclick="filterStatus('WATCH')">Watch</button>
    <button onclick="filterStatus('OK')">OK</button>
    <button onclick="filterType('ALL')">All types</button>
    <button onclick="filterType('UserMailbox')">User mailboxes</button>
    <button onclick="filterType('SharedMailbox')">Shared mailboxes</button>
    <button onclick="exportVisibleRowsToCsv()">Export visible rows</button>
    <input id="searchBox" type="search" placeholder="Search user, email, license, recommendation..." oninput="applyFilters()">
  </div>

  <div class="section">
    <h2>Management summary</h2>
    <div class="note">
      Ympäristössä on <b>$countTotal</b> raportoitua postilaatikkoa.
      High risk -tasolla on <b>$countHighRisk</b>, kriittisiä quota-havaintoja <b>$countCritical</b> ja varoitustasolla <b>$countWarning</b>.
      Alle 3 GB quota-tilaa jäljellä on <b>$countUnder3GB</b> postilaatikolla.
      Edelliseen ajoon verrattuna yli 1 GB kasvaneita postilaatikoita on <b>$countGrowing</b>.
      Tämä raportti on täysin read-only. Tenantin asetuksia ei muutettu. Ihme kyllä, joskus paras muutos on olla muuttamatta mitään.
    </div>
  </div>

  <div class="section">
    <h2>Top 10 risk score</h2>
    <div class="note">
      RiskScore yhdistää quota-tilanteen, kasvutrendin, archive-puutteen, shared mailbox -koon, stale-käytön ja lisenssitiedon puutteen.
    </div>
    <table>
      <thead>
        <tr>
          <th>Risk</th>
          <th>Level</th>
          <th>Status</th>
          <th>Display name</th>
          <th>UPN</th>
          <th class="num">Used GB</th>
          <th class="num">Remaining GB</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>
        $($topRiskHtml -join "`n")
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Top 10 largest mailboxes</h2>
    <table>
      <thead>
        <tr>
          <th>Display name</th>
          <th>UPN</th>
          <th class="num">Used GB</th>
          <th class="num">Quota GB</th>
          <th class="num">Used %</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>
        $($topUsedHtml -join "`n")
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Top 10 lowest remaining quota</h2>
    <table>
      <thead>
        <tr>
          <th>Display name</th>
          <th>UPN</th>
          <th class="num">Remaining GB</th>
          <th class="num">Used GB</th>
          <th class="num">Quota GB</th>
          <th class="num">Used %</th>
        </tr>
      </thead>
      <tbody>
        $($topRemainingLowHtml -join "`n")
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Top 10 mailbox growth since previous run</h2>
    <table>
      <thead>
        <tr>
          <th>Display name</th>
          <th>UPN</th>
          <th class="num">Growth GB</th>
          <th class="num">Previous used GB</th>
          <th class="num">Current used GB</th>
          <th>Previous run</th>
        </tr>
      </thead>
      <tbody>
        $($topGrowthHtml -join "`n")
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Mailbox quota details</h2>

    <p class="small">
      Status logic:
      CRITICAL = >= $CriticalPercent% used or <= $CriticalRemainingGB GB left.
      WARNING = >= $WarningPercent% used or <= $WarningRemainingGB GB left.
      WATCH = >= $WatchPercent% used or <= $WatchRemainingGB GB left.
      Remaining quota is calculated against ProhibitSendReceiveQuota.
      Trend is based on local history.csv.
      Click table headers to sort.
    </p>

    <table id="mainTable">
      <thead>
        <tr>
          <th>Risk</th>
          <th>Risk level</th>
          <th>Status</th>
          <th>Recommendation</th>
          <th>Display name</th>
          <th>UPN</th>
          <th>SMTP</th>
          <th>Type</th>
          <th>Licenses</th>
          <th class="num">Used GB</th>
          <th class="num">Previous GB</th>
          <th class="num">Growth GB</th>
          <th class="num">Hard quota GB</th>
          <th class="num">Remaining GB</th>
          <th class="num">Used %</th>
          <th class="num">Items</th>
          <th class="num">Deleted items</th>
          <th>Deleted item size</th>
          <th>Last logon</th>
          <th>Archive</th>
          <th class="num">Archive used GB</th>
          <th class="num">Archive items</th>
          <th>License error</th>
          <th>Archive error</th>
          <th>Error</th>
        </tr>
      </thead>
      <tbody>
        $($rowsHtml -join "`n")
      </tbody>
    </table>
  </div>

</div>

<script>
let currentStatus = 'ALL';
let currentType = 'ALL';
let customFilter = null;
let sortDirections = {};

function resetFilters() {
  currentStatus = 'ALL';
  currentType = 'ALL';
  customFilter = null;
  document.getElementById('searchBox').value = '';
  applyFilters();
}

function filterStatus(status) {
  currentStatus = status;
  customFilter = null;
  applyFilters();
}

function filterType(type) {
  currentType = type;
  customFilter = null;
  applyFilters();
}

function filterRisk(limit) {
  customFilter = function(row) {
    const value = parseFloat(row.cells[0].innerText.replace(',', '.'));
    return !isNaN(value) && value >= limit;
  };
  applyFilters();
}

function filterRemaining(limit) {
  customFilter = function(row) {
    const value = parseFloat(row.cells[13].innerText.replace(',', '.'));
    return !isNaN(value) && value <= limit;
  };
  applyFilters();
}

function filterGrowth() {
  customFilter = function(row) {
    const value = parseFloat(row.cells[11].innerText.replace(',', '.'));
    return !isNaN(value) && value > 1;
  };
  applyFilters();
}

function filterSharedLarge() {
  customFilter = function(row) {
    const type = row.getAttribute('data-type');
    const used = parseFloat(row.cells[9].innerText.replace(',', '.'));
    return type === 'SharedMailbox' && !isNaN(used) && used >= $LargeMailboxGB;
  };
  applyFilters();
}

function filterArchiveMissingNearFull() {
  customFilter = function(row) {
    const archiveStatus = row.cells[19].innerText.trim();
    const usedPercent = parseFloat(row.cells[14].innerText.replace(',', '.'));
    return archiveStatus !== 'Active' && !isNaN(usedPercent) && usedPercent >= $WarningPercent;
  };
  applyFilters();
}

function filterLicenseErrors() {
  customFilter = function(row) {
    return row.cells[22].innerText.trim().length > 0;
  };
  applyFilters();
}

function applyFilters() {
  const q = document.getElementById('searchBox').value.toLowerCase();
  const rows = document.querySelectorAll('#mainTable tbody tr');

  rows.forEach(row => {
    const status = row.getAttribute('data-status');
    const type = row.getAttribute('data-type');
    const text = row.innerText.toLowerCase();

    const statusMatch = currentStatus === 'ALL' || status === currentStatus;
    const typeMatch = currentType === 'ALL' || type === currentType;
    const searchMatch = !q || text.includes(q);
    const customMatch = !customFilter || customFilter(row);

    row.style.display = (statusMatch && typeMatch && searchMatch && customMatch) ? '' : 'none';
  });
}

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  value = value.toString();
  if (value.includes('"') || value.includes(',') || value.includes('\\n') || value.includes('\\r')) {
    return '"' + value.replace(/"/g, '""') + '"';
  }
  return value;
}

function exportVisibleRowsToCsv() {
  const table = document.getElementById('mainTable');
  const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.innerText.trim());
  const rows = Array.from(table.querySelectorAll('tbody tr')).filter(row => row.style.display !== 'none');

  let csv = [];
  csv.push(headers.map(csvEscape).join(','));

  rows.forEach(row => {
    const cells = Array.from(row.cells).map(td => td.innerText.trim());
    csv.push(cells.map(csvEscape).join(','));
  });

  const blob = new Blob([csv.join('\\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'visible-mailbox-quota-rows.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function sortTable(tableId, columnIndex) {
  const table = document.getElementById(tableId);
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);

  const key = tableId + '-' + columnIndex;
  sortDirections[key] = !sortDirections[key];
  const asc = sortDirections[key];

  rows.sort((a, b) => {
    let av = a.cells[columnIndex].innerText.trim();
    let bv = b.cells[columnIndex].innerText.trim();

    const an = parseFloat(av.replace(',', '.'));
    const bn = parseFloat(bv.replace(',', '.'));

    if (!isNaN(an) && !isNaN(bn)) {
      return asc ? an - bn : bn - an;
    }

    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  });

  rows.forEach(row => tbody.appendChild(row));
}

document.addEventListener('DOMContentLoaded', function() {
  const table = document.getElementById('mainTable');
  const headers = table.querySelectorAll('thead th');

  headers.forEach((th, index) => {
    th.addEventListener('click', function() {
      sortTable('mainTable', index);
    });
  });
});
</script>

</body>
</html>
"@

Set-Content -Path $htmlPath -Value $html -Encoding UTF8

# ------------------------------------------------------------
# Done
# ------------------------------------------------------------

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "CSV              : $csvPath" -ForegroundColor Cyan
Write-Host "HTML             : $htmlPath" -ForegroundColor Cyan
Write-Host "JSON summary     : $jsonPath" -ForegroundColor Cyan
Write-Host "History          : $historyPath" -ForegroundColor Cyan

if ($IncludeFolderBreakdown) {
    Write-Host "Folder breakdown : $folderBreakdownPath" -ForegroundColor Cyan
}

Write-Host ""

Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "  Total                       : $countTotal"
Write-Host "  Used GB                     : $totalUsedGB"
Write-Host "  High risk                   : $countHighRisk"
Write-Host "  Elevated risk               : $countElevatedRisk"
Write-Host "  Critical                    : $countCritical"
Write-Host "  Warning                     : $countWarning"
Write-Host "  Watch                       : $countWatch"
Write-Host "  OK                          : $countOk"
Write-Host "  Errors                      : $countError"
Write-Host "  <= 3 GB remaining           : $countUnder3GB"
Write-Host "  Growth > 1 GB since previous: $countGrowing"
Write-Host "  Large shared mailboxes      : $countSharedLarge"
Write-Host "  Near full without archive   : $countArchiveMissingNearFull"
Write-Host "  License lookup errors       : $countLicenseErrors"
Write-Host ""

if ($DisconnectWhenDone) {
    Disconnect-ExchangeOnline -Confirm:$false

    if ($graphConnected) {
        Disconnect-MgGraph | Out-Null
    }

    Write-Host "Disconnected from Exchange Online / Graph." -ForegroundColor Gray
}
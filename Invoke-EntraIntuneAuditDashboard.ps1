<#
.SYNOPSIS
    Entra ID and Intune Audit Dashboard.

.DESCRIPTION
    Kerää Entra ID -käyttäjät, Entra-laitteet ja valinnaisesti Intune-laitteet yhteen CSV/JSON/HTML-auditointinäkymään.

.REQUIREMENTS
    - Microsoft Graph PowerShell -moduulit ja tarvittavat Entra/Intune-lukuoikeudet

.OUTPUTS
    - CSV-, JSON- ja HTML-auditointiraportit

.EXAMPLE
    .\Invoke-EntraIntuneAuditDashboard.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Invoke-EntraIntuneAuditDashboard.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

param(
    [string]$OutputFolder = (Join-Path $PSScriptRoot "output\entra"),
    [int]$InactiveUserDays = 90,
    [int]$InactiveDeviceDays = 90,
    [int]$InactiveIntuneDays = 60,
    [int]$SignInLogLookbackDays = 30,
    [switch]$SkipIntune,
    [switch]$UseDeviceAuth
)

$ErrorActionPreference = "Stop"
$ScriptVersion = "1.7"
$RunMode = if ($SkipIntune) { "EntraOnly" } else { "Entra+Intune" }

# =========================================================
# Entra / AAD Read-Only Audit Dashboard v1.7
# - Users
# - Entra Devices
# - Intune Managed Devices (optional)
# - Correlation tab with Hard/Soft matching
# - Duplicate device name detection
# - CSV + HTML + JSON output
# - Review candidate CSVs
# - Read-only only
# - Progress bars
# - Auto-install missing Microsoft Graph modules
# - Clickable summary cards
# - Top Findings
# - Export visible rows to CSV from browser
# - Copy visible key values from browser
# - ADUC / NOC light theme
# - Page size selector + pagination
# - signInActivity role-aware fallback
# - Recommendation field
# - RiskOrder sorting
# - localStorage for active tab and page size
# =========================================================

function Safe-WriteHost {
    param(
        [string]$Text,
        [string]$Color = "White"
    )

    $validColors = [System.Enum]::GetNames([System.ConsoleColor])
    if ($Color -in $validColors) {
        Write-Host $Text -ForegroundColor $Color
    }
    else {
        Write-Host $Text
    }
}

function New-SafeHtml {
    param([object]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Format-DateValue {
    param([object]$DateValue)

    if ($null -eq $DateValue -or [string]::IsNullOrWhiteSpace([string]$DateValue)) {
        return ""
    }

    try {
        return ([datetime]$DateValue).ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        return [string]$DateValue
    }
}

function Get-DaysSince {
    param([object]$DateValue)

    if ($null -eq $DateValue -or [string]::IsNullOrWhiteSpace([string]$DateValue)) {
        return $null
    }

    try {
        $dt = [datetime]$DateValue
        return [math]::Floor(((Get-Date) - $dt).TotalDays)
    }
    catch {
        return $null
    }
}

function Get-RiskBadge {
    param(
        [string]$Text,
        [string]$CssClass
    )
    return '<span class="badge ' + $CssClass + '">' + (New-SafeHtml $Text) + '</span>'
}

function Convert-ToJsonHtmlSafe {
    param([object]$Object)

    $json = $Object | ConvertTo-Json -Depth 12 -Compress
    return [System.Net.WebUtility]::HtmlEncode($json)
}

function Get-RiskSortOrder {
    param([string]$Risk)

    switch ($Risk) {
        "HIGH"   { return 1 }
        "MEDIUM" { return 2 }
        "LOW"    { return 3 }
        default  { return 4 }
    }
}

function Test-IsLegacyOs {
    param(
        [string]$OperatingSystem,
        [string]$OperatingSystemVersion
    )

    $os = [string]$OperatingSystem
    $ver = [string]$OperatingSystemVersion

    if ([string]::IsNullOrWhiteSpace($os) -and [string]::IsNullOrWhiteSpace($ver)) {
        return $false
    }

    if ($os -match 'Windows 7|Windows 8|Windows 8\.1|Windows XP|Windows Vista') {
        return $true
    }

    if ($os -match 'Windows' -and $ver -match '^6\.') {
        return $true
    }

    return $false
}

function Get-NormalizedName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return "" }
    return $Name.Trim().ToLowerInvariant()
}

function Ensure-GraphModules {
    param(
        [switch]$IncludeIntune
    )

    Safe-WriteHost "Checking Microsoft Graph modules..." "Cyan"

    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )

    if ($IncludeIntune) {
        $requiredModules += "Microsoft.Graph.DeviceManagement"
    }

    foreach ($module in $requiredModules) {
        $installed = Get-Module -ListAvailable -Name $module

        if (-not $installed) {
            Safe-WriteHost "Installing missing module: $module" "Yellow"
            try {
                Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
            catch {
                throw "Failed to install module '$module'. Error: $($_.Exception.Message)"
            }
        }
        else {
            Safe-WriteHost "Module OK: $module" "DarkGray"
        }
    }
}

function Test-GraphModuleVersionHealth {
    Safe-WriteHost "Checking Microsoft Graph module version health..." "Cyan"

    $mods = @(
        Get-Module -ListAvailable Microsoft.Graph* |
            Select-Object Name, Version, Path |
            Sort-Object Name, Version
    )

    if (-not $mods -or $mods.Count -eq 0) {
        Safe-WriteHost "No Microsoft.Graph modules found before install check." "DarkGray"
        return
    }

    $problemGroups = @(
        $mods |
            Group-Object Name |
            Where-Object { @($_.Group.Version | Select-Object -Unique).Count -gt 1 }
    )

    if ($problemGroups.Count -gt 0) {
        Safe-WriteHost "WARNING: Multiple versions of one or more Microsoft.Graph modules were found." "Yellow"
        Safe-WriteHost "This can cause 'Assembly with same name is already loaded' errors." "Yellow"

        foreach ($g in $problemGroups) {
            Safe-WriteHost ("Module: " + $g.Name) "Yellow"
            $g.Group | Select-Object Name, Version, Path | Format-Table -AutoSize
        }

        throw "Microsoft.Graph module version conflict detected. Clean up old Graph modules and reinstall a single clean set."
    }

    Safe-WriteHost "Graph module version health OK." "DarkGray"
}


function Ensure-GraphConnection {
    param(
        [string[]]$Scopes,
        [switch]$UseDeviceAuth
    )

    try {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
    }
    catch {
        $ctx = $null
    }

    $needsConnect = $false

    if ($null -eq $ctx) {
        $needsConnect = $true
    }
    else {
        $existingScopes = @($ctx.Scopes)
        $missing = @($Scopes | Where-Object { $_ -notin $existingScopes })
        if ($missing.Count -gt 0) {
            $needsConnect = $true
        }
    }

    if ($needsConnect) {
        if ($UseDeviceAuth) {
            Connect-MgGraph -Scopes $Scopes -NoWelcome -UseDeviceAuthentication | Out-Null
        }
        else {
            try {
                Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
            }
            catch {
                $msg = $_.Exception.Message
                if ($msg -match 'A window handle must be configured' -or $msg -match 'InteractiveBrowserCredential authentication failed') {
                    Write-Warning "Interactive WAM sign-in failed. Falling back to device code authentication..."
                    Connect-MgGraph -Scopes $Scopes -NoWelcome -UseDeviceAuthentication | Out-Null
                }
                else {
                    throw
                }
            }
        }
    }
}

function Update-StepProgress {
    param(
        [int]$Id,
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )

    if ($PercentComplete -lt 0) { $PercentComplete = 0 }
    if ($PercentComplete -gt 100) { $PercentComplete = 100 }

    Write-Progress -Id $Id -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

function Complete-StepProgress {
    param(
        [int]$Id,
        [string]$Activity,
        [string]$Status = "Done"
    )

    Write-Progress -Id $Id -Activity $Activity -Status $Status -Completed
}

function Get-LicenseSkuMap {
    $map = @{}
    try {
        $skus = @(Get-MgSubscribedSku -All)
        foreach ($sku in $skus) {
            if ($sku.SkuId) {
                $map[[string]$sku.SkuId] = [string]$sku.SkuPartNumber
            }
        }
    }
    catch {
        Write-Warning "Could not read subscribed SKUs. License names will fall back to SkuId."
    }
    return $map
}

function Get-LicenseNames {
    param(
        [object[]]$AssignedLicenses,
        [hashtable]$SkuMap
    )

    if (-not $AssignedLicenses) { return "" }

    $names = foreach ($lic in $AssignedLicenses) {
        $skuId = [string]$lic.SkuId
        if ([string]::IsNullOrWhiteSpace($skuId)) { continue }

        if ($SkuMap.ContainsKey($skuId)) {
            $SkuMap[$skuId]
        }
        else {
            $skuId
        }
    }

    return (($names | Sort-Object -Unique) -join "; ")
}

function Get-UserRiskData {
    param(
        [object]$User,
        [int]$InactiveDays
    )

    $lastInteractive = $null
    $lastNonInteractive = $null
    $lastAny = $null

    if ($null -ne $User.SignInActivity) {
        if ($User.SignInActivity.PSObject.Properties.Name -contains "LastSignInDateTime") {
            $lastInteractive = $User.SignInActivity.LastSignInDateTime
        }
        if ($User.SignInActivity.PSObject.Properties.Name -contains "LastNonInteractiveSignInDateTime") {
            $lastNonInteractive = $User.SignInActivity.LastNonInteractiveSignInDateTime
        }
        if ($User.SignInActivity.PSObject.Properties.Name -contains "LastSuccessfulSignInDateTime") {
            $lastAny = $User.SignInActivity.LastSuccessfulSignInDateTime
        }
    }

    if (-not $lastAny) {
        if ($lastInteractive -and $lastNonInteractive) {
            if ([datetime]$lastInteractive -ge [datetime]$lastNonInteractive) {
                $lastAny = $lastInteractive
            }
            else {
                $lastAny = $lastNonInteractive
            }
        }
        elseif ($lastInteractive) {
            $lastAny = $lastInteractive
        }
        elseif ($lastNonInteractive) {
            $lastAny = $lastNonInteractive
        }
    }

    $daysSince = Get-DaysSince $lastAny
    $isNeverSignedIn = $null -eq $lastAny
    $isInactive = $false

    if ($null -ne $daysSince -and $daysSince -ge $InactiveDays) {
        $isInactive = $true
    }

    $licenseCount = 0
    if ($User.AssignedLicenses) {
        $licenseCount = @($User.AssignedLicenses).Count
    }

    $flags = New-Object System.Collections.Generic.List[string]
    $risk = "OK"
    $riskClass = "ok"

    if (-not $User.AccountEnabled -and $licenseCount -gt 0) {
        $flags.Add("Disabled + licensed")
        $risk = "HIGH"
        $riskClass = "high"
    }

    if ($User.UserType -eq "Guest" -and ($isNeverSignedIn -or $isInactive)) {
        $flags.Add("Stale guest")
        if ($risk -ne "HIGH") {
            $risk = "MEDIUM"
            $riskClass = "medium"
        }
    }

    if ($isNeverSignedIn) {
        $flags.Add("Never signed in")
        if ($risk -eq "OK") {
            $risk = "MEDIUM"
            $riskClass = "medium"
        }
    }

    if ($isInactive) {
        $flags.Add("Inactive")
        if ($risk -eq "OK") {
            $risk = "MEDIUM"
            $riskClass = "medium"
        }
    }

    if (-not $User.AccountEnabled -and $licenseCount -eq 0 -and $flags.Count -eq 0) {
        $flags.Add("Disabled")
        $risk = "LOW"
        $riskClass = "low"
    }

[PSCustomObject]@{
    LastInteractiveSignIn    = $lastInteractive
    LastNonInteractiveSignIn = $lastNonInteractive
    LastAnySignIn            = $lastAny
    DaysSinceLastAnySignIn   = $daysSince
    NeverSignedIn            = $isNeverSignedIn
    Inactive                 = $isInactive
    LicenseCount             = $licenseCount
    Flags                    = ($flags -join "; ")
    Risk                     = $risk
    RiskClass                = $riskClass
    RiskOrder                = Get-RiskSortOrder $risk
    SignInConfidence         = "High"
    ActivityStatus           = if ($isNeverSignedIn) { "NeverSignedInFromSignInActivity" } elseif ($isInactive) { "StaleCandidateFromSignInActivity" } else { "ActiveOrRecentlyUsedFromSignInActivity" }
}
}

function Get-UserRiskDataFallback {
    param(
        [object]$User,
        [object]$AuditLogFallback,
        [int]$InactiveDays
    )

    $licenseCount = 0
    if ($User.AssignedLicenses) {
        $licenseCount = @($User.AssignedLicenses).Count
    }

    $lastAny = $null
    $daysSince = $null
    $isNeverSignedIn = $false
    $isInactive = $false
    $signInConfidence = "Low"
    $activityStatus = "UnknownDueToSignInActivityUnavailable"

    $flags = New-Object System.Collections.Generic.List[string]

    if ($null -ne $AuditLogFallback -and -not [string]::IsNullOrWhiteSpace([string]$AuditLogFallback.LastSignIn)) {
        $lastAny = $AuditLogFallback.LastSignIn
        $daysSince = Get-DaysSince $lastAny
        $signInConfidence = "FallbackRecent"
        $activityStatus = "ActiveRecentFromAuditLogs"
        $flags.Add("Last successful sign-in from auditLogs fallback")

        if ($null -ne $daysSince -and $daysSince -ge $InactiveDays) {
            $isInactive = $true
            $activityStatus = "StaleCandidateFromAuditLogs"
            $flags.Add("Inactive based on auditLogs fallback")
        }
    }
    else {
        $flags.Add("signInActivity unavailable")
        $flags.Add("No successful sign-in found in auditLogs fallback window")
        $flags.Add("Stale status cannot be confirmed from fallback data only")
    }

    $risk = "OK"
    $riskClass = "ok"

    if (-not $User.AccountEnabled -and $licenseCount -gt 0) {
        $flags.Add("Disabled + licensed")
        $risk = "HIGH"
        $riskClass = "high"
    }
    elseif (-not $User.AccountEnabled) {
        $flags.Add("Disabled")
        $risk = "LOW"
        $riskClass = "low"
    }
    elseif ($isInactive) {
        $risk = "MEDIUM"
        $riskClass = "medium"
    }
    elseif ($User.UserType -eq "Guest" -and $null -eq $lastAny) {
        $flags.Add("Guest with unknown recent activity")
        $risk = "MEDIUM"
        $riskClass = "medium"
    }
    elseif ($User.UserType -eq "Guest") {
        $flags.Add("Guest")
        $risk = "LOW"
        $riskClass = "low"
    }
    elseif ($null -eq $lastAny) {
        $risk = "LOW"
        $riskClass = "low"
    }

    [PSCustomObject]@{
        LastInteractiveSignIn    = $null
        LastNonInteractiveSignIn = $null
        LastAnySignIn            = $lastAny
        DaysSinceLastAnySignIn   = $daysSince
        NeverSignedIn            = $isNeverSignedIn
        Inactive                 = $isInactive
        LicenseCount             = $licenseCount
        Flags                    = ($flags -join "; ")
        Risk                     = $risk
        RiskClass                = $riskClass
        RiskOrder                = Get-RiskSortOrder $risk
        SignInConfidence         = $signInConfidence
        ActivityStatus           = $activityStatus
    }
}

function Get-UserRecommendation {
    param([object]$Row)

    if (-not $Row.AccountEnabled -and [int]$Row.LicenseCount -gt 0) {
        return "Review urgently"
    }
    if ($Row.UserType -eq "Guest" -and ($Row.Inactive -eq $true -or $Row.NeverSignedIn -eq $true)) {
        return "Likely removable"
    }
    if ($Row.Inactive -eq $true -or $Row.NeverSignedIn -eq $true) {
        return "Review"
    }
    if (-not $Row.AccountEnabled) {
        return "Review"
    }
    return "Keep"
}

function Get-DeviceRiskData {
    param(
        [object]$Device,
        [int]$InactiveDays
    )

    $lastSeen = $Device.ApproximateLastSignInDateTime
    $daysSince = Get-DaysSince $lastSeen
    $isInactive = $false
    $flags = New-Object System.Collections.Generic.List[string]
    $risk = "OK"
    $riskClass = "ok"

    if ($null -eq $lastSeen) {
        $flags.Add("No last sign-in")
        $risk = "MEDIUM"
        $riskClass = "medium"
    }
    elseif ($daysSince -ge $InactiveDays) {
        $flags.Add("Inactive")
        $risk = "MEDIUM"
        $riskClass = "medium"
        $isInactive = $true
    }

    if (-not $Device.AccountEnabled) {
        $flags.Add("Disabled")
        if ($risk -eq "OK") {
            $risk = "LOW"
            $riskClass = "low"
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$Device.DisplayName)) {
        $flags.Add("Missing display name")
        if ($risk -eq "OK") {
            $risk = "LOW"
            $riskClass = "low"
        }
    }

    $isLegacyOs = Test-IsLegacyOs -OperatingSystem $Device.OperatingSystem -OperatingSystemVersion $Device.OperatingSystemVersion
    if ($isLegacyOs) {
        $flags.Add("Legacy OS")
        if ($risk -eq "OK") {
            $risk = "LOW"
            $riskClass = "low"
        }
    }

    if ($isInactive -and $Device.AccountEnabled -and (-not [bool]$Device.IsManaged)) {
        $flags.Add("Inactive + unmanaged")
        if ($risk -eq "OK" -or $risk -eq "LOW") {
            $risk = "MEDIUM"
            $riskClass = "medium"
        }
    }

    [PSCustomObject]@{
        LastSeen     = $lastSeen
        DaysSince    = $daysSince
        Inactive     = $isInactive
        LegacyOs     = $isLegacyOs
        Flags        = ($flags -join "; ")
        Risk         = $risk
        RiskClass    = $riskClass
        RiskOrder    = Get-RiskSortOrder $risk
    }
}

function Get-DeviceRecommendation {
    param([object]$Row)

    if ($Row.Inactive -eq $true -and $Row.AccountEnabled -eq $true -and $Row.IsManaged -eq $false) {
        return "Likely removable"
    }
    if ($Row.Inactive -eq $true) {
        return "Review"
    }
    if ($Row.LegacyOs -eq $true) {
        return "Review"
    }
    if ($Row.AccountEnabled -eq $false) {
        return "Review"
    }
    return "Keep"
}

function Get-IntuneRiskData {
    param(
        [object]$Device,
        [int]$InactiveDays
    )

    $lastSync = $Device.LastSyncDateTime
    $daysSince = Get-DaysSince $lastSync
    $isInactive = $false
    $flags = New-Object System.Collections.Generic.List[string]
    $risk = "OK"
    $riskClass = "ok"

    if ($null -eq $lastSync) {
        $flags.Add("No sync time")
        $risk = "MEDIUM"
        $riskClass = "medium"
    }
    elseif ($daysSince -ge $InactiveDays) {
        $flags.Add("Inactive")
        $risk = "MEDIUM"
        $riskClass = "medium"
        $isInactive = $true
    }

    if ($Device.ComplianceState -and [string]$Device.ComplianceState -ne "compliant") {
        $flags.Add("Non-compliant")
        if ($risk -ne "HIGH") {
            $risk = "MEDIUM"
            $riskClass = "medium"
        }
    }

    if ($Device.ManagementState -and [string]$Device.ManagementState -match "retire|wipe") {
        $flags.Add("Retire/Wipe state")
        $risk = "HIGH"
        $riskClass = "high"
    }

    [PSCustomObject]@{
        LastSync  = $lastSync
        DaysSince = $daysSince
        Inactive  = $isInactive
        Flags     = ($flags -join "; ")
        Risk      = $risk
        RiskClass = $riskClass
        RiskOrder = Get-RiskSortOrder $risk
    }
}

function Get-IntuneRecommendation {
    param([object]$Row)

    if ($Row.ManagementState -match 'retire|wipe') {
        return "Review urgently"
    }
    if ($Row.ComplianceState -and $Row.ComplianceState -ne "compliant") {
        return "Review"
    }
    if ($Row.Inactive -eq $true) {
        return "Review"
    }
    return "Keep"
}

function Get-CorrelationRecommendation {
    param([object]$Row)

    if ($Row.IssueType -eq "IntuneOnly") { return "Review urgently" }
    if ($Row.MatchType -eq "SoftMatchByName") { return "Needs validation" }
    if ($Row.IssueType -eq "EntraOnly") { return "Review" }
    return "Keep"
}

function Get-DuplicateRecommendation {
    param([object]$Row)

    if ($Row.Count -gt 1) { return "Needs validation" }
    return "Keep"
}

function New-UsersHtmlRows {
    param([object[]]$Rows)

    $sb = New-Object System.Text.StringBuilder

    foreach ($row in $Rows) {
        $riskBadge = Get-RiskBadge -Text $row.Risk -CssClass $row.RiskClass
        $problem = ($row.Risk -ne "OK" -or -not [string]::IsNullOrWhiteSpace([string]$row.Flags))

        $detailObj = [ordered]@{
            Id                       = $row.Id
            DisplayName              = $row.DisplayName
            UserPrincipalName        = $row.UserPrincipalName
            Mail                     = $row.Mail
            AccountEnabled           = $row.AccountEnabled
            UserType                 = $row.UserType
            Department               = $row.Department
            JobTitle                 = $row.JobTitle
            CompanyName              = $row.CompanyName
            OnPremisesSyncEnabled    = $row.OnPremisesSyncEnabled
            CreatedDateTime          = $row.CreatedDateTime
            LicenseCount             = $row.LicenseCount
            LicenseNames             = $row.LicenseNames
            LastInteractiveSignIn    = $row.LastInteractiveSignIn
            LastNonInteractiveSignIn = $row.LastNonInteractiveSignIn
            LastAnySignIn            = $row.LastAnySignIn
            DaysSinceLastAnySignIn   = $row.DaysSinceLastAnySignIn
            NeverSignedIn            = $row.NeverSignedIn
            Inactive                 = $row.Inactive
			Flags                    = $row.Flags
			SignInConfidence         = $row.SignInConfidence
			ActivityStatus           = $row.ActivityStatus
			Recommendation           = $row.Recommendation
			Risk                     = $row.Risk
        }

        [void]$sb.AppendLine(
            "<tr " +
            "data-type='user' " +
            "data-risk='" + (New-SafeHtml $row.Risk) + "' " +
            "data-problem='" + ([string]$problem).ToLower() + "' " +
            "data-inactive='" + ([string]$row.Inactive).ToLower() + "' " +
            "data-disabled='" + ([string](-not $row.AccountEnabled)).ToLower() + "' " +
            "data-never='" + ([string]$row.NeverSignedIn).ToLower() + "' " +
            "data-guest='" + ([string]($row.UserType -eq 'Guest')).ToLower() + "' " +
            "data-hybrid='" + ([string]([bool]$row.OnPremisesSyncEnabled)).ToLower() + "' " +
            "data-disabledlicensed='" + ([string]((-not $row.AccountEnabled) -and ([int]$row.LicenseCount -gt 0))).ToLower() + "' " +
            "data-upn='" + (New-SafeHtml $row.UserPrincipalName) + "' " +
            "data-objectid='" + (New-SafeHtml $row.Id) + "' " +
            "data-flags='" + (New-SafeHtml $row.Flags) + "' " +
            "data-details='" + (Convert-ToJsonHtmlSafe $detailObj) + "'>" +
            "<td>" + (New-SafeHtml $row.DisplayName) + "</td>" +
            "<td>" + (New-SafeHtml $row.UserPrincipalName) + "</td>" +
            "<td>" + (New-SafeHtml $row.UserType) + "</td>" +
            "<td>" + (New-SafeHtml $row.AccountEnabled) + "</td>" +
            "<td>" + (New-SafeHtml $row.LicenseCount) + "</td>" +
            "<td>" + (New-SafeHtml $row.LastAnySignIn) + "</td>" +
            "<td>" + (New-SafeHtml $row.DaysSinceLastAnySignIn) + "</td>" +
            "<td>" + (New-SafeHtml $row.Flags) + "</td>" +
            "<td>" + (New-SafeHtml $row.Recommendation) + "</td>" +
            "<td>" + $riskBadge + "</td>" +
            "<td><button class='btn-detail' type='button'>Details</button></td>" +
            "</tr>"
        )
    }

    return $sb.ToString()
}

function New-DevicesHtmlRows {
    param([object[]]$Rows)

    $sb = New-Object System.Text.StringBuilder

    foreach ($row in $Rows) {
        $riskBadge = Get-RiskBadge -Text $row.Risk -CssClass $row.RiskClass
        $problem = ($row.Risk -ne "OK" -or -not [string]::IsNullOrWhiteSpace([string]$row.Flags))

        $detailObj = [ordered]@{
            Id                     = $row.Id
            DeviceId               = $row.DeviceId
            DisplayName            = $row.DisplayName
            AccountEnabled         = $row.AccountEnabled
            TrustType              = $row.TrustType
            ProfileType            = $row.ProfileType
            IsManaged              = $row.IsManaged
            IsCompliant            = $row.IsCompliant
            OperatingSystem        = $row.OperatingSystem
            OperatingSystemVersion = $row.OperatingSystemVersion
            Manufacturer           = $row.Manufacturer
            Model                  = $row.Model
            CreatedDateTime        = $row.CreatedDateTime
            ApproximateLastSignIn  = $row.ApproximateLastSignIn
            DaysSinceLastSignIn    = $row.DaysSinceLastSignIn
            Inactive               = $row.Inactive
            LegacyOs               = $row.LegacyOs
            Flags                  = $row.Flags
            Recommendation         = $row.Recommendation
            Risk                   = $row.Risk
        }

        [void]$sb.AppendLine(
            "<tr " +
            "data-type='device' " +
            "data-risk='" + (New-SafeHtml $row.Risk) + "' " +
            "data-problem='" + ([string]$problem).ToLower() + "' " +
            "data-inactive='" + ([string]$row.Inactive).ToLower() + "' " +
            "data-disabled='" + ([string](-not $row.AccountEnabled)).ToLower() + "' " +
            "data-legacy='" + ([string]$row.LegacyOs).ToLower() + "' " +
            "data-trusttype='" + (New-SafeHtml $row.TrustType) + "' " +
            "data-deviceid='" + (New-SafeHtml $row.DeviceId) + "' " +
            "data-objectid='" + (New-SafeHtml $row.Id) + "' " +
            "data-flags='" + (New-SafeHtml $row.Flags) + "' " +
            "data-details='" + (Convert-ToJsonHtmlSafe $detailObj) + "'>" +
            "<td>" + (New-SafeHtml $row.DisplayName) + "</td>" +
            "<td>" + (New-SafeHtml $row.OperatingSystem) + "</td>" +
            "<td>" + (New-SafeHtml $row.TrustType) + "</td>" +
            "<td>" + (New-SafeHtml $row.AccountEnabled) + "</td>" +
            "<td>" + (New-SafeHtml $row.IsManaged) + "</td>" +
            "<td>" + (New-SafeHtml $row.IsCompliant) + "</td>" +
            "<td>" + (New-SafeHtml $row.ApproximateLastSignIn) + "</td>" +
            "<td>" + (New-SafeHtml $row.DaysSinceLastSignIn) + "</td>" +
            "<td>" + (New-SafeHtml $row.Flags) + "</td>" +
            "<td>" + (New-SafeHtml $row.Recommendation) + "</td>" +
            "<td>" + $riskBadge + "</td>" +
            "<td><button class='btn-detail' type='button'>Details</button></td>" +
            "</tr>"
        )
    }

    return $sb.ToString()
}

function New-IntuneHtmlRows {
    param([object[]]$Rows)

    $sb = New-Object System.Text.StringBuilder

    foreach ($row in $Rows) {
        $riskBadge = Get-RiskBadge -Text $row.Risk -CssClass $row.RiskClass
        $problem = ($row.Risk -ne "OK" -or -not [string]::IsNullOrWhiteSpace([string]$row.Flags))

        $detailObj = [ordered]@{
            Id                = $row.Id
            AzureADDeviceId   = $row.AzureADDeviceId
            DeviceName        = $row.DeviceName
            UserPrincipalName = $row.UserPrincipalName
            OwnerType         = $row.OwnerType
            ManagementAgent   = $row.ManagementAgent
            ComplianceState   = $row.ComplianceState
            ManagementState   = $row.ManagementState
            OperatingSystem   = $row.OperatingSystem
            OSVersion         = $row.OSVersion
            Manufacturer      = $row.Manufacturer
            Model             = $row.Model
            EnrolledDateTime  = $row.EnrolledDateTime
            LastSyncDateTime  = $row.LastSyncDateTime
            DaysSinceLastSync = $row.DaysSinceLastSync
            Inactive          = $row.Inactive
            Flags             = $row.Flags
            Recommendation    = $row.Recommendation
            Risk              = $row.Risk
        }

        [void]$sb.AppendLine(
            "<tr " +
            "data-type='intune' " +
            "data-risk='" + (New-SafeHtml $row.Risk) + "' " +
            "data-problem='" + ([string]$problem).ToLower() + "' " +
            "data-inactive='" + ([string]$row.Inactive).ToLower() + "' " +
            "data-noncompliant='" + ([string]($row.ComplianceState -ne 'compliant' -and -not [string]::IsNullOrWhiteSpace([string]$row.ComplianceState))).ToLower() + "' " +
            "data-azureaddeviceid='" + (New-SafeHtml $row.AzureADDeviceId) + "' " +
            "data-objectid='" + (New-SafeHtml $row.Id) + "' " +
            "data-upn='" + (New-SafeHtml $row.UserPrincipalName) + "' " +
            "data-flags='" + (New-SafeHtml $row.Flags) + "' " +
            "data-details='" + (Convert-ToJsonHtmlSafe $detailObj) + "'>" +
            "<td>" + (New-SafeHtml $row.DeviceName) + "</td>" +
            "<td>" + (New-SafeHtml $row.UserPrincipalName) + "</td>" +
            "<td>" + (New-SafeHtml $row.OperatingSystem) + "</td>" +
            "<td>" + (New-SafeHtml $row.ComplianceState) + "</td>" +
            "<td>" + (New-SafeHtml $row.ManagementAgent) + "</td>" +
            "<td>" + (New-SafeHtml $row.LastSyncDateTime) + "</td>" +
            "<td>" + (New-SafeHtml $row.DaysSinceLastSync) + "</td>" +
            "<td>" + (New-SafeHtml $row.Flags) + "</td>" +
            "<td>" + (New-SafeHtml $row.Recommendation) + "</td>" +
            "<td>" + $riskBadge + "</td>" +
            "<td><button class='btn-detail' type='button'>Details</button></td>" +
            "</tr>"
        )
    }

    return $sb.ToString()
}

function New-CorrelationHtmlRows {
    param([object[]]$Rows)

    $sb = New-Object System.Text.StringBuilder

    foreach ($row in $Rows) {
        $riskBadge = Get-RiskBadge -Text $row.Risk -CssClass $row.RiskClass
        $problem = ($row.Risk -ne "OK" -or -not [string]::IsNullOrWhiteSpace([string]$row.Flags))

        $detailObj = [ordered]@{
            IssueType        = $row.IssueType
            MatchType        = $row.MatchType
            DisplayName      = $row.DisplayName
            DeviceId         = $row.DeviceId
            AzureADDeviceId  = $row.AzureADDeviceId
            EntraPresent     = $row.EntraPresent
            IntunePresent    = $row.IntunePresent
            EntraLastSignIn  = $row.EntraLastSignIn
            IntuneLastSync   = $row.IntuneLastSync
            Flags            = $row.Flags
            Recommendation   = $row.Recommendation
            Risk             = $row.Risk
        }

        [void]$sb.AppendLine(
            "<tr " +
            "data-type='correlation' " +
            "data-risk='" + (New-SafeHtml $row.Risk) + "' " +
            "data-problem='" + ([string]$problem).ToLower() + "' " +
            "data-issuetype='" + (New-SafeHtml $row.IssueType) + "' " +
            "data-matchtype='" + (New-SafeHtml $row.MatchType) + "' " +
            "data-deviceid='" + (New-SafeHtml $row.DeviceId) + "' " +
            "data-azureaddeviceid='" + (New-SafeHtml $row.AzureADDeviceId) + "' " +
            "data-details='" + (Convert-ToJsonHtmlSafe $detailObj) + "'>" +
            "<td>" + (New-SafeHtml $row.IssueType) + "</td>" +
            "<td>" + (New-SafeHtml $row.MatchType) + "</td>" +
            "<td>" + (New-SafeHtml $row.DisplayName) + "</td>" +
            "<td>" + (New-SafeHtml $row.EntraPresent) + "</td>" +
            "<td>" + (New-SafeHtml $row.IntunePresent) + "</td>" +
            "<td>" + (New-SafeHtml $row.EntraLastSignIn) + "</td>" +
            "<td>" + (New-SafeHtml $row.IntuneLastSync) + "</td>" +
            "<td>" + (New-SafeHtml $row.Flags) + "</td>" +
            "<td>" + (New-SafeHtml $row.Recommendation) + "</td>" +
            "<td>" + $riskBadge + "</td>" +
            "<td><button class='btn-detail' type='button'>Details</button></td>" +
            "</tr>"
        )
    }

    return $sb.ToString()
}

function New-DuplicateHtmlRows {
    param([object[]]$Rows)

    $sb = New-Object System.Text.StringBuilder

    foreach ($row in $Rows) {
        $riskBadge = Get-RiskBadge -Text $row.Risk -CssClass $row.RiskClass
        $problem = ($row.Risk -ne "OK" -or -not [string]::IsNullOrWhiteSpace([string]$row.Flags))

        $detailObj = [ordered]@{
            DuplicateName  = $row.DuplicateName
            Count          = $row.Count
            Source         = $row.Source
            ObjectIds      = $row.ObjectIds
            Flags          = $row.Flags
            Recommendation = $row.Recommendation
            Risk           = $row.Risk
        }

        [void]$sb.AppendLine(
            "<tr " +
            "data-type='duplicate' " +
            "data-risk='" + (New-SafeHtml $row.Risk) + "' " +
            "data-problem='" + ([string]$problem).ToLower() + "' " +
            "data-source='" + (New-SafeHtml $row.Source) + "' " +
            "data-objectids='" + (New-SafeHtml $row.ObjectIds) + "' " +
            "data-details='" + (Convert-ToJsonHtmlSafe $detailObj) + "'>" +
            "<td>" + (New-SafeHtml $row.DuplicateName) + "</td>" +
            "<td>" + (New-SafeHtml $row.Count) + "</td>" +
            "<td>" + (New-SafeHtml $row.Source) + "</td>" +
            "<td>" + (New-SafeHtml $row.Flags) + "</td>" +
            "<td>" + (New-SafeHtml $row.Recommendation) + "</td>" +
            "<td>" + $riskBadge + "</td>" +
            "<td><button class='btn-detail' type='button'>Details</button></td>" +
            "</tr>"
        )
    }

    return $sb.ToString()
}

function New-TopFindingItem {
    param(
        [string]$TabTarget,
        [string]$FilterWrap,
        [string]$Filter,
        [string]$SearchId,
        [string]$Title,
        [string]$Description,
        [string]$Severity
    )

    $severityClass = switch ($Severity) {
        "HIGH"   { "high" }
        "MEDIUM" { "medium" }
        "LOW"    { "low" }
        default  { "ok" }
    }

    return @"
<button class="finding-card" type="button" data-tab-target="$TabTarget" data-filter-wrap="$FilterWrap" data-filter="$Filter" data-search-id="$SearchId">
    <div class="finding-top">
        <span class="badge $severityClass">$Severity</span>
        <span class="finding-title">$(New-SafeHtml $Title)</span>
    </div>
    <div class="finding-desc">$(New-SafeHtml $Description)</div>
</button>
"@
}
function Get-ObjectPropertyValue {
    param(
        [object]$Object,
        [string]$Name
    )

    if ($null -eq $Object) { return $null }

    if ($Object -is [hashtable]) {
        if ($Object.ContainsKey($Name)) {
            return $Object[$Name]
        }
        return $null
    }

    if ($Object.PSObject.Properties.Name -contains $Name) {
        return $Object.$Name
    }

    return $null
}

function Get-AuditLogLastSignInMap {
    param(
        [int]$LookbackDays = 30
    )

    $map = @{}

    try {
        $since = (Get-Date).AddDays(-1 * $LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

        Write-Warning "Trying auditLogs/signIns fallback for last successful sign-ins. Lookback: $LookbackDays day(s)."

        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $since&`$orderby=createdDateTime desc&`$top=1000"

        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $items = @($response.value)

            foreach ($item in $items) {
                $upn = [string](Get-ObjectPropertyValue -Object $item -Name "userPrincipalName")
                if ([string]::IsNullOrWhiteSpace($upn)) {
                    continue
                }

                $status = Get-ObjectPropertyValue -Object $item -Name "status"
                $errorCode = Get-ObjectPropertyValue -Object $status -Name "errorCode"

                # Only successful sign-ins
                if ([string]$errorCode -ne "0") {
                    continue
                }

                $created = Get-ObjectPropertyValue -Object $item -Name "createdDateTime"
                if ([string]::IsNullOrWhiteSpace([string]$created)) {
                    continue
                }

                $key = $upn.Trim().ToLowerInvariant()

                if (-not $map.ContainsKey($key)) {
                    $map[$key] = [PSCustomObject]@{
                        UserPrincipalName = $upn
                        LastSignIn        = $created
                        AppDisplayName    = Get-ObjectPropertyValue -Object $item -Name "appDisplayName"
                        IpAddress         = Get-ObjectPropertyValue -Object $item -Name "ipAddress"
                        Source            = "auditLogs/signIns"
                    }
                }
            }

            $nextLink = $null

            if ($response -is [hashtable]) {
                if ($response.ContainsKey("@odata.nextLink")) {
                    $nextLink = $response["@odata.nextLink"]
                }
            }
            elseif ($response.PSObject.Properties.Name -contains "@odata.nextLink") {
                $nextLink = $response.'@odata.nextLink'
            }

            $uri = $nextLink
        }
        while (-not [string]::IsNullOrWhiteSpace([string]$uri))

        Write-Warning ("auditLogs/signIns fallback collected last successful sign-in for {0} user(s)." -f $map.Count)
    }
    catch {
        Write-Warning "auditLogs/signIns fallback failed."
        Write-Warning $_.Exception.Message
    }

    return $map
}
# ---------------------------------------------------------
# Output folder
# ---------------------------------------------------------
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$usersCsvPath    = Join-Path $OutputFolder ("Entra_Users_" + $timestamp + ".csv")
$devicesCsvPath  = Join-Path $OutputFolder ("Entra_Devices_" + $timestamp + ".csv")
$intuneCsvPath   = Join-Path $OutputFolder ("Intune_Devices_" + $timestamp + ".csv")
$htmlPath        = Join-Path $OutputFolder ("Entra_Audit_Dashboard_" + $timestamp + ".html")
$summaryJsonPath = Join-Path $OutputFolder ("Entra_Audit_Summary_" + $timestamp + ".json")

$reviewDisabledLicensedCsvPath = Join-Path $OutputFolder ("Review_Disabled_Licensed_Users_" + $timestamp + ".csv")
$reviewStaleGuestsCsvPath      = Join-Path $OutputFolder ("Review_Stale_Guests_" + $timestamp + ".csv")
$reviewInactiveDevicesCsvPath  = Join-Path $OutputFolder ("Review_Inactive_Entra_Devices_" + $timestamp + ".csv")
$reviewInactiveIntuneCsvPath   = Join-Path $OutputFolder ("Review_Inactive_Intune_Devices_" + $timestamp + ".csv")
$correlationCsvPath            = Join-Path $OutputFolder ("Review_Correlation_Issues_" + $timestamp + ".csv")
$duplicateDevicesCsvPath       = Join-Path $OutputFolder ("Review_Duplicate_Device_Names_" + $timestamp + ".csv")

$scriptStart = Get-Date

# ---------------------------------------------------------
# Modules / Graph connection
# ---------------------------------------------------------
Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Checking Microsoft Graph modules" -PercentComplete 1
Ensure-GraphModules -IncludeIntune:(-not $SkipIntune)

$requiredScopes = @(
    "User.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "Device.Read.All"
)

if (-not $SkipIntune) {
    $requiredScopes += "DeviceManagementManagedDevices.Read.All"
}

Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Connecting to Microsoft Graph" -PercentComplete 3
Ensure-GraphConnection -Scopes $requiredScopes -UseDeviceAuth:$UseDeviceAuth
Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Connected to Microsoft Graph" -PercentComplete 8

Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Reading subscribed SKUs" -PercentComplete 9
$licenseSkuMap = Get-LicenseSkuMap

# ---------------------------------------------------------
# Collect Entra Users
# ---------------------------------------------------------
Safe-WriteHost "Collecting Entra users..." "Cyan"
Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Fetching Entra users" -PercentComplete 10

[int]$userSignInActivityAvailable = 1
[int]$userAuditLogFallbackUsed = 0
$userSignInActivityError = ""
$userAuditLogFallbackCount = 0
$userAuditLogFallbackMap = @{}
$rawUsers = @()

try {
    $rawUsers = @(
        Get-MgUser -All `
            -Property "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,userType,department,jobTitle,companyName,assignedLicenses,signInActivity,onPremisesSyncEnabled" `
            -ErrorAction Stop
    )
}
catch {
    $userSignInActivityAvailable = 0
    $userAuditLogFallbackUsed = 1
    $userSignInActivityError = $_.Exception.Message

    Write-Warning "User signInActivity property is not available. Falling back to basic user read without signInActivity..."
    Write-Warning "Trying to enrich user last sign-in from auditLogs/signIns instead..."

    $rawUsers = @(
        Get-MgUser -All `
            -Property "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,userType,department,jobTitle,companyName,assignedLicenses,onPremisesSyncEnabled" `
            -ErrorAction Stop
    )

    $userAuditLogFallbackMap = Get-AuditLogLastSignInMap -LookbackDays $SignInLogLookbackDays
    $userAuditLogFallbackCount = $userAuditLogFallbackMap.Count
}
$usersReport = New-Object System.Collections.Generic.List[object]
$userTotal = $rawUsers.Count
$userIndex = 0

foreach ($u in $rawUsers) {
    $userIndex++

    $percent = if ($userTotal -gt 0) { [int](($userIndex / $userTotal) * 100) } else { 100 }
    $statusName = if ([string]::IsNullOrWhiteSpace([string]$u.UserPrincipalName)) { $u.DisplayName } else { $u.UserPrincipalName }

    Update-StepProgress -Id 1 `
        -Activity "Processing Entra users" `
        -Status ("{0}/{1} - {2}" -f $userIndex, $userTotal, $statusName) `
        -PercentComplete $percent

if ($userSignInActivityAvailable -eq 1) {
    $risk = Get-UserRiskData -User $u -InactiveDays $InactiveUserDays
}
else {
    $auditFallback = $null
    $upnKey = ""

    if (-not [string]::IsNullOrWhiteSpace([string]$u.UserPrincipalName)) {
        $upnKey = ([string]$u.UserPrincipalName).Trim().ToLowerInvariant()
    }

    if (-not [string]::IsNullOrWhiteSpace($upnKey) -and $userAuditLogFallbackMap.ContainsKey($upnKey)) {
        $auditFallback = $userAuditLogFallbackMap[$upnKey]
    }

    $risk = Get-UserRiskDataFallback `
        -User $u `
        -AuditLogFallback $auditFallback `
        -InactiveDays $InactiveUserDays
}

    $licenseNames = Get-LicenseNames -AssignedLicenses $u.AssignedLicenses -SkuMap $licenseSkuMap

    $row = [PSCustomObject]@{
        ObjectType                 = "User"
        Id                         = $u.Id
        DisplayName                = $u.DisplayName
        UserPrincipalName          = $u.UserPrincipalName
        Mail                       = $u.Mail
        AccountEnabled             = $u.AccountEnabled
        UserType                   = $u.UserType
        Department                 = $u.Department
        JobTitle                   = $u.JobTitle
        CompanyName                = $u.CompanyName
        OnPremisesSyncEnabled      = [bool]$u.OnPremisesSyncEnabled
        CreatedDateTime            = Format-DateValue $u.CreatedDateTime
        LastInteractiveSignIn      = Format-DateValue $risk.LastInteractiveSignIn
        LastNonInteractiveSignIn   = Format-DateValue $risk.LastNonInteractiveSignIn
        LastAnySignIn              = Format-DateValue $risk.LastAnySignIn
        DaysSinceLastAnySignIn     = $risk.DaysSinceLastAnySignIn
        NeverSignedIn              = $risk.NeverSignedIn
        Inactive                   = $risk.Inactive
        LicenseCount               = $risk.LicenseCount
        LicenseNames               = $licenseNames
        Flags                      = $risk.Flags
		SignInConfidence           = $risk.SignInConfidence
		ActivityStatus             = $risk.ActivityStatus
		Risk                       = $risk.Risk
		RiskClass                  = $risk.RiskClass
		RiskOrder                  = $risk.RiskOrder
		Recommendation             = ""
    }

    $row.Recommendation = Get-UserRecommendation -Row $row
    $usersReport.Add($row) | Out-Null
}

Complete-StepProgress -Id 1 -Activity "Processing Entra users"
Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Exporting Entra users CSV" -PercentComplete 35

$usersReport = @($usersReport | Sort-Object RiskOrder, DisplayName)
$usersReport | Export-Csv -Path $usersCsvPath -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------
# Collect Entra Devices
# ---------------------------------------------------------
Safe-WriteHost "Collecting Entra devices..." "Cyan"
Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Fetching Entra devices" -PercentComplete 40

$rawDevices = @(Get-MgDevice -All -Property "id,deviceId,displayName,accountEnabled,approximateLastSignInDateTime,createdDateTime,operatingSystem,operatingSystemVersion,trustType,profileType,isManaged,isCompliant,manufacturer,model")

$devicesReport = New-Object System.Collections.Generic.List[object]
$deviceTotal = $rawDevices.Count
$deviceIndex = 0

foreach ($d in $rawDevices) {
    $deviceIndex++

    $percent = if ($deviceTotal -gt 0) { [int](($deviceIndex / $deviceTotal) * 100) } else { 100 }
    $statusName = if ([string]::IsNullOrWhiteSpace([string]$d.DisplayName)) { $d.DeviceId } else { $d.DisplayName }

    Update-StepProgress -Id 2 `
        -Activity "Processing Entra devices" `
        -Status ("{0}/{1} - {2}" -f $deviceIndex, $deviceTotal, $statusName) `
        -PercentComplete $percent

    $risk = Get-DeviceRiskData -Device $d -InactiveDays $InactiveDeviceDays

    $row = [PSCustomObject]@{
        ObjectType                 = "EntraDevice"
        Id                         = $d.Id
        DeviceId                   = $d.DeviceId
        DisplayName                = $d.DisplayName
        AccountEnabled             = $d.AccountEnabled
        TrustType                  = $d.TrustType
        ProfileType                = $d.ProfileType
        IsManaged                  = $d.IsManaged
        IsCompliant                = $d.IsCompliant
        OperatingSystem            = $d.OperatingSystem
        OperatingSystemVersion     = $d.OperatingSystemVersion
        Manufacturer               = $d.Manufacturer
        Model                      = $d.Model
        CreatedDateTime            = Format-DateValue $d.CreatedDateTime
        ApproximateLastSignIn      = Format-DateValue $risk.LastSeen
        DaysSinceLastSignIn        = $risk.DaysSince
        Inactive                   = $risk.Inactive
        LegacyOs                   = $risk.LegacyOs
        Flags                      = $risk.Flags
        Risk                       = $risk.Risk
        RiskClass                  = $risk.RiskClass
        RiskOrder                  = $risk.RiskOrder
        Recommendation             = ""
    }

    $row.Recommendation = Get-DeviceRecommendation -Row $row
    $devicesReport.Add($row) | Out-Null
}

Complete-StepProgress -Id 2 -Activity "Processing Entra devices"
Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Exporting Entra devices CSV" -PercentComplete 62

$devicesReport = @($devicesReport | Sort-Object RiskOrder, DisplayName)
$devicesReport | Export-Csv -Path $devicesCsvPath -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------
# Collect Intune devices (best effort)
# ---------------------------------------------------------
[int]$intuneCollectionOk = 0
$intuneErrorText = ""
$intuneReport = @()

if (-not $SkipIntune) {
    try {
        Safe-WriteHost "Collecting Intune managed devices..." "Cyan"
        Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Fetching Intune managed devices" -PercentComplete 68

        $rawIntune = @(Get-MgDeviceManagementManagedDevice -All -Property "id,azureADDeviceId,deviceName,userPrincipalName,managedDeviceOwnerType,managementAgent,complianceState,managementState,lastSyncDateTime,operatingSystem,osVersion,manufacturer,model,enrolledDateTime")

        $intuneReport = New-Object System.Collections.Generic.List[object]
        $intuneTotal = $rawIntune.Count
        $intuneIndex = 0

        foreach ($d in $rawIntune) {
            $intuneIndex++

            $percent = if ($intuneTotal -gt 0) { [int](($intuneIndex / $intuneTotal) * 100) } else { 100 }
            $statusName = if ([string]::IsNullOrWhiteSpace([string]$d.DeviceName)) { $d.Id } else { $d.DeviceName }

            Update-StepProgress -Id 3 `
                -Activity "Processing Intune devices" `
                -Status ("{0}/{1} - {2}" -f $intuneIndex, $intuneTotal, $statusName) `
                -PercentComplete $percent

            $risk = Get-IntuneRiskData -Device $d -InactiveDays $InactiveIntuneDays

            $row = [PSCustomObject]@{
                ObjectType             = "IntuneDevice"
                Id                     = $d.Id
                AzureADDeviceId        = $d.AzureADDeviceId
                DeviceName             = $d.DeviceName
                UserPrincipalName      = $d.UserPrincipalName
                OwnerType              = $d.ManagedDeviceOwnerType
                ManagementAgent        = $d.ManagementAgent
                ComplianceState        = $d.ComplianceState
                ManagementState        = $d.ManagementState
                OperatingSystem        = $d.OperatingSystem
                OSVersion              = $d.OSVersion
                Manufacturer           = $d.Manufacturer
                Model                  = $d.Model
                EnrolledDateTime       = Format-DateValue $d.EnrolledDateTime
                LastSyncDateTime       = Format-DateValue $risk.LastSync
                DaysSinceLastSync      = $risk.DaysSince
                Inactive               = $risk.Inactive
                Flags                  = $risk.Flags
                Risk                   = $risk.Risk
                RiskClass              = $risk.RiskClass
                RiskOrder              = $risk.RiskOrder
                Recommendation         = ""
            }

            $row.Recommendation = Get-IntuneRecommendation -Row $row
            $intuneReport.Add($row) | Out-Null
        }

        Complete-StepProgress -Id 3 -Activity "Processing Intune devices"
        Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Exporting Intune devices CSV" -PercentComplete 82

        $intuneReport = @($intuneReport | Sort-Object RiskOrder, DeviceName)
        $intuneReport | Export-Csv -Path $intuneCsvPath -NoTypeInformation -Encoding UTF8
        $intuneCollectionOk = 1
    }
    catch {
        $intuneCollectionOk = 0
        $intuneErrorText = $_.Exception.Message
        Write-Warning ("Intune data collection failed: " + $intuneErrorText)
    }
}
else {
    Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Skipping Intune collection" -PercentComplete 82
}

# ---------------------------------------------------------
# Correlation / duplicate analysis
# ---------------------------------------------------------
Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Analyzing correlation and duplicates" -PercentComplete 84

$correlationReport = New-Object System.Collections.Generic.List[object]
$duplicateReport   = New-Object System.Collections.Generic.List[object]

$entraByDeviceId = @{}
$entraByName = @{}
foreach ($row in $devicesReport) {
    if (-not [string]::IsNullOrWhiteSpace([string]$row.DeviceId)) {
        $entraByDeviceId[[string]$row.DeviceId] = $row
    }

    $n = Get-NormalizedName $row.DisplayName
    if (-not [string]::IsNullOrWhiteSpace($n)) {
        if (-not $entraByName.ContainsKey($n)) { $entraByName[$n] = @() }
        $entraByName[$n] += $row
    }
}

$intuneByAzureAdDeviceId = @{}
$intuneByName = @{}
foreach ($row in $intuneReport) {
    if (-not [string]::IsNullOrWhiteSpace([string]$row.AzureADDeviceId)) {
        $intuneByAzureAdDeviceId[[string]$row.AzureADDeviceId] = $row
    }

    $n = Get-NormalizedName $row.DeviceName
    if (-not [string]::IsNullOrWhiteSpace($n)) {
        if (-not $intuneByName.ContainsKey($n)) { $intuneByName[$n] = @() }
        $intuneByName[$n] += $row
    }
}

foreach ($row in $devicesReport) {
    $matchType = "NoMatch"
    $matched = $false

    if (-not [string]::IsNullOrWhiteSpace([string]$row.DeviceId) -and $intuneByAzureAdDeviceId.ContainsKey([string]$row.DeviceId)) {
        $matchType = "HardMatchById"
        $matched = $true
    }
    elseif (-not [string]::IsNullOrWhiteSpace((Get-NormalizedName $row.DisplayName)) -and $intuneByName.ContainsKey((Get-NormalizedName $row.DisplayName))) {
        $matchType = "SoftMatchByName"
        $matched = $true
    }

    if (-not $matched) {
        $corrRow = [PSCustomObject]@{
            IssueType       = "EntraOnly"
            MatchType       = "NoMatch"
            DisplayName     = $row.DisplayName
            DeviceId        = $row.DeviceId
            AzureADDeviceId = ""
            EntraPresent    = $true
            IntunePresent   = $false
            EntraLastSignIn = $row.ApproximateLastSignIn
            IntuneLastSync  = ""
            Flags           = "Present in Entra only"
            Recommendation  = ""
            Risk            = "MEDIUM"
            RiskClass       = "medium"
            RiskOrder       = Get-RiskSortOrder "MEDIUM"
        }
        $corrRow.Recommendation = Get-CorrelationRecommendation -Row $corrRow
        $correlationReport.Add($corrRow) | Out-Null
    }
    elseif ($matchType -eq "SoftMatchByName") {
        $corrRow = [PSCustomObject]@{
            IssueType       = "Matched"
            MatchType       = "SoftMatchByName"
            DisplayName     = $row.DisplayName
            DeviceId        = $row.DeviceId
            AzureADDeviceId = ""
            EntraPresent    = $true
            IntunePresent   = $true
            EntraLastSignIn = $row.ApproximateLastSignIn
            IntuneLastSync  = ($intuneByName[(Get-NormalizedName $row.DisplayName)][0].LastSyncDateTime)
            Flags           = "Matched by normalized device name only - verify"
            Recommendation  = ""
            Risk            = "LOW"
            RiskClass       = "low"
            RiskOrder       = Get-RiskSortOrder "LOW"
        }
        $corrRow.Recommendation = Get-CorrelationRecommendation -Row $corrRow
        $correlationReport.Add($corrRow) | Out-Null
    }
}

foreach ($row in $intuneReport) {
    $matchType = "NoMatch"
    $matched = $false

    if (-not [string]::IsNullOrWhiteSpace([string]$row.AzureADDeviceId) -and $entraByDeviceId.ContainsKey([string]$row.AzureADDeviceId)) {
        $matchType = "HardMatchById"
        $matched = $true
    }
    elseif (-not [string]::IsNullOrWhiteSpace((Get-NormalizedName $row.DeviceName)) -and $entraByName.ContainsKey((Get-NormalizedName $row.DeviceName))) {
        $matchType = "SoftMatchByName"
        $matched = $true
    }

    if (-not $matched) {
        $corrRow = [PSCustomObject]@{
            IssueType       = "IntuneOnly"
            MatchType       = "NoMatch"
            DisplayName     = $row.DeviceName
            DeviceId        = ""
            AzureADDeviceId = $row.AzureADDeviceId
            EntraPresent    = $false
            IntunePresent   = $true
            EntraLastSignIn = ""
            IntuneLastSync  = $row.LastSyncDateTime
            Flags           = "Present in Intune only"
            Recommendation  = ""
            Risk            = "HIGH"
            RiskClass       = "high"
            RiskOrder       = Get-RiskSortOrder "HIGH"
        }
        $corrRow.Recommendation = Get-CorrelationRecommendation -Row $corrRow
        $correlationReport.Add($corrRow) | Out-Null
    }
}

foreach ($key in $entraByName.Keys) {
    $items = @($entraByName[$key])
    if ($items.Count -gt 1) {
        $dupRow = [PSCustomObject]@{
            DuplicateName  = $items[0].DisplayName
            Count          = $items.Count
            Source         = "Entra"
            ObjectIds      = (($items | ForEach-Object { $_.Id }) -join "; ")
            Flags          = "Duplicate display name in Entra"
            Recommendation = ""
            Risk           = "MEDIUM"
            RiskClass      = "medium"
            RiskOrder      = Get-RiskSortOrder "MEDIUM"
        }
        $dupRow.Recommendation = Get-DuplicateRecommendation -Row $dupRow
        $duplicateReport.Add($dupRow) | Out-Null
    }
}

foreach ($key in $intuneByName.Keys) {
    $items = @($intuneByName[$key])
    if ($items.Count -gt 1) {
        $dupRow = [PSCustomObject]@{
            DuplicateName  = $items[0].DeviceName
            Count          = $items.Count
            Source         = "Intune"
            ObjectIds      = (($items | ForEach-Object { $_.Id }) -join "; ")
            Flags          = "Duplicate device name in Intune"
            Recommendation = ""
            Risk           = "MEDIUM"
            RiskClass      = "medium"
            RiskOrder      = Get-RiskSortOrder "MEDIUM"
        }
        $dupRow.Recommendation = Get-DuplicateRecommendation -Row $dupRow
        $duplicateReport.Add($dupRow) | Out-Null
    }
}

$correlationReport = @($correlationReport | Sort-Object RiskOrder, IssueType, DisplayName)
$duplicateReport   = @($duplicateReport   | Sort-Object RiskOrder, Source, DuplicateName)

$correlationReport | Export-Csv -Path $correlationCsvPath -NoTypeInformation -Encoding UTF8
$duplicateReport   | Export-Csv -Path $duplicateDevicesCsvPath -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------
# Summary
# ---------------------------------------------------------
Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Building summary" -PercentComplete 86

$totalUsers = @($usersReport).Count
$usersHigh = @($usersReport | Where-Object { $_.Risk -eq "HIGH" }).Count
$usersMedium = @($usersReport | Where-Object { $_.Risk -eq "MEDIUM" }).Count
$usersDisabled = @($usersReport | Where-Object { $_.AccountEnabled -eq $false }).Count
$usersInactive = @($usersReport | Where-Object { $_.Inactive -eq $true }).Count
$usersNever = @($usersReport | Where-Object { $_.NeverSignedIn -eq $true }).Count
$usersGuests = @($usersReport | Where-Object { $_.UserType -eq "Guest" }).Count
$usersDisabledLicensed = @($usersReport | Where-Object { $_.AccountEnabled -eq $false -and [int]$_.LicenseCount -gt 0 }).Count
$usersHybridSynced = @($usersReport | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count

$totalDevices = @($devicesReport).Count
$devicesHigh = @($devicesReport | Where-Object { $_.Risk -eq "HIGH" }).Count
$devicesMedium = @($devicesReport | Where-Object { $_.Risk -eq "MEDIUM" }).Count
$devicesDisabled = @($devicesReport | Where-Object { $_.AccountEnabled -eq $false }).Count
$devicesInactive = @($devicesReport | Where-Object { $_.Inactive -eq $true }).Count
$devicesNoLast = @($devicesReport | Where-Object { [string]::IsNullOrWhiteSpace($_.ApproximateLastSignIn) }).Count
$devicesLegacyOs = @($devicesReport | Where-Object { $_.LegacyOs -eq $true }).Count
$devicesAzureAdJoined = @($devicesReport | Where-Object { $_.TrustType -eq "AzureAd" }).Count
$devicesHybridJoined  = @($devicesReport | Where-Object { $_.TrustType -eq "ServerAd" }).Count
$devicesRegistered    = @($devicesReport | Where-Object { $_.TrustType -eq "Workplace" }).Count

$totalIntune = @($intuneReport).Count
$intuneHigh = @($intuneReport | Where-Object { $_.Risk -eq "HIGH" }).Count
$intuneMedium = @($intuneReport | Where-Object { $_.Risk -eq "MEDIUM" }).Count
$intuneInactive = @($intuneReport | Where-Object { $_.Inactive -eq $true }).Count
$intuneNonCompliant = @($intuneReport | Where-Object { $_.ComplianceState -ne "compliant" -and -not [string]::IsNullOrWhiteSpace([string]$_.ComplianceState) }).Count

$correlationIssues = @($correlationReport).Count
$correlationSoftMatches = @($correlationReport | Where-Object { $_.MatchType -eq "SoftMatchByName" }).Count
$duplicateDeviceNames = @($duplicateReport).Count

$durationSeconds = [math]::Round(((Get-Date) - $scriptStart).TotalSeconds, 1)

$summary = [PSCustomObject]@{
    ScriptVersion               = $ScriptVersion
    RunMode                     = $RunMode
    GeneratedAt                 = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    TenantId                    = (Get-MgContext).TenantId
    InactiveUserDays            = $InactiveUserDays
    InactiveDeviceDays          = $InactiveDeviceDays
    InactiveIntuneDays          = $InactiveIntuneDays
    DurationSeconds             = $durationSeconds
    UserSignInActivityAvailable = [bool]$userSignInActivityAvailable
    UserSignInActivityError     = $userSignInActivityError
	UserAuditLogFallbackUsed    = [bool]$userAuditLogFallbackUsed
	UserAuditLogFallbackDays    = $SignInLogLookbackDays
	UserAuditLogFallbackCount   = $userAuditLogFallbackCount

    TotalUsers             = $totalUsers
    UsersHigh              = $usersHigh
    UsersMedium            = $usersMedium
    UsersDisabled          = $usersDisabled
    UsersInactive          = $usersInactive
    UsersNeverSignedIn     = $usersNever
    UsersGuests            = $usersGuests
    UsersDisabledLicensed  = $usersDisabledLicensed
    UsersHybridSynced      = $usersHybridSynced

    TotalDevices           = $totalDevices
    DevicesHigh            = $devicesHigh
    DevicesMedium          = $devicesMedium
    DevicesDisabled        = $devicesDisabled
    DevicesInactive        = $devicesInactive
    DevicesNoLastSignIn    = $devicesNoLast
    DevicesLegacyOs        = $devicesLegacyOs
    DevicesAzureAdJoined   = $devicesAzureAdJoined
    DevicesHybridJoined    = $devicesHybridJoined
    DevicesRegistered      = $devicesRegistered

    IntuneCollectionOk     = [bool]$intuneCollectionOk
    TotalIntune            = $totalIntune
    IntuneHigh             = $intuneHigh
    IntuneMedium           = $intuneMedium
    IntuneInactive         = $intuneInactive
    IntuneNonCompliant     = $intuneNonCompliant
    IntuneError            = $intuneErrorText

    CorrelationIssues      = $correlationIssues
    CorrelationSoftMatches = $correlationSoftMatches
    DuplicateDeviceNames   = $duplicateDeviceNames

    UsersCsv                  = $usersCsvPath
    DevicesCsv                = $devicesCsvPath
    IntuneCsv                 = $intuneCsvPath
    ReviewDisabledLicensedCsv = $reviewDisabledLicensedCsvPath
    ReviewStaleGuestsCsv      = $reviewStaleGuestsCsvPath
    ReviewInactiveDevicesCsv  = $reviewInactiveDevicesCsvPath
    ReviewInactiveIntuneCsv   = $reviewInactiveIntuneCsvPath
    CorrelationCsv            = $correlationCsvPath
    DuplicateDevicesCsv       = $duplicateDevicesCsvPath
    HtmlReport                = $htmlPath
}

# ---------------------------------------------------------
# Review candidate CSVs
# ---------------------------------------------------------
$reviewDisabledLicensed = @($usersReport | Where-Object { $_.AccountEnabled -eq $false -and [int]$_.LicenseCount -gt 0 })

if ($userSignInActivityAvailable -eq 1) {
    $reviewStaleGuests = @(
        $usersReport | Where-Object {
            $_.UserType -eq "Guest" -and
            ($_.Inactive -eq $true -or $_.NeverSignedIn -eq $true)
        }
    )
}
else {
    $reviewStaleGuests = @(
        $usersReport | Where-Object {
            $_.UserType -eq "Guest" -and
            (
                $_.Inactive -eq $true -or
                $_.ActivityStatus -eq "UnknownDueToSignInActivityUnavailable" -or
                $_.Flags -match "No successful sign-in found"
            )
        }
    )
}

$reviewInactiveDevices  = @($devicesReport | Where-Object { $_.Inactive -eq $true })
$reviewInactiveIntune   = @($intuneReport | Where-Object { $_.Inactive -eq $true })

$reviewDisabledLicensed | Export-Csv -Path $reviewDisabledLicensedCsvPath -NoTypeInformation -Encoding UTF8
$reviewStaleGuests      | Export-Csv -Path $reviewStaleGuestsCsvPath      -NoTypeInformation -Encoding UTF8
$reviewInactiveDevices  | Export-Csv -Path $reviewInactiveDevicesCsvPath  -NoTypeInformation -Encoding UTF8
$reviewInactiveIntune   | Export-Csv -Path $reviewInactiveIntuneCsvPath   -NoTypeInformation -Encoding UTF8

Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Writing summary JSON" -PercentComplete 89
$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryJsonPath -Encoding UTF8

# ---------------------------------------------------------
# HTML data rows
# ---------------------------------------------------------
Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Building HTML rows" -PercentComplete 91

$usersRowsHtml = New-UsersHtmlRows -Rows $usersReport
$devicesRowsHtml = New-DevicesHtmlRows -Rows $devicesReport
$intuneRowsHtml = New-IntuneHtmlRows -Rows $intuneReport
$correlationRowsHtml = New-CorrelationHtmlRows -Rows $correlationReport
$duplicateRowsHtml   = New-DuplicateHtmlRows -Rows $duplicateReport

# ---------------------------------------------------------
# Top Findings
# ---------------------------------------------------------
$findings = New-Object System.Collections.Generic.List[string]

if ($userSignInActivityAvailable -eq 0) {
    $findings.Add((New-TopFindingItem `
        -TabTarget "usersTab" `
        -FilterWrap "usersFilters" `
        -Filter "all" `
        -SearchId "usersSearch" `
        -Title "User signInActivity unavailable" `
        -Description "user.signInActivity could not be read. Last sign-in is enriched from auditLogs/signIns where available. Inactivity and never-signed-in logic are limited by log retention/lookback." `
        -Severity "MEDIUM")) | Out-Null
}

if ($usersDisabledLicensed -gt 0) {
    $findings.Add((New-TopFindingItem -TabTarget "usersTab" -FilterWrap "usersFilters" -Filter "disabledlicensed" -SearchId "usersSearch" -Title "Disabled + licensed users" -Description "$usersDisabledLicensed user(s) still disabled but consuming license(s)." -Severity "HIGH")) | Out-Null
}

if ($userSignInActivityAvailable -eq 1) {
    $staleGuests = @(
        $usersReport | Where-Object {
            $_.UserType -eq "Guest" -and
            ($_.Inactive -eq $true -or $_.NeverSignedIn -eq $true)
        }
    ).Count
}
else {
    $staleGuests = @(
        $usersReport | Where-Object {
            $_.UserType -eq "Guest" -and
            (
                $_.Inactive -eq $true -or
                $_.ActivityStatus -eq "UnknownDueToSignInActivityUnavailable" -or
                $_.Flags -match "No successful sign-in found"
            )
        }
    ).Count
}
if ($staleGuests -gt 0) {
    $findings.Add((New-TopFindingItem -TabTarget "usersTab" -FilterWrap "usersFilters" -Filter "guest" -SearchId "usersSearch" -Title "Stale guest users" -Description "$staleGuests guest account(s) look stale or unused." -Severity "MEDIUM")) | Out-Null
}

if ($usersInactive -gt 0) {
    $findings.Add((New-TopFindingItem -TabTarget "usersTab" -FilterWrap "usersFilters" -Filter "inactive" -SearchId "usersSearch" -Title "Inactive users" -Description "$usersInactive user(s) exceeded the inactivity threshold." -Severity "MEDIUM")) | Out-Null
}

if ($devicesInactive -gt 0) {
    $findings.Add((New-TopFindingItem -TabTarget "devicesTab" -FilterWrap "devicesFilters" -Filter "inactive" -SearchId "devicesSearch" -Title "Inactive Entra devices" -Description "$devicesInactive device(s) exceeded the inactivity threshold." -Severity "MEDIUM")) | Out-Null
}

if ($devicesLegacyOs -gt 0) {
    $findings.Add((New-TopFindingItem -TabTarget "devicesTab" -FilterWrap "devicesFilters" -Filter "legacy" -SearchId "devicesSearch" -Title "Legacy OS devices" -Description "$devicesLegacyOs device(s) appear to have a legacy operating system." -Severity "LOW")) | Out-Null
}

if ($intuneNonCompliant -gt 0) {
    $findings.Add((New-TopFindingItem -TabTarget "intuneTab" -FilterWrap "intuneFilters" -Filter "noncompliant" -SearchId "intuneSearch" -Title "Non-compliant Intune devices" -Description "$intuneNonCompliant Intune device(s) are non-compliant." -Severity "HIGH")) | Out-Null
}

if ($correlationIssues -gt 0) {
    $findings.Add((New-TopFindingItem -TabTarget "correlationTab" -FilterWrap "correlationFilters" -Filter "all" -SearchId "correlationSearch" -Title "Correlation issues" -Description "$correlationIssues correlation row(s) generated across Entra and Intune." -Severity "HIGH")) | Out-Null
}

if ($correlationSoftMatches -gt 0) {
    $findings.Add((New-TopFindingItem -TabTarget "correlationTab" -FilterWrap "correlationFilters" -Filter "softmatch" -SearchId "correlationSearch" -Title "Soft name matches" -Description "$correlationSoftMatches device match(es) were inferred only by normalized device name." -Severity "LOW")) | Out-Null
}

if ($duplicateDeviceNames -gt 0) {
    $findings.Add((New-TopFindingItem -TabTarget "duplicatesTab" -FilterWrap "duplicatesFilters" -Filter "all" -SearchId "duplicatesSearch" -Title "Duplicate device names" -Description "$duplicateDeviceNames duplicate device-name grouping(s) detected." -Severity "MEDIUM")) | Out-Null
}

if ($findings.Count -eq 0) {
    $findings.Add((New-TopFindingItem -TabTarget "usersTab" -FilterWrap "usersFilters" -Filter "all" -SearchId "usersSearch" -Title "No major findings" -Description "Nothing obvious was flagged by the current threshold logic." -Severity "OK")) | Out-Null
}

$findingsHtml = ($findings -join [Environment]::NewLine)

# ---------------------------------------------------------
# HTML
# ---------------------------------------------------------
$tenantIdSafe = New-SafeHtml ((Get-MgContext).TenantId)
$generatedSafe = New-SafeHtml $summary.GeneratedAt
$usersCsvSafe = New-SafeHtml $usersCsvPath
$devicesCsvSafe = New-SafeHtml $devicesCsvPath
$intuneCsvSafe = New-SafeHtml $intuneCsvPath
$intuneErrorSafe = New-SafeHtml $intuneErrorText
$userSignInActivityErrorSafe = New-SafeHtml $userSignInActivityError
$summaryJsonSafe = New-SafeHtml $summaryJsonPath
$durationSafe = New-SafeHtml $durationSeconds
$reviewDisabledLicensedCsvSafe = New-SafeHtml $reviewDisabledLicensedCsvPath
$reviewStaleGuestsCsvSafe = New-SafeHtml $reviewStaleGuestsCsvPath
$reviewInactiveDevicesCsvSafe = New-SafeHtml $reviewInactiveDevicesCsvPath
$reviewInactiveIntuneCsvSafe = New-SafeHtml $reviewInactiveIntuneCsvPath
$correlationCsvSafe = New-SafeHtml $correlationCsvPath
$duplicateDevicesCsvSafe = New-SafeHtml $duplicateDevicesCsvPath
$scriptVersionSafe = New-SafeHtml $ScriptVersion
$runModeSafe = New-SafeHtml $RunMode

$correlationEntraOnly = @($correlationReport | Where-Object { $_.IssueType -eq 'EntraOnly' }).Count
$correlationIntuneOnly = @($correlationReport | Where-Object { $_.IssueType -eq 'IntuneOnly' }).Count
$duplicateEntraCount = @($duplicateReport | Where-Object { $_.Source -eq 'Entra' }).Count
$duplicateIntuneCount = @($duplicateReport | Where-Object { $_.Source -eq 'Intune' }).Count

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Entra Audit Dashboard v$scriptVersionSafe</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{
    --bg:#f7f9fc;--card:#ffffff;--line:#dbe2ea;--line2:#e8edf3;--text:#1f2937;--muted:#6b7280;
    --accent:#2563eb;--accent-soft:#eff6ff;--ok-bg:#e8f7ee;--ok-fg:#166534;--low-bg:#eaf2ff;
    --low-fg:#1d4ed8;--medium-bg:#fff7e6;--medium-fg:#92400e;--high-bg:#fee2e2;--high-fg:#991b1b;
    --btn:#ffffff;--btn-active:#e8f0ff;--shadow:0 1px 2px rgba(0,0,0,.04)
}
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text)}
.wrap{max-width:1900px;margin:0 auto;padding:20px}
h1,h2,h3{margin:0 0 10px 0}.muted{color:var(--muted)}
.box{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;box-shadow:var(--shadow);margin-bottom:18px}
.topbar{display:flex;flex-wrap:wrap;justify-content:space-between;gap:16px;align-items:flex-start}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:16px 0 18px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;box-shadow:var(--shadow)}
.action-card{appearance:none;width:100%;text-align:left;cursor:pointer;transition:transform .12s ease,border-color .12s ease,background .12s ease,box-shadow .12s ease;color:var(--text)}
.action-card:hover,.finding-card:hover{transform:translateY(-1px);border-color:#bfd2f5;background:#fafcff}
.action-card:focus{outline:2px solid var(--accent);outline-offset:2px}
.action-card.active-card,.finding-card.active-card{border-color:var(--accent);background:var(--accent-soft);box-shadow:0 0 0 1px rgba(37,99,235,.08)}
.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.card .value{font-size:28px;font-weight:700;margin-top:6px;color:#111827}
.findings-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:8px}
.finding-card{appearance:none;width:100%;text-align:left;background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:14px;cursor:pointer;transition:transform .12s ease,border-color .12s ease,background .12s ease}
.finding-top{display:flex;gap:10px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
.finding-title{font-weight:700}
.finding-desc{color:var(--muted);font-size:14px;line-height:1.45}
.tabs{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.tab-btn{background:var(--btn);color:var(--text);border:1px solid var(--line);border-radius:999px;padding:10px 14px;cursor:pointer;font-weight:600}
.tab-btn.active{background:var(--accent-soft);color:#11307a;border-color:#bfd2f5}
.tab-content{display:none}.tab-content.active{display:block}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.filter-btn{background:var(--btn);border:1px solid var(--line);color:var(--text);border-radius:999px;padding:8px 12px;cursor:pointer}
.filter-btn.active{background:var(--btn-active);border-color:#bfd2f5;color:#11307a;font-weight:600}
.search-row{display:flex;flex-wrap:wrap;gap:10px;margin:10px 0 10px 0;align-items:center}
.search-row input,.search-row select{background:#fff;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:14px}
.search-row input{flex:1 1 280px;min-width:260px}
.search-row .page-size-wrap{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:14px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:6px 10px}
.search-row .page-size-wrap select{border:none;padding:4px 6px;background:transparent;min-width:70px}
.search-row .page-size-wrap select:focus,.search-row input:focus,.search-row select:focus{outline:none}
.export-btn,.pager-btn,.copy-btn{background:#fff;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:10px 12px;cursor:pointer;font-weight:600}
.export-btn:hover,.pager-btn:hover,.copy-btn:hover{border-color:#bfd2f5;background:#fafcff}
.pager-btn[disabled]{opacity:.5;cursor:not-allowed;background:#f8fafc}
.mini-stats{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px 0}
.mini-stat{background:#fff;border:1px solid var(--line);border-radius:999px;padding:7px 11px;color:var(--muted);font-size:13px}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px;background:#fff}
table{width:100%;border-collapse:collapse;min-width:1200px;background:#fff}
th,td{padding:10px 12px;border-bottom:1px solid var(--line2);text-align:left;vertical-align:top;font-size:14px}
th{position:sticky;top:0;z-index:2;background:#f9fafb;cursor:pointer;user-select:none;color:#111827}
tr:hover td{background:#fafcff}
tr.row-risk-high td{background:#fff8f8}
tr.row-risk-medium td{background:#fffdf7}
tr.row-risk-low td{background:#f8fbff}
.badge{display:inline-block;border-radius:999px;padding:4px 9px;font-size:12px;font-weight:700;border:1px solid transparent}
.badge.ok{background:var(--ok-bg);color:var(--ok-fg);border-color:#b7e4c7}
.badge.low{background:var(--low-bg);color:var(--low-fg);border-color:#c8d9ff}
.badge.medium{background:var(--medium-bg);color:var(--medium-fg);border-color:#f4d9a7}
.badge.high{background:var(--high-bg);color:var(--high-fg);border-color:#f3b8b8}
.btn-detail{background:#fff;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:7px 10px;cursor:pointer;font-size:13px;font-weight:600}
.btn-detail:hover{border-color:#bfd2f5;background:#fafcff}
.foot{margin-top:18px;color:var(--muted);font-size:13px}
.modal{position:fixed;inset:0;background:rgba(15,23,42,.45);display:none;align-items:center;justify-content:center;padding:20px;z-index:9999}
.modal.open{display:flex}
.modal-card{width:min(900px,95vw);max-height:85vh;overflow:auto;background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 20px 50px rgba(15,23,42,.18)}
.modal-top{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px}
.close-btn{background:#fff;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:8px 12px;cursor:pointer;font-weight:600}
.close-btn:hover{border-color:#bfd2f5;background:#fafcff}
.kv{display:grid;grid-template-columns:260px 1fr;gap:8px 14px;margin-top:8px}
.kv .k{color:var(--muted);font-weight:600}
.notice{background:#fff8f8;border:1px solid #f2c7c7;border-radius:10px;padding:14px;margin-bottom:14px;line-height:1.5;color:#7f1d1d}
.hidden-row{display:none !important}
.pagination-row{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;margin-top:10px}
.pager-left,.pager-right{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.pager-info{color:var(--muted);font-size:13px}
.sort-indicator{color:#9ca3af;font-size:11px;margin-left:6px}
@media (max-width:900px){.kv{grid-template-columns:1fr}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:640px){.cards{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">

    <div class="topbar box">
        <div>
            <h1>Entra Audit Dashboard v$scriptVersionSafe</h1>
            <div class="muted">Read-only cloud audit for users, devices and cleanup-review candidates.</div>
        </div>
        <div class="muted">
            <div><strong>Generated:</strong> $generatedSafe</div>
            <div><strong>Tenant:</strong> $tenantIdSafe</div>
            <div><strong>Duration:</strong> $durationSafe sec</div>
            <div><strong>Version:</strong> $scriptVersionSafe</div>
            <div><strong>Run mode:</strong> $runModeSafe</div>
            <div><strong>User inactivity threshold:</strong> $InactiveUserDays days</div>
            <div><strong>Device inactivity threshold:</strong> $InactiveDeviceDays days</div>
            <div><strong>Intune inactivity threshold:</strong> $InactiveIntuneDays days</div>
			<div><strong>Sign-in log fallback lookback:</strong> $SignInLogLookbackDays days</div>
        </div>
    </div>

    <div class="cards">
        <button class="card action-card" type="button" data-tab-target="usersTab" data-filter-wrap="usersFilters" data-filter="all" data-search-id="usersSearch">
            <div class="label">Users</div><div class="value">$totalUsers</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="usersTab" data-filter-wrap="usersFilters" data-filter="problems" data-search-id="usersSearch">
            <div class="label">User problems</div><div class="value">$($usersHigh + $usersMedium)</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="usersTab" data-filter-wrap="usersFilters" data-filter="disabledlicensed" data-search-id="usersSearch">
            <div class="label">Disabled + licensed</div><div class="value">$usersDisabledLicensed</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="devicesTab" data-filter-wrap="devicesFilters" data-filter="problems" data-search-id="devicesSearch">
            <div class="label">Device problems</div><div class="value">$($devicesHigh + $devicesMedium + $devicesLegacyOs)</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="devicesTab" data-filter-wrap="devicesFilters" data-filter="inactive" data-search-id="devicesSearch">
            <div class="label">Inactive devices</div><div class="value">$devicesInactive</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="devicesTab" data-filter-wrap="devicesFilters" data-filter="legacy" data-search-id="devicesSearch">
            <div class="label">Legacy OS</div><div class="value">$devicesLegacyOs</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="intuneTab" data-filter-wrap="intuneFilters" data-filter="problems" data-search-id="intuneSearch">
            <div class="label">Intune problems</div><div class="value">$($intuneHigh + $intuneMedium)</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="intuneTab" data-filter-wrap="intuneFilters" data-filter="noncompliant" data-search-id="intuneSearch">
            <div class="label">Non-compliant Intune</div><div class="value">$intuneNonCompliant</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="correlationTab" data-filter-wrap="correlationFilters" data-filter="all" data-search-id="correlationSearch">
            <div class="label">Correlation issues</div><div class="value">$correlationIssues</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="correlationTab" data-filter-wrap="correlationFilters" data-filter="softmatch" data-search-id="correlationSearch">
            <div class="label">Soft matches</div><div class="value">$correlationSoftMatches</div>
        </button>
        <button class="card action-card" type="button" data-tab-target="duplicatesTab" data-filter-wrap="duplicatesFilters" data-filter="all" data-search-id="duplicatesSearch">
            <div class="label">Duplicate device names</div><div class="value">$duplicateDeviceNames</div>
        </button>
    </div>

    <div class="box">
        <h2>Top Findings</h2>
        <div class="muted">Klikkaa löytöä siirtyäksesi suoraan oikeaan tabiin ja filtteriin.</div>
        <div class="findings-grid">
            $findingsHtml
        </div>
    </div>

    <div class="box">
        <div class="tabs">
            <button class="tab-btn active" data-tab="usersTab">Users</button>
            <button class="tab-btn" data-tab="devicesTab">Entra Devices</button>
            <button class="tab-btn" data-tab="intuneTab">Intune Devices</button>
            <button class="tab-btn" data-tab="correlationTab">Correlation</button>
            <button class="tab-btn" data-tab="duplicatesTab">Duplicates</button>
        </div>

        <div id="usersTab" class="tab-content active">
            <h2>Users</h2>
            $(if ($userSignInActivityAvailable -eq 0) { "<div class='notice'><strong>User signInActivity property unavailable.</strong><br>" + $userSignInActivityErrorSafe + "<br><br><strong>Fallback:</strong> Last sign-in values are enriched from auditLogs/signIns where available. Lookback: $SignInLogLookbackDays day(s). Matched users: $userAuditLogFallbackCount. Inactivity and never-signed-in findings are limited by log retention/lookback.</div>" } else { "" })
            <div class="mini-stats">
                <div class="mini-stat">Total: $totalUsers</div>
                <div class="mini-stat">Disabled: $usersDisabled</div>
                <div class="mini-stat">Inactive: $usersInactive</div>
                <div class="mini-stat">Never signed in: $usersNever</div>
                <div class="mini-stat">Guests: $usersGuests</div>
                <div class="mini-stat">Hybrid synced: $usersHybridSynced</div>
                <div class="mini-stat">Disabled + licensed: $usersDisabledLicensed</div>
            </div>
            <div class="filters" id="usersFilters">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="problems">Problems only</button>
                <button class="filter-btn" data-filter="high">HIGH</button>
                <button class="filter-btn" data-filter="medium">MEDIUM</button>
                <button class="filter-btn" data-filter="inactive">Inactive</button>
                <button class="filter-btn" data-filter="disabled">Disabled</button>
                <button class="filter-btn" data-filter="disabledlicensed">Disabled + licensed</button>
                <button class="filter-btn" data-filter="never">Never signed in</button>
                <button class="filter-btn" data-filter="guest">Guests</button>
                <button class="filter-btn" data-filter="hybrid">Hybrid synced</button>
            </div>
            <div class="search-row">
                <input type="text" id="usersSearch" placeholder="Search users...">
                <div class="page-size-wrap"><span>Rows/page</span><select id="usersPageSize"><option value="10">10</option><option value="25" selected>25</option><option value="50">50</option><option value="100">100</option><option value="250">250</option><option value="999999">All</option></select></div>
                <button class="export-btn" type="button" data-export-table="usersTable" data-export-name="visible_users.csv">Export visible Users</button>
                <button class="copy-btn" type="button" data-copy-table="usersTable" data-copy-attr="upn">Copy visible UPNs</button>
                <button class="copy-btn" type="button" data-copy-table="usersTable" data-copy-attr="objectid">Copy visible ObjectIds</button>
                <div class="muted" id="usersVisibleCount"></div>
            </div>
            <div class="table-wrap">
                <table id="usersTable">
                    <thead><tr><th>Name</th><th>UPN</th><th>Type</th><th>Enabled</th><th>Licenses</th><th>Last sign-in</th><th>Days</th><th>Flags</th><th>Recommendation</th><th>Risk</th><th>Details</th></tr></thead>
                    <tbody>$usersRowsHtml</tbody>
                </table>
            </div>
            <div class="pagination-row"><div class="pager-left"><button class="pager-btn" id="usersPrevBtn" type="button">Previous</button><button class="pager-btn" id="usersNextBtn" type="button">Next</button></div><div class="pager-right"><div class="pager-info" id="usersPageInfo"></div></div></div>
        </div>

        <div id="devicesTab" class="tab-content">
            <h2>Entra Devices</h2>
            <div class="mini-stats">
                <div class="mini-stat">Total: $totalDevices</div>
                <div class="mini-stat">Disabled: $devicesDisabled</div>
                <div class="mini-stat">Inactive: $devicesInactive</div>
                <div class="mini-stat">No last sign-in: $devicesNoLast</div>
                <div class="mini-stat">Legacy OS: $devicesLegacyOs</div>
                <div class="mini-stat">Azure AD joined: $devicesAzureAdJoined</div>
                <div class="mini-stat">Hybrid joined: $devicesHybridJoined</div>
                <div class="mini-stat">Registered: $devicesRegistered</div>
            </div>
            <div class="filters" id="devicesFilters">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="problems">Problems only</button>
                <button class="filter-btn" data-filter="high">HIGH</button>
                <button class="filter-btn" data-filter="medium">MEDIUM</button>
                <button class="filter-btn" data-filter="inactive">Inactive</button>
                <button class="filter-btn" data-filter="disabled">Disabled</button>
                <button class="filter-btn" data-filter="nolast">No last sign-in</button>
                <button class="filter-btn" data-filter="legacy">Legacy OS</button>
                <button class="filter-btn" data-filter="azuread">Azure AD joined</button>
                <button class="filter-btn" data-filter="hybrid">Hybrid joined</button>
                <button class="filter-btn" data-filter="registered">Registered</button>
            </div>
            <div class="search-row">
                <input type="text" id="devicesSearch" placeholder="Search Entra devices...">
                <div class="page-size-wrap"><span>Rows/page</span><select id="devicesPageSize"><option value="10">10</option><option value="25" selected>25</option><option value="50">50</option><option value="100">100</option><option value="250">250</option><option value="999999">All</option></select></div>
                <button class="export-btn" type="button" data-export-table="devicesTable" data-export-name="visible_entra_devices.csv">Export visible Entra Devices</button>
                <button class="copy-btn" type="button" data-copy-table="devicesTable" data-copy-attr="deviceid">Copy visible DeviceIds</button>
                <button class="copy-btn" type="button" data-copy-table="devicesTable" data-copy-attr="objectid">Copy visible ObjectIds</button>
                <div class="muted" id="devicesVisibleCount"></div>
            </div>
            <div class="table-wrap">
                <table id="devicesTable">
                    <thead><tr><th>Name</th><th>OS</th><th>TrustType</th><th>Enabled</th><th>Managed</th><th>Compliant</th><th>Approx last sign-in</th><th>Days</th><th>Flags</th><th>Recommendation</th><th>Risk</th><th>Details</th></tr></thead>
                    <tbody>$devicesRowsHtml</tbody>
                </table>
            </div>
            <div class="pagination-row"><div class="pager-left"><button class="pager-btn" id="devicesPrevBtn" type="button">Previous</button><button class="pager-btn" id="devicesNextBtn" type="button">Next</button></div><div class="pager-right"><div class="pager-info" id="devicesPageInfo"></div></div></div>
        </div>

        <div id="intuneTab" class="tab-content">
            <h2>Intune Devices</h2>
            <div class="mini-stats">
                <div class="mini-stat">Collection OK: $([bool]$intuneCollectionOk)</div>
                <div class="mini-stat">Total: $totalIntune</div>
                <div class="mini-stat">Inactive: $intuneInactive</div>
                <div class="mini-stat">Non-compliant: $intuneNonCompliant</div>
                <div class="mini-stat">HIGH: $intuneHigh</div>
                <div class="mini-stat">MEDIUM: $intuneMedium</div>
            </div>
            $(if ($intuneCollectionOk -eq 0) { "<div class='notice'><strong>Intune collection failed or skipped.</strong><br>" + $intuneErrorSafe + "</div>" } else { "" })
            <div class="filters" id="intuneFilters">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="problems">Problems only</button>
                <button class="filter-btn" data-filter="high">HIGH</button>
                <button class="filter-btn" data-filter="medium">MEDIUM</button>
                <button class="filter-btn" data-filter="inactive">Inactive</button>
                <button class="filter-btn" data-filter="noncompliant">Non-compliant</button>
            </div>
            <div class="search-row">
                <input type="text" id="intuneSearch" placeholder="Search Intune devices...">
                <div class="page-size-wrap"><span>Rows/page</span><select id="intunePageSize"><option value="10">10</option><option value="25" selected>25</option><option value="50">50</option><option value="100">100</option><option value="250">250</option><option value="999999">All</option></select></div>
                <button class="export-btn" type="button" data-export-table="intuneTable" data-export-name="visible_intune_devices.csv">Export visible Intune Devices</button>
                <button class="copy-btn" type="button" data-copy-table="intuneTable" data-copy-attr="azureaddeviceid">Copy visible AzureADDeviceIds</button>
                <button class="copy-btn" type="button" data-copy-table="intuneTable" data-copy-attr="upn">Copy visible UPNs</button>
                <div class="muted" id="intuneVisibleCount"></div>
            </div>
            <div class="table-wrap">
                <table id="intuneTable">
                    <thead><tr><th>Name</th><th>User</th><th>OS</th><th>Compliance</th><th>Agent</th><th>Last sync</th><th>Days</th><th>Flags</th><th>Recommendation</th><th>Risk</th><th>Details</th></tr></thead>
                    <tbody>$intuneRowsHtml</tbody>
                </table>
            </div>
            <div class="pagination-row"><div class="pager-left"><button class="pager-btn" id="intunePrevBtn" type="button">Previous</button><button class="pager-btn" id="intuneNextBtn" type="button">Next</button></div><div class="pager-right"><div class="pager-info" id="intunePageInfo"></div></div></div>
        </div>

        <div id="correlationTab" class="tab-content">
            <h2>Correlation</h2>
            <div class="mini-stats">
                <div class="mini-stat">Issues: $correlationIssues</div>
                <div class="mini-stat">Entra only: $correlationEntraOnly</div>
                <div class="mini-stat">Intune only: $correlationIntuneOnly</div>
                <div class="mini-stat">Soft name matches: $correlationSoftMatches</div>
            </div>
            <div class="filters" id="correlationFilters">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="problems">Problems only</button>
                <button class="filter-btn" data-filter="entraonly">Entra only</button>
                <button class="filter-btn" data-filter="intuneonly">Intune only</button>
                <button class="filter-btn" data-filter="softmatch">Soft match</button>
                <button class="filter-btn" data-filter="high">HIGH</button>
            </div>
            <div class="search-row">
                <input type="text" id="correlationSearch" placeholder="Search correlation issues...">
                <div class="page-size-wrap"><span>Rows/page</span><select id="correlationPageSize"><option value="10">10</option><option value="25" selected>25</option><option value="50">50</option><option value="100">100</option><option value="250">250</option><option value="999999">All</option></select></div>
                <button class="export-btn" type="button" data-export-table="correlationTable" data-export-name="visible_correlation_issues.csv">Export visible Correlation</button>
                <button class="copy-btn" type="button" data-copy-table="correlationTable" data-copy-attr="deviceid">Copy visible DeviceIds</button>
                <button class="copy-btn" type="button" data-copy-table="correlationTable" data-copy-attr="azureaddeviceid">Copy visible AzureADDeviceIds</button>
                <div class="muted" id="correlationVisibleCount"></div>
            </div>
            <div class="table-wrap">
                <table id="correlationTable">
                    <thead><tr><th>Issue</th><th>Match</th><th>Name</th><th>Entra</th><th>Intune</th><th>Entra last sign-in</th><th>Intune last sync</th><th>Flags</th><th>Recommendation</th><th>Risk</th><th>Details</th></tr></thead>
                    <tbody>$correlationRowsHtml</tbody>
                </table>
            </div>
            <div class="pagination-row"><div class="pager-left"><button class="pager-btn" id="correlationPrevBtn" type="button">Previous</button><button class="pager-btn" id="correlationNextBtn" type="button">Next</button></div><div class="pager-right"><div class="pager-info" id="correlationPageInfo"></div></div></div>
        </div>

        <div id="duplicatesTab" class="tab-content">
            <h2>Duplicates</h2>
            <div class="mini-stats">
                <div class="mini-stat">Duplicate groups: $duplicateDeviceNames</div>
                <div class="mini-stat">Entra duplicates: $duplicateEntraCount</div>
                <div class="mini-stat">Intune duplicates: $duplicateIntuneCount</div>
            </div>
            <div class="filters" id="duplicatesFilters">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="problems">Problems only</button>
                <button class="filter-btn" data-filter="entra">Entra</button>
                <button class="filter-btn" data-filter="intune">Intune</button>
            </div>
            <div class="search-row">
                <input type="text" id="duplicatesSearch" placeholder="Search duplicate names...">
                <div class="page-size-wrap"><span>Rows/page</span><select id="duplicatesPageSize"><option value="10">10</option><option value="25" selected>25</option><option value="50">50</option><option value="100">100</option><option value="250">250</option><option value="999999">All</option></select></div>
                <button class="export-btn" type="button" data-export-table="duplicatesTable" data-export-name="visible_duplicate_devices.csv">Export visible Duplicates</button>
                <button class="copy-btn" type="button" data-copy-table="duplicatesTable" data-copy-attr="objectids">Copy visible ObjectIds</button>
                <div class="muted" id="duplicatesVisibleCount"></div>
            </div>
            <div class="table-wrap">
                <table id="duplicatesTable">
                    <thead><tr><th>Name</th><th>Count</th><th>Source</th><th>Flags</th><th>Recommendation</th><th>Risk</th><th>Details</th></tr></thead>
                    <tbody>$duplicateRowsHtml</tbody>
                </table>
            </div>
            <div class="pagination-row"><div class="pager-left"><button class="pager-btn" id="duplicatesPrevBtn" type="button">Previous</button><button class="pager-btn" id="duplicatesNextBtn" type="button">Next</button></div><div class="pager-right"><div class="pager-info" id="duplicatesPageInfo"></div></div></div>
        </div>
    </div>

    <div class="box">
        <h2>Generated files</h2>
        <div class="muted">Quick reference to generated output paths.</div>
        <div class="kv" style="margin-top:12px;">
            <div class="k">Users CSV</div><div>$usersCsvSafe</div>
            <div class="k">Devices CSV</div><div>$devicesCsvSafe</div>
            <div class="k">Intune CSV</div><div>$intuneCsvSafe</div>
            <div class="k">Summary JSON</div><div>$summaryJsonSafe</div>
            <div class="k">Review Disabled + Licensed CSV</div><div>$reviewDisabledLicensedCsvSafe</div>
            <div class="k">Review Stale Guests CSV</div><div>$reviewStaleGuestsCsvSafe</div>
            <div class="k">Review Inactive Entra Devices CSV</div><div>$reviewInactiveDevicesCsvSafe</div>
            <div class="k">Review Inactive Intune Devices CSV</div><div>$reviewInactiveIntuneCsvSafe</div>
            <div class="k">Correlation Issues CSV</div><div>$correlationCsvSafe</div>
            <div class="k">Duplicate Devices CSV</div><div>$duplicateDevicesCsvSafe</div>
        </div>
    </div>

    <div class="foot">
        Read-only dashboard generated from Microsoft Graph data. No write actions performed.
    </div>
</div>

<div id="detailModal" class="modal">
    <div class="modal-card">
        <div class="modal-top">
            <h3 id="modalTitle">Details</h3>
            <button class="close-btn" type="button" id="closeModalBtn">Close</button>
        </div>
        <div id="modalBody"></div>
    </div>
</div>

<script>
(function(){
    const STORAGE_PREFIX = 'entraAuditV17.';
    const tabs = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const tableControllers = {};

    function saveSetting(key, value) {
        try { localStorage.setItem(STORAGE_PREFIX + key, value); } catch(err) {}
    }
    function loadSetting(key, fallback='') {
        try {
            const v = localStorage.getItem(STORAGE_PREFIX + key);
            return v == null ? fallback : v;
        } catch(err) {
            return fallback;
        }
    }

    function activateTab(tabId) {
        tabs.forEach(x => x.classList.remove('active'));
        tabContents.forEach(x => x.classList.remove('active'));
        const btn = document.querySelector('.tab-btn[data-tab="' + tabId + '"]');
        const tab = document.getElementById(tabId);
        if (btn) btn.classList.add('active');
        if (tab) tab.classList.add('active');
        saveSetting('activeTab', tabId);
    }

    tabs.forEach(btn => {
        btn.addEventListener('click', () => activateTab(btn.dataset.tab));
    });

    function setActiveCard(cardEl) {
        document.querySelectorAll('.action-card,.finding-card').forEach(c => c.classList.remove('active-card'));
        if (cardEl) cardEl.classList.add('active-card');
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replaceAll('&','&amp;')
            .replaceAll('<','&lt;')
            .replaceAll('>','&gt;')
            .replaceAll('"','&quot;')
            .replaceAll("'","&#39;");
    }

    function csvEscape(value) {
        const str = String(value ?? '');
        return '"' + str.replaceAll('"', '""') + '"';
    }

    function renderDetails(obj) {
        const keys = Object.keys(obj);
        let html = "<div class='kv'>";
        keys.forEach(k => {
            const v = obj[k] == null ? "" : String(obj[k]);
            html += "<div class='k'>" + escapeHtml(k) + "</div><div>" + escapeHtml(v) + "</div>";
        });
        html += "</div>";
        return html;
    }

    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    const closeModalBtn = document.getElementById('closeModalBtn');

    document.querySelectorAll('.btn-detail').forEach(btn => {
        btn.addEventListener('click', e => {
            const tr = e.target.closest('tr');
            const raw = tr.dataset.details || '{}';
            let obj = {};
            try { obj = JSON.parse(raw); }
            catch(err) { obj = { error: 'Failed to parse details', raw: raw }; }

            const titleText =
                obj.DisplayName ||
                obj.DeviceName ||
                obj.UserPrincipalName ||
                obj.DuplicateName ||
                obj.IssueType ||
                obj.Id ||
                'Details';

            modalTitle.textContent = titleText;
            modalBody.innerHTML = renderDetails(obj);
            modal.classList.add('open');
        });
    });

    function closeModal(){ modal.classList.remove('open'); }
    closeModalBtn.addEventListener('click', closeModal);
    modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });

    function clearSearch(searchId) {
        const search = document.getElementById(searchId);
        if (search) search.value = '';
    }

    function setupTableController(config) {
        const table = document.getElementById(config.tableId);
        const tbody = table.tBodies[0];
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const filterWrap = document.getElementById(config.filterWrapId);
        const search = document.getElementById(config.searchId);
        const count = document.getElementById(config.countId);
        const pageSizeEl = document.getElementById(config.pageSizeId);
        const prevBtn = document.getElementById(config.prevBtnId);
        const nextBtn = document.getElementById(config.nextBtnId);
        const pageInfo = document.getElementById(config.pageInfoId);

        let activeFilter = 'all';
        let currentPage = 1;
        let pageSize = Number(loadSetting(config.pageSizeId, pageSizeEl?.value || 25));

        if (pageSizeEl) {
            pageSizeEl.value = String(pageSize);
        }

        rows.forEach(r => {
            const risk = (r.dataset.risk || '').toUpperCase();
            if (risk === 'HIGH') r.classList.add('row-risk-high');
            else if (risk === 'MEDIUM') r.classList.add('row-risk-medium');
            else if (risk === 'LOW') r.classList.add('row-risk-low');
        });

        function matchesFilter(row) {
            switch(config.mode) {
                case 'users':
                    if (activeFilter === 'all') return true;
                    if (activeFilter === 'problems') return row.dataset.problem === 'true';
                    if (activeFilter === 'high') return row.dataset.risk === 'HIGH';
                    if (activeFilter === 'medium') return row.dataset.risk === 'MEDIUM';
                    if (activeFilter === 'inactive') return row.dataset.inactive === 'true';
                    if (activeFilter === 'disabled') return row.dataset.disabled === 'true';
                    if (activeFilter === 'disabledlicensed') return row.dataset.disabledlicensed === 'true';
                    if (activeFilter === 'never') return row.dataset.never === 'true';
                    if (activeFilter === 'guest') return row.dataset.guest === 'true';
                    if (activeFilter === 'hybrid') return row.dataset.hybrid === 'true';
                    return true;

                case 'devices':
                    if (activeFilter === 'all') return true;
                    if (activeFilter === 'problems') return row.dataset.problem === 'true';
                    if (activeFilter === 'high') return row.dataset.risk === 'HIGH';
                    if (activeFilter === 'medium') return row.dataset.risk === 'MEDIUM';
                    if (activeFilter === 'inactive') return row.dataset.inactive === 'true';
                    if (activeFilter === 'disabled') return row.dataset.disabled === 'true';
                    if (activeFilter === 'nolast') return row.cells[6].innerText.trim() === '';
                    if (activeFilter === 'legacy') return row.dataset.legacy === 'true';
                    if (activeFilter === 'azuread') return row.dataset.trusttype === 'AzureAd';
                    if (activeFilter === 'hybrid') return row.dataset.trusttype === 'ServerAd';
                    if (activeFilter === 'registered') return row.dataset.trusttype === 'Workplace';
                    return true;

                case 'intune':
                    if (activeFilter === 'all') return true;
                    if (activeFilter === 'problems') return row.dataset.problem === 'true';
                    if (activeFilter === 'high') return row.dataset.risk === 'HIGH';
                    if (activeFilter === 'medium') return row.dataset.risk === 'MEDIUM';
                    if (activeFilter === 'inactive') return row.dataset.inactive === 'true';
                    if (activeFilter === 'noncompliant') return row.dataset.noncompliant === 'true';
                    return true;

                case 'correlation':
                    if (activeFilter === 'all') return true;
                    if (activeFilter === 'problems') return row.dataset.problem === 'true';
                    if (activeFilter === 'entraonly') return row.dataset.issuetype === 'EntraOnly';
                    if (activeFilter === 'intuneonly') return row.dataset.issuetype === 'IntuneOnly';
                    if (activeFilter === 'softmatch') return row.dataset.matchtype === 'SoftMatchByName';
                    if (activeFilter === 'high') return row.dataset.risk === 'HIGH';
                    return true;

                case 'duplicates':
                    if (activeFilter === 'all') return true;
                    if (activeFilter === 'problems') return row.dataset.problem === 'true';
                    if (activeFilter === 'entra') return row.dataset.source === 'Entra';
                    if (activeFilter === 'intune') return row.dataset.source === 'Intune';
                    return true;
            }
            return true;
        }

        function getFilteredRows() {
            const q = (search.value || '').trim().toLowerCase();
            return rows.filter(row => {
                const text = row.innerText.toLowerCase();
                return matchesFilter(row) && (q === '' || text.includes(q));
            });
        }

        function apply() {
            const filteredRows = getFilteredRows();
            const totalFiltered = filteredRows.length;
            const effectivePageSize = pageSize > 0 ? pageSize : 25;
            const totalPages = Math.max(1, Math.ceil(totalFiltered / effectivePageSize));

            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;

            const startIndex = totalFiltered === 0 ? 0 : ((currentPage - 1) * effectivePageSize);
            const endIndex = totalFiltered === 0 ? 0 : Math.min(startIndex + effectivePageSize, totalFiltered);

            rows.forEach(row => row.classList.add('hidden-row'));
            filteredRows.slice(startIndex, endIndex).forEach(row => row.classList.remove('hidden-row'));

            const visibleNow = endIndex - startIndex;
            count.textContent = 'Visible rows: ' + visibleNow + ' / Filtered: ' + totalFiltered + ' / Total: ' + rows.length;

            if (totalFiltered === 0) {
                pageInfo.textContent = 'Page 0 / 0';
            } else if (effectivePageSize >= 999999) {
                pageInfo.textContent = 'Showing all filtered rows (' + totalFiltered + ')';
            } else {
                pageInfo.textContent = 'Page ' + currentPage + ' / ' + totalPages + ' | Rows ' + (startIndex + 1) + '-' + endIndex;
            }

            prevBtn.disabled = currentPage <= 1 || totalFiltered === 0 || effectivePageSize >= 999999;
            nextBtn.disabled = currentPage >= totalPages || totalFiltered === 0 || effectivePageSize >= 999999;
        }

        filterWrap.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                filterWrap.querySelectorAll('.filter-btn').forEach(x => x.classList.remove('active'));
                btn.classList.add('active');
                activeFilter = btn.dataset.filter;
                currentPage = 1;
                apply();
            });
        });

        search.addEventListener('input', () => {
            currentPage = 1;
            apply();
        });

        pageSizeEl.addEventListener('change', () => {
            pageSize = Number(pageSizeEl.value || 25);
            saveSetting(config.pageSizeId, pageSize);
            currentPage = 1;
            apply();
        });

        prevBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                apply();
            }
        });

        nextBtn.addEventListener('click', () => {
            currentPage++;
            apply();
        });

        function setFilter(filterName, clearSearchBox) {
            if (clearSearchBox) clearSearch(config.searchId);
            const btn = filterWrap.querySelector('.filter-btn[data-filter="' + filterName + '"]');
            if (btn) btn.click();
            else {
                activeFilter = filterName || 'all';
                currentPage = 1;
                apply();
            }
        }

        tableControllers[config.tableId] = { setFilter, refresh: apply };
        apply();
    }

    function sortTable(table, colIndex) {
        const tbody = table.tBodies[0];
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const current = table.getAttribute('data-sort-dir') || 'asc';
        const currentCol = table.getAttribute('data-sort-col');

        let nextDir = 'asc';
        if (String(currentCol) === String(colIndex)) {
            nextDir = current === 'asc' ? 'desc' : 'asc';
        }

        table.setAttribute('data-sort-dir', nextDir);
        table.setAttribute('data-sort-col', colIndex);

        rows.sort((a,b) => {
            const av = (a.children[colIndex]?.innerText || '').trim();
            const bv = (b.children[colIndex]?.innerText || '').trim();
            const an = Number(av);
            const bn = Number(bv);
            let cmp;
            if (!isNaN(an) && !isNaN(bn) && av !== '' && bv !== '') cmp = an - bn;
            else cmp = av.localeCompare(bv, undefined, {numeric:true, sensitivity:'base'});
            return nextDir === 'asc' ? cmp : -cmp;
        });

        rows.forEach(r => tbody.appendChild(r));

        table.querySelectorAll('th').forEach(th => {
            const base = th.getAttribute('data-base-text');
            if (base) th.innerHTML = escapeHtml(base);
        });

        const th = table.querySelectorAll('th')[colIndex];
        if (th) {
            const base = th.getAttribute('data-base-text') || th.innerText.trim();
            th.innerHTML = escapeHtml(base) + '<span class="sort-indicator">' + (nextDir === 'asc' ? '▲' : '▼') + '</span>';
        }

        const controller = tableControllers[table.id];
        if (controller) controller.refresh();
    }

    function exportVisibleRows(tableId, fileName) {
        const table = document.getElementById(tableId);
        if (!table) return;

        const headers = Array.from(table.querySelectorAll('thead th'))
            .map(th => th.getAttribute('data-base-text') || th.innerText.trim())
            .filter(h => h !== 'Details');

        const rows = Array.from(table.querySelectorAll('tbody tr'))
            .filter(tr => !tr.classList.contains('hidden-row'));

        const csvRows = [];
        csvRows.push(headers.map(v => csvEscape(v)).join(','));

        rows.forEach(tr => {
            const cells = Array.from(tr.children)
                .slice(0, headers.length)
                .map(td => csvEscape(td.innerText.trim()));
            csvRows.push(cells.join(','));
        });

        const blob = new Blob(["\uFEFF" + csvRows.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    async function copyVisibleValues(tableId, attrName) {
        const table = document.getElementById(tableId);
        if (!table) return;

        const rows = Array.from(table.querySelectorAll('tbody tr'))
            .filter(tr => !tr.classList.contains('hidden-row'));

        const values = rows
            .map(r => (r.dataset[attrName] || '').trim())
            .filter(v => v !== '');

        const text = values.join('\r\n');
        if (!text) return;

        try {
            await navigator.clipboard.writeText(text);
            alert('Copied ' + values.length + ' value(s) to clipboard.');
        } catch(err) {
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            alert('Copied ' + values.length + ' value(s) to clipboard.');
        }
    }

    document.querySelectorAll('table').forEach(table => {
        table.querySelectorAll('th').forEach((th, idx) => {
            th.setAttribute('data-base-text', th.innerText.trim());
            if (th.innerText.trim() === 'Details') return;
            th.addEventListener('click', () => sortTable(table, idx));
        });
    });

    setupTableController({ tableId:'usersTable', filterWrapId:'usersFilters', searchId:'usersSearch', countId:'usersVisibleCount', pageSizeId:'usersPageSize', prevBtnId:'usersPrevBtn', nextBtnId:'usersNextBtn', pageInfoId:'usersPageInfo', mode:'users' });
    setupTableController({ tableId:'devicesTable', filterWrapId:'devicesFilters', searchId:'devicesSearch', countId:'devicesVisibleCount', pageSizeId:'devicesPageSize', prevBtnId:'devicesPrevBtn', nextBtnId:'devicesNextBtn', pageInfoId:'devicesPageInfo', mode:'devices' });
    setupTableController({ tableId:'intuneTable', filterWrapId:'intuneFilters', searchId:'intuneSearch', countId:'intuneVisibleCount', pageSizeId:'intunePageSize', prevBtnId:'intunePrevBtn', nextBtnId:'intuneNextBtn', pageInfoId:'intunePageInfo', mode:'intune' });
    setupTableController({ tableId:'correlationTable', filterWrapId:'correlationFilters', searchId:'correlationSearch', countId:'correlationVisibleCount', pageSizeId:'correlationPageSize', prevBtnId:'correlationPrevBtn', nextBtnId:'correlationNextBtn', pageInfoId:'correlationPageInfo', mode:'correlation' });
    setupTableController({ tableId:'duplicatesTable', filterWrapId:'duplicatesFilters', searchId:'duplicatesSearch', countId:'duplicatesVisibleCount', pageSizeId:'duplicatesPageSize', prevBtnId:'duplicatesPrevBtn', nextBtnId:'duplicatesNextBtn', pageInfoId:'duplicatesPageInfo', mode:'duplicates' });

    document.querySelectorAll('.action-card,.finding-card').forEach(card => {
        card.addEventListener('click', () => {
            const tabTarget = card.dataset.tabTarget;
            const filterWrap = card.dataset.filterWrap;
            const filter = card.dataset.filter || 'all';
            const searchId = card.dataset.searchId;

            activateTab(tabTarget);

            let tableId = '';
            if (filterWrap === 'usersFilters') tableId = 'usersTable';
            if (filterWrap === 'devicesFilters') tableId = 'devicesTable';
            if (filterWrap === 'intuneFilters') tableId = 'intuneTable';
            if (filterWrap === 'correlationFilters') tableId = 'correlationTable';
            if (filterWrap === 'duplicatesFilters') tableId = 'duplicatesTable';

            if (searchId) clearSearch(searchId);
            if (tableControllers[tableId]) tableControllers[tableId].setFilter(filter, false);
            setActiveCard(card);
        });
    });

    document.querySelectorAll('.export-btn').forEach(btn => {
        btn.addEventListener('click', () => exportVisibleRows(btn.dataset.exportTable, btn.dataset.exportName || 'export.csv'));
    });

    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => copyVisibleValues(btn.dataset.copyTable, btn.dataset.copyAttr));
    });

    const savedTab = loadSetting('activeTab', 'usersTab');
    activateTab(savedTab);
})();
</script>

</body>
</html>
"@

Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Writing HTML dashboard" -PercentComplete 96
Set-Content -Path $htmlPath -Value $html -Encoding UTF8

Update-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Finalizing" -PercentComplete 99
Complete-StepProgress -Id 0 -Activity "Entra Audit Dashboard" -Status "Completed"

Safe-WriteHost "" "White"
Safe-WriteHost "Done." "Green"
Safe-WriteHost ("HTML: " + $htmlPath) "Yellow"
Safe-WriteHost ("Users CSV: " + $usersCsvPath) "Yellow"
Safe-WriteHost ("Devices CSV: " + $devicesCsvPath) "Yellow"
if (-not $SkipIntune) {
    Safe-WriteHost ("Intune CSV: " + $intuneCsvPath) "Yellow"
}
Safe-WriteHost ("Review Disabled+Licensed CSV: " + $reviewDisabledLicensedCsvPath) "Yellow"
Safe-WriteHost ("Review Stale Guests CSV: " + $reviewStaleGuestsCsvPath) "Yellow"
Safe-WriteHost ("Review Inactive Entra Devices CSV: " + $reviewInactiveDevicesCsvPath) "Yellow"
Safe-WriteHost ("Review Inactive Intune Devices CSV: " + $reviewInactiveIntuneCsvPath) "Yellow"
Safe-WriteHost ("Correlation Issues CSV: " + $correlationCsvPath) "Yellow"
Safe-WriteHost ("Duplicate Devices CSV: " + $duplicateDevicesCsvPath) "Yellow"
Safe-WriteHost ("Summary JSON: " + $summaryJsonPath) "Yellow"

if ($userSignInActivityAvailable -eq 0) {
    Safe-WriteHost "" "White"
    Safe-WriteHost "WARNING: user.signInActivity was not available. auditLogs/signIns fallback was used where possible." "Yellow"
    Safe-WriteHost ("Fallback lookback days: " + $SignInLogLookbackDays) "Yellow"
    Safe-WriteHost ("Fallback matched users: " + $userAuditLogFallbackCount) "Yellow"
    Safe-WriteHost "IMPORTANT: Users without fallback sign-in are REVIEW candidates, not confirmed never-signed-in users." "Yellow"
}
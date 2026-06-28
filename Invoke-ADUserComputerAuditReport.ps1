<#
.SYNOPSIS
    Active Directory Users and Computers Audit Dashboard.

.DESCRIPTION
    Auditoi AD-käyttäjät ja -tietokoneet, kuten vanhat kirjautumiset, käytöstä poistetut objektit, lukitukset ja perustason riskihavainnot.

.REQUIREMENTS
    - ActiveDirectory PowerShell -moduuli ja lukuoikeus AD-objekteihin

.OUTPUTS
    - HTML/CSV-raportit käyttäjistä, tietokoneista ja havainnoista

.EXAMPLE
    .\Invoke-ADUserComputerAuditReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Invoke-ADUserComputerAuditReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY COLLECTION: The audit collection is intended to be read-only. The generated report may include optional bulk-action helper snippets or CSV exports for manual review only. Review generated helper code separately and run it only if you intentionally choose to do so.
#>

param(
    [string]$OutputFolder = (Join-Path $PSScriptRoot "output\aduc"),
    [int]$OldUserDays = 90,
    [int]$OldComputerDays = 90,
    [string]$UserSearchBase = "",
    [string]$ComputerSearchBase = "",
    [string]$CanonicalNameLike = ""
)

$ErrorActionPreference = "Stop"

function New-SafeHtml {
    param([object]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-BadgeHtml {
    param(
        [string]$Text,
        [string]$Class
    )
    return '<span class="badge ' + $Class + '">' + ([System.Net.WebUtility]::HtmlEncode($Text)) + '</span>'
}

function Get-DateText {
    param($DateValue)

    if ($null -eq $DateValue) { return "" }

    try {
        return ([datetime]$DateValue).ToString("dd-MM-yyyy HH:mm:ss")
    }
    catch {
        return ""
    }
}

function Get-DateSortText {
    param($DateValue)

    if ($null -eq $DateValue) { return "" }

    try {
        return ([datetime]$DateValue).ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        return ""
    }
}

function Get-DaysSinceText {
    param($DateValue)

    if ($null -eq $DateValue) { return "" }

    try {
        $days = [math]::Floor(((Get-Date) - ([datetime]$DateValue)).TotalDays)
        return [string]$days
    }
    catch {
        return ""
    }
}

function Get-PercentText {
    param(
        [int]$Part,
        [int]$Total
    )

    if ($Total -eq 0) { return "0 (0%)" }

    $pct = [math]::Round(($Part / $Total) * 100, 1)
    return "$Part ($pct`%)"
}

function Test-IsInactive {
    param(
        $LastLogonDate,
        [int]$ThresholdDays
    )

    if ($null -eq $LastLogonDate) {
        return $true
    }

    try {
        return ([datetime]$LastLogonDate -lt (Get-Date).AddDays(-$ThresholdDays))
    }
    catch {
        return $false
    }
}

function Test-IsPrivilegedUser {
    param($UserObject)

    $isPrivileged = $false
    $groupDns = @()

    if ($UserObject.memberOf) {
        $groupDns = @($UserObject.memberOf)
    }

    $memberOfText = ($groupDns -join "; ")

    $privilegedPrefixes = @(
        "CN=Domain Admins,",
        "CN=Enterprise Admins,",
        "CN=Schema Admins,",
        "CN=Administrators,",
        "CN=Account Operators,",
        "CN=Server Operators,",
        "CN=Backup Operators,",
        "CN=Print Operators,"
    )

    if ($UserObject.adminCount -eq 1) {
        $isPrivileged = $true
    }

    if (-not $isPrivileged -and $groupDns.Count -gt 0) {
        foreach ($groupDn in $groupDns) {
            foreach ($prefix in $privilegedPrefixes) {
                if ([string]$groupDn -like "$prefix*") {
                    $isPrivileged = $true
                    break
                }
            }
            if ($isPrivileged) { break }
        }
    }

    return [pscustomobject]@{
        IsPrivileged = $isPrivileged
        MemberOfText = $memberOfText
    }
}

function Test-IsProtectedBuiltInUser {
    param($UserObject)

    $protectedNames = @(
        "Administrator",
        "Guest",
        "krbtgt",
        "DefaultAccount",
        "WDAGUtilityAccount"
    )

    $sam = ""
    $sid = ""

    try { $sam = [string]$UserObject.SamAccountName } catch {}
    try {
        if ($UserObject.SID) {
            $sid = [string]$UserObject.SID.Value
        }
    } catch {}

    $isProtected = $false
    $reason = ""

    if ($protectedNames -contains $sam) {
        $isProtected = $true
        $reason = "Built-in protected account name"
    }

    if (-not $isProtected -and $sid) {
        if (
            $sid -match '-500$' -or
            $sid -match '-501$' -or
            $sid -match '-502$' -or
            $sid -match '-503$' -or
            $sid -match '-504$'
        ) {
            $isProtected = $true
            $reason = "Built-in protected SID/RID"
        }
    }

    return [pscustomobject]@{
        IsProtectedBuiltIn = $isProtected
        ProtectedReason    = $reason
    }
}

function Test-IsExcludedDefaultContainer {
    param(
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return $false
    }

    $dn = $DistinguishedName.ToUpperInvariant()

    $excludedContainers = @(
        'CN=USERS,',
        'CN=BUILTIN,',
        'CN=COMPUTERS,',
        'OU=DOMAIN CONTROLLERS,'
    )

    foreach ($container in $excludedContainers) {
        if ($dn -match ('(^|,)' + [regex]::Escape($container))) {
            return $true
        }
    }

    return $false
}

function Test-IsServerOS {
    param($ComputerObject)

    try {
        $os = [string]$ComputerObject.OperatingSystem
        if ($os -match 'Windows Server') {
            return $true
        }
    }
    catch {}

    return $false
}

function Get-ComputerRoleHint {
    param($ComputerObject)

    $name = ""
    $dns  = ""
    $os   = ""

    try { $name = [string]$ComputerObject.Name } catch {}
    try { $dns  = [string]$ComputerObject.DNSHostName } catch {}
    try { $os   = [string]$ComputerObject.OperatingSystem } catch {}

    $combined = ($name + " " + $dns + " " + $os).ToLowerInvariant()

    if ($combined -match '\bdc\b|domain controller') { return "DC" }
    elseif ($combined -match 'sql') { return "SQL" }
    elseif ($combined -match 'file|fs\b') { return "File" }
    elseif ($combined -match 'web|www|iis') { return "Web" }
    elseif ($combined -match 'print') { return "Print" }
    elseif ($combined -match 'app|api') { return "App" }
    elseif ($combined -match 'rds|terminal|ts\b') { return "RDS" }
    elseif ($combined -match 'backup|veeam') { return "Backup" }
    elseif ($combined -match 'mgmt|manage') { return "Mgmt" }
    elseif ($combined -match 'vpn|rras|nps') { return "Infra" }
    elseif ($os -match 'Windows Server') { return "Server" }

    return "Workstation"
}

function Get-UserRiskHint {
    param($u)

    if ($u.IsProtectedBuiltIn) {
        return "PROTECTED BUILT-IN ACCOUNT"
    }
    elseif ($u.IsPrivileged -and $u.Enabled -and $u.IsInactive) {
        return "PRIVILEGED + INACTIVE"
    }
    elseif ($u.Enabled -eq $false -and $u.IsInactive) {
        return "DISABLED + INACTIVE"
    }
    elseif ($u.Enabled -and $u.NoLastLogon) {
        return "ENABLED + NO LAST LOGON"
    }
    elseif ($u.Enabled -and $u.LockedOut) {
        return "LOCKED OUT"
    }
    elseif ($u.Enabled -and $u.PasswordNeverExpires -and $u.IsPrivileged) {
        return "PRIVILEGED + PWD NEVER EXPIRES"
    }
    elseif ($u.IsPrivileged) {
        return "PRIVILEGED ACCOUNT"
    }
    elseif ($u.Enabled -eq $false) {
        return "DISABLED"
    }
    elseif ($u.IsInactive) {
        return "INACTIVE - verify"
    }
    else {
        return "ACTIVE"
    }
}

function Get-ComputerRiskHint {
    param($c)

    if ($c.IsServer -and $c.RoleHint -eq "DC") {
        return "DOMAIN CONTROLLER - REVIEW SEPARATELY"
    }
    elseif ($c.IsServer -and $c.Enabled -and $c.IsInactive) {
        return "SERVER + INACTIVE"
    }
    elseif ($c.Enabled -eq $false -and $c.IsInactive) {
        return "DISABLED + INACTIVE"
    }
    elseif ($c.Enabled -and $c.NoLastLogon) {
        return "ENABLED + NO LAST LOGON"
    }
    elseif ($c.IsWindows10OrOlder) {
        return "WINDOWS 10 / OLDER"
    }
    elseif ($c.IsOldOS) {
        return "OLD OS - review"
    }
    elseif ($c.Enabled -eq $false) {
        return "DISABLED"
    }
    elseif ($c.IsInactive) {
        return "STALE COMPUTER - verify"
    }
    elseif ($c.IsServer) {
        return "ACTIVE SERVER"
    }
    else {
        return "ACTIVE CLIENT"
    }
}

Import-Module ActiveDirectory -ErrorAction Stop

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

$htmlPath = Join-Path $OutputFolder "index.html"

$domainInfo = Get-ADDomain
$forestInfo = Get-ADForest

Write-Host "Reading AD users..." -ForegroundColor Cyan

$userParams = @{
    Filter     = "*"
    Properties = @(
        "DisplayName","SamAccountName","UserPrincipalName","Enabled","LastLogonDate",
        "PasswordNeverExpires","LockedOut","PasswordLastSet","WhenCreated","WhenChanged",
        "DistinguishedName","CanonicalName","Department","Title","Company","Description",
        "mail","Manager","adminCount","memberOf","SID"
    )
}

if (-not [string]::IsNullOrWhiteSpace($UserSearchBase)) {
    $userParams.SearchBase = $UserSearchBase
}

$adUsers = Get-ADUser @userParams

$adUsers = $adUsers | Where-Object {
    -not (Test-IsExcludedDefaultContainer -DistinguishedName $_.DistinguishedName)
}

if (-not [string]::IsNullOrWhiteSpace($CanonicalNameLike)) {
    $adUsers = $adUsers | Where-Object {
        $_.CanonicalName -like $CanonicalNameLike
    }
}

Write-Host "Reading AD computers..." -ForegroundColor Cyan

$computerParams = @{
    Filter     = "*"
    Properties = @(
        "DNSHostName","Enabled","LastLogonDate","OperatingSystem","OperatingSystemVersion",
        "WhenCreated","WhenChanged","DistinguishedName","CanonicalName","Description"
    )
}

if (-not [string]::IsNullOrWhiteSpace($ComputerSearchBase)) {
    $computerParams.SearchBase = $ComputerSearchBase
}

$adComputers = Get-ADComputer @computerParams

$adComputers = $adComputers | Where-Object {
    -not (Test-IsExcludedDefaultContainer -DistinguishedName $_.DistinguishedName)
}

if (-not [string]::IsNullOrWhiteSpace($CanonicalNameLike)) {
    $adComputers = $adComputers | Where-Object {
        $_.CanonicalName -like $CanonicalNameLike
    }
}

$userResults = foreach ($u in $adUsers) {
    $noLastLogon   = ($null -eq $u.LastLogonDate)
    $isInactive    = Test-IsInactive -LastLogonDate $u.LastLogonDate -ThresholdDays $OldUserDays
    $privInfo      = Test-IsPrivilegedUser -UserObject $u
    $protectedInfo = Test-IsProtectedBuiltInUser -UserObject $u

    [pscustomobject][ordered]@{
        ObjectType            = "User"
        Name                  = $u.Name
        DisplayName           = $u.DisplayName
        SamAccountName        = $u.SamAccountName
        UserPrincipalName     = $u.UserPrincipalName
        Enabled               = [bool]$u.Enabled
        LockedOut             = [bool]$u.LockedOut
        PasswordNeverExpires  = [bool]$u.PasswordNeverExpires
        IsAdminLike           = [bool]($u.adminCount -eq 1)
        IsPrivileged          = [bool]$privInfo.IsPrivileged
        IsProtectedBuiltIn    = [bool]$protectedInfo.IsProtectedBuiltIn
        ProtectedReason       = $protectedInfo.ProtectedReason
        SID                   = if ($u.SID) { [string]$u.SID.Value } else { "" }
        MemberOf              = $privInfo.MemberOfText
        Department            = $u.Department
        Title                 = $u.Title
        Company               = $u.Company
        Email                 = $u.mail
        LastLogonDate         = Get-DateText $u.LastLogonDate
        LastLogonDateSort     = Get-DateSortText $u.LastLogonDate
        DaysSinceLastLogon    = Get-DaysSinceText $u.LastLogonDate
        NoLastLogon           = [bool]$noLastLogon
        IsInactive            = [bool]$isInactive
        PasswordLastSet       = Get-DateText $u.PasswordLastSet
        PasswordLastSetSort   = Get-DateSortText $u.PasswordLastSet
        WhenCreated           = Get-DateText $u.WhenCreated
        WhenCreatedSort       = Get-DateSortText $u.WhenCreated
        WhenChanged           = Get-DateText $u.WhenChanged
        WhenChangedSort       = Get-DateSortText $u.WhenChanged
        CanonicalName         = $u.CanonicalName
        DistinguishedName     = $u.DistinguishedName
        Description           = $u.Description
        RiskHint              = ""
    }
}

foreach ($u in $userResults) {
    $u.RiskHint = Get-UserRiskHint -u $u
}

$allComputerResults = foreach ($c in $adComputers) {
    $noLastLogon = ($null -eq $c.LastLogonDate)
    $isInactive  = Test-IsInactive -LastLogonDate $c.LastLogonDate -ThresholdDays $OldComputerDays
    $isServer    = Test-IsServerOS -ComputerObject $c
    $roleHint    = Get-ComputerRoleHint -ComputerObject $c

    $isOldOS = $false
    $isWindows10OrOlder = $false
    $isLegacyClientOs = $false

    if ($c.OperatingSystem -match "Windows 10|Windows 8|Windows 8\.1|Windows 7|Windows XP|Windows Vista") {
        $isWindows10OrOlder = $true
    }

    if ($c.OperatingSystem -match "Windows 8|Windows 8\.1|Windows 7|Windows XP|Windows Vista") {
        $isLegacyClientOs = $true
    }

    if ($c.OperatingSystem -match "Windows XP|Windows Vista|Windows 7|Windows 8|Windows 8\.1") {
        $isOldOS = $true
    }

    [pscustomobject][ordered]@{
        ObjectType             = "Computer"
        Name                   = $c.Name
        DNSHostName            = $c.DNSHostName
        Enabled                = [bool]$c.Enabled
        IsServer               = [bool]$isServer
        RoleHint               = $roleHint
        IsOldOS                = [bool]$isOldOS
        IsWindows10OrOlder     = [bool]$isWindows10OrOlder
        IsLegacyClientOs       = [bool]$isLegacyClientOs
        OperatingSystem        = $c.OperatingSystem
        OperatingSystemVersion = $c.OperatingSystemVersion
        LastLogonDate          = Get-DateText $c.LastLogonDate
        LastLogonDateSort      = Get-DateSortText $c.LastLogonDate
        DaysSinceLastLogon     = Get-DaysSinceText $c.LastLogonDate
        NoLastLogon            = [bool]$noLastLogon
        IsInactive             = [bool]$isInactive
        WhenCreated            = Get-DateText $c.WhenCreated
        WhenCreatedSort        = Get-DateSortText $c.WhenCreated
        WhenChanged            = Get-DateText $c.WhenChanged
        WhenChangedSort        = Get-DateSortText $c.WhenChanged
        CanonicalName          = $c.CanonicalName
        DistinguishedName      = $c.DistinguishedName
        Description            = $c.Description
        RiskHint               = ""
    }
}

foreach ($c in $allComputerResults) {
    $c.RiskHint = Get-ComputerRiskHint -c $c
}

$computerResults = @($allComputerResults | Where-Object { -not $_.IsServer } | Sort-Object Name)
$serverResults   = @($allComputerResults | Where-Object { $_.IsServer } | Sort-Object Name)

$userTotal                    = @($userResults).Count
$userEnabledCount             = @($userResults | Where-Object { $_.Enabled }).Count
$userDisabledCount            = @($userResults | Where-Object { -not $_.Enabled }).Count
$userInactiveCount            = @($userResults | Where-Object { $_.IsInactive }).Count
$userNoLastLogonCount         = @($userResults | Where-Object { $_.NoLastLogon }).Count
$userLockedCount              = @($userResults | Where-Object { $_.LockedOut }).Count
$userPwdNeverExpires          = @($userResults | Where-Object { $_.PasswordNeverExpires }).Count
$userAdminLikeCount           = @($userResults | Where-Object { $_.IsAdminLike }).Count
$userPrivilegedCount          = @($userResults | Where-Object { $_.IsPrivileged }).Count
$userProtectedBuiltInCount    = @($userResults | Where-Object { $_.IsProtectedBuiltIn }).Count
$userPrivilegedInactiveCount  = @($userResults | Where-Object { $_.IsPrivileged -and $_.IsInactive }).Count
$userCleanupCount             = @($userResults | Where-Object { (-not $_.Enabled) -or $_.IsInactive -or $_.NoLastLogon }).Count
$userAdminCountResetEligible  = @($userResults | Where-Object { (-not $_.Enabled) -and $_.IsAdminLike }).Count

$computerTotal                = @($computerResults).Count
$computerEnabledCount         = @($computerResults | Where-Object { $_.Enabled }).Count
$computerDisabledCount        = @($computerResults | Where-Object { -not $_.Enabled }).Count
$computerInactiveCount        = @($computerResults | Where-Object { $_.IsInactive }).Count
$computerNoLastLogonCount     = @($computerResults | Where-Object { $_.NoLastLogon }).Count
$computerOldOsCount           = @($computerResults | Where-Object { $_.IsOldOS }).Count
$computerWin10OrOlderCount    = @($computerResults | Where-Object { $_.IsWindows10OrOlder }).Count
$computerEnabledInactiveCount = @($computerResults | Where-Object { $_.Enabled -and $_.IsInactive }).Count
$computerCleanupCount         = @($computerResults | Where-Object { (-not $_.Enabled) -or $_.IsInactive -or $_.NoLastLogon }).Count

$serverTotal                  = @($serverResults).Count
$serverEnabledCount           = @($serverResults | Where-Object { $_.Enabled }).Count
$serverDisabledCount          = @($serverResults | Where-Object { -not $_.Enabled }).Count
$serverInactiveCount          = @($serverResults | Where-Object { $_.IsInactive }).Count
$serverCleanupCount           = @($serverResults | Where-Object { (-not $_.Enabled) -or $_.IsInactive -or $_.NoLastLogon }).Count
$serverActiveCount            = @($serverResults | Where-Object { $_.Enabled -and -not $_.IsInactive -and -not $_.NoLastLogon }).Count
$serverEnabledInactiveCount   = @($serverResults | Where-Object { $_.Enabled -and $_.IsInactive }).Count
$dcServerCount                = @($serverResults | Where-Object { $_.RoleHint -eq "DC" }).Count
$sqlServerCount               = @($serverResults | Where-Object { $_.RoleHint -eq "SQL" }).Count

$topFindings = @()

if ($userProtectedBuiltInCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$userProtectedBuiltInCount built-in protected accounts detected"
        Target    = "users"
        Filter    = "protectedbuiltin"
        BadgeText = "Users"
        BadgeCss  = "badge-blue"
    }
}
if ($userPrivilegedInactiveCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$userPrivilegedInactiveCount privileged accounts are inactive"
        Target    = "users"
        Filter    = "privinactive"
        BadgeText = "Users"
        BadgeCss  = "badge-blue"
    }
}
if ($userLockedCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$userLockedCount users are locked out"
        Target    = "users"
        Filter    = "locked"
        BadgeText = "Users"
        BadgeCss  = "badge-blue"
    }
}
if ($userAdminCountResetEligible -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$userAdminCountResetEligible disabled adminCount users may need adminCount reset before delete"
        Target    = "users"
        Filter    = "adminlike"
        BadgeText = "Users"
        BadgeCss  = "badge-blue"
    }
}
if ($computerWin10OrOlderCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$computerWin10OrOlderCount client computers are Windows 10 or older"
        Target    = "computers"
        Filter    = "win10older"
        BadgeText = "Computers"
        BadgeCss  = "badge-yellow"
    }
}
if ($computerEnabledInactiveCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$computerEnabledInactiveCount enabled client computers are inactive"
        Target    = "computers"
        Filter    = "enabledinactive"
        BadgeText = "Computers"
        BadgeCss  = "badge-yellow"
    }
}
if ($serverEnabledInactiveCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$serverEnabledInactiveCount enabled servers are inactive"
        Target    = "servers"
        Filter    = "highrisk"
        BadgeText = "Servers"
        BadgeCss  = "badge-purple"
    }
}
if ($dcServerCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$dcServerCount domain controller server objects detected"
        Target    = "servers"
        Filter    = "all"
        BadgeText = "Servers"
        BadgeCss  = "badge-purple"
    }
}
if ($sqlServerCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$sqlServerCount SQL server objects detected"
        Target    = "servers"
        Filter    = "all"
        BadgeText = "Servers"
        BadgeCss  = "badge-purple"
    }
}
if ($topFindings.Count -eq 0) {
    $topFindings += [pscustomobject]@{
        Text      = "No obvious high-priority findings detected from current heuristics"
        Target    = ""
        Filter    = ""
        BadgeText = "Info"
        BadgeCss  = "badge-gray"
    }
}

$topFindingsHtml = ""
foreach ($f in $topFindings) {
    $badgeHtml = '<span class="badge finding-badge ' + (New-SafeHtml $f.BadgeCss) + '">' + (New-SafeHtml $f.BadgeText) + '</span>'

    if ([string]::IsNullOrWhiteSpace($f.Target)) {
        $topFindingsHtml += '<li><span class="finding-static">' + $badgeHtml + '<span class="finding-text">' + (New-SafeHtml $f.Text) + '</span></span></li>'
    }
    else {
        $topFindingsHtml += '<li><button type="button" class="finding-link" onclick="openFinding(''' + (New-SafeHtml $f.Target) + ''',''' + (New-SafeHtml $f.Filter) + ''')">' + $badgeHtml + '<span class="finding-text">' + (New-SafeHtml $f.Text) + '</span></button></li>'
    }
}

$userRows = New-Object System.Text.StringBuilder
foreach ($r in ($userResults | Sort-Object Name)) {
    $enabledBadge    = if ($r.Enabled) { Get-BadgeHtml -Text "Enabled" -Class "badge-green" } else { Get-BadgeHtml -Text "Disabled" -Class "badge-gray" }
    $lockedBadge     = if ($r.LockedOut) { Get-BadgeHtml -Text "Locked" -Class "badge-red" } else { "" }
    $pwdNeverBadge   = if ($r.PasswordNeverExpires) { Get-BadgeHtml -Text "Never Expires" -Class "badge-yellow" } else { "" }
    $adminLikeBadge  = if ($r.IsAdminLike) { Get-BadgeHtml -Text "Admin-like" -Class "badge-blue" } else { "" }
    $privilegedBadge = if ($r.IsPrivileged) { Get-BadgeHtml -Text "Privileged" -Class "badge-purple" } else { "" }
    $protectedBadge  = if ($r.IsProtectedBuiltIn) { Get-BadgeHtml -Text "Protected" -Class "badge-red" } else { "" }
    $noLogonBadge    = if ($r.NoLastLogon) { Get-BadgeHtml -Text "No Logon" -Class "badge-red" } else { "" }
    $inactiveBadge   = if ($r.IsInactive) { Get-BadgeHtml -Text "Inactive" -Class "badge-yellow" } else { "" }

    $null = $userRows.AppendLine(@"
<tr
    data-enabled="$(($r.Enabled).ToString().ToLowerInvariant())"
    data-disabled="$(((-not $r.Enabled)).ToString().ToLowerInvariant())"
    data-inactive="$(($r.IsInactive).ToString().ToLowerInvariant())"
    data-nologon="$(($r.NoLastLogon).ToString().ToLowerInvariant())"
    data-locked="$(($r.LockedOut).ToString().ToLowerInvariant())"
    data-pwdnever="$(($r.PasswordNeverExpires).ToString().ToLowerInvariant())"
    data-adminlike="$(($r.IsAdminLike).ToString().ToLowerInvariant())"
    data-privileged="$(($r.IsPrivileged).ToString().ToLowerInvariant())"
    data-protectedbuiltin="$(($r.IsProtectedBuiltIn).ToString().ToLowerInvariant())"
    data-privinactive="$((($r.IsPrivileged -and $r.IsInactive)).ToString().ToLowerInvariant())"
    data-cleanup="$(((-not $r.Enabled) -or $r.IsInactive -or $r.NoLastLogon).ToString().ToLowerInvariant())"
>
    <td>
        <input
            type="checkbox"
            class="row-select"
            data-target="users"
            data-objecttype="User"
            data-name="$(New-SafeHtml $r.Name)"
            data-displayname="$(New-SafeHtml $r.DisplayName)"
            data-sam="$(New-SafeHtml $r.SamAccountName)"
            data-upn="$(New-SafeHtml $r.UserPrincipalName)"
            data-dn="$(New-SafeHtml $r.DistinguishedName)"
            data-enabled="$(($r.Enabled).ToString().ToLowerInvariant())"
            data-adminlike="$(($r.IsAdminLike).ToString().ToLowerInvariant())"
            data-privileged="$(($r.IsPrivileged).ToString().ToLowerInvariant())"
            data-protectedbuiltin="$(($r.IsProtectedBuiltIn).ToString().ToLowerInvariant())"
            data-protectedreason="$(New-SafeHtml $r.ProtectedReason)"
            data-server="false"
            onchange="updateBulkSelection()"
        >
    </td>
    <td data-sort="$(New-SafeHtml $r.Name)">$(New-SafeHtml $r.Name)</td>
    <td data-sort="$(New-SafeHtml $r.DisplayName)">$(New-SafeHtml $r.DisplayName)</td>
    <td data-sort="$(New-SafeHtml $r.SamAccountName)">$(New-SafeHtml $r.SamAccountName)</td>
    <td data-sort="$(New-SafeHtml $r.UserPrincipalName)">$(New-SafeHtml $r.UserPrincipalName)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.Enabled))">$enabledBadge</td>
    <td data-sort="$(New-SafeHtml ([string]$r.LockedOut))">$lockedBadge</td>
    <td data-sort="$(New-SafeHtml ([string]$r.PasswordNeverExpires))">$pwdNeverBadge</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsAdminLike))">$adminLikeBadge</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsPrivileged))">$privilegedBadge $protectedBadge</td>
    <td data-sort="$(New-SafeHtml $r.LastLogonDateSort)">$(New-SafeHtml $r.LastLogonDate)</td>
    <td data-sort="$(New-SafeHtml $r.DaysSinceLastLogon)">$(New-SafeHtml $r.DaysSinceLastLogon)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.NoLastLogon))">$noLogonBadge</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsInactive))">$inactiveBadge</td>
    <td data-sort="$(New-SafeHtml $r.Department)">$(New-SafeHtml $r.Department)</td>
    <td data-sort="$(New-SafeHtml $r.Title)">$(New-SafeHtml $r.Title)</td>
    <td data-sort="$(New-SafeHtml $r.CanonicalName)">$(New-SafeHtml $r.CanonicalName)</td>
    <td data-sort="$(New-SafeHtml $r.RiskHint)">$(New-SafeHtml $r.RiskHint)</td>
</tr>
"@)
}

$computerRows = New-Object System.Text.StringBuilder
foreach ($r in ($computerResults | Sort-Object Name)) {
    $enabledBadge    = if ($r.Enabled) { Get-BadgeHtml -Text "Enabled" -Class "badge-green" } else { Get-BadgeHtml -Text "Disabled" -Class "badge-gray" }
    $roleBadge       = Get-BadgeHtml -Text $r.RoleHint -Class "badge-blue"
    $win10OlderBadge = if ($r.IsWindows10OrOlder) { Get-BadgeHtml -Text "Win10/Older" -Class "badge-yellow" } else { "" }
    $oldOsBadge      = if ($r.IsOldOS) { Get-BadgeHtml -Text "Legacy OS" -Class "badge-red" } else { "" }
    $noLogonBadge    = if ($r.NoLastLogon) { Get-BadgeHtml -Text "No Logon" -Class "badge-red" } else { "" }
    $inactiveBadge   = if ($r.IsInactive) { Get-BadgeHtml -Text "Inactive" -Class "badge-yellow" } else { "" }

    $null = $computerRows.AppendLine(@"
<tr
    data-enabled="$(($r.Enabled).ToString().ToLowerInvariant())"
    data-disabled="$(((-not $r.Enabled)).ToString().ToLowerInvariant())"
    data-inactive="$(($r.IsInactive).ToString().ToLowerInvariant())"
    data-nologon="$(($r.NoLastLogon).ToString().ToLowerInvariant())"
    data-server="false"
    data-oldos="$(($r.IsOldOS).ToString().ToLowerInvariant())"
    data-win10older="$(($r.IsWindows10OrOlder).ToString().ToLowerInvariant())"
    data-enabledinactive="$((($r.Enabled -and $r.IsInactive)).ToString().ToLowerInvariant())"
    data-cleanup="$(((-not $r.Enabled) -or $r.IsInactive -or $r.NoLastLogon).ToString().ToLowerInvariant())"
>
    <td>
        <input
            type="checkbox"
            class="row-select"
            data-target="computers"
            data-objecttype="Computer"
            data-name="$(New-SafeHtml $r.Name)"
            data-displayname=""
            data-sam=""
            data-upn=""
            data-dn="$(New-SafeHtml $r.DistinguishedName)"
            data-enabled="$(($r.Enabled).ToString().ToLowerInvariant())"
            data-adminlike="false"
            data-privileged="false"
            data-protectedbuiltin="false"
            data-protectedreason=""
            data-server="false"
            onchange="updateBulkSelection()"
        >
    </td>
    <td data-sort="$(New-SafeHtml $r.Name)">$(New-SafeHtml $r.Name)</td>
    <td data-sort="$(New-SafeHtml $r.DNSHostName)">$(New-SafeHtml $r.DNSHostName)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.Enabled))">$enabledBadge</td>
    <td data-sort="$(New-SafeHtml $r.RoleHint)">$roleBadge</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsWindows10OrOlder))">$win10OlderBadge</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsOldOS))">$oldOsBadge</td>
    <td data-sort="$(New-SafeHtml $r.OperatingSystem)">$(New-SafeHtml $r.OperatingSystem)</td>
    <td data-sort="$(New-SafeHtml $r.OperatingSystemVersion)">$(New-SafeHtml $r.OperatingSystemVersion)</td>
    <td data-sort="$(New-SafeHtml $r.LastLogonDateSort)">$(New-SafeHtml $r.LastLogonDate)</td>
    <td data-sort="$(New-SafeHtml $r.DaysSinceLastLogon)">$(New-SafeHtml $r.DaysSinceLastLogon)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.NoLastLogon))">$noLogonBadge</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsInactive))">$inactiveBadge</td>
    <td data-sort="$(New-SafeHtml $r.CanonicalName)">$(New-SafeHtml $r.CanonicalName)</td>
    <td data-sort="$(New-SafeHtml $r.RiskHint)">$(New-SafeHtml $r.RiskHint)</td>
</tr>
"@)
}

$serverRows = New-Object System.Text.StringBuilder
foreach ($r in ($serverResults | Sort-Object Name)) {
    $enabledBadge  = if ($r.Enabled) { Get-BadgeHtml -Text "Enabled" -Class "badge-green" } else { Get-BadgeHtml -Text "Disabled" -Class "badge-gray" }
    $roleBadge     = Get-BadgeHtml -Text $r.RoleHint -Class "badge-purple"
    $inactiveBadge = if ($r.IsInactive) { Get-BadgeHtml -Text "Inactive" -Class "badge-yellow" } else { "" }

    $null = $serverRows.AppendLine(@"
<tr
    data-enabled="$(($r.Enabled).ToString().ToLowerInvariant())"
    data-disabled="$(((-not $r.Enabled)).ToString().ToLowerInvariant())"
    data-inactive="$(($r.IsInactive).ToString().ToLowerInvariant())"
    data-nologon="$(($r.NoLastLogon).ToString().ToLowerInvariant())"
    data-server="true"
    data-active="$((($r.Enabled -and -not $r.IsInactive -and -not $r.NoLastLogon)).ToString().ToLowerInvariant())"
    data-highrisk="$((($r.Enabled -and $r.IsInactive)).ToString().ToLowerInvariant())"
    data-cleanup="$(((-not $r.Enabled) -or $r.IsInactive -or $r.NoLastLogon).ToString().ToLowerInvariant())"
>
    <td>
        <input
            type="checkbox"
            class="row-select"
            data-target="servers"
            data-objecttype="Computer"
            data-name="$(New-SafeHtml $r.Name)"
            data-displayname=""
            data-sam=""
            data-upn=""
            data-dn="$(New-SafeHtml $r.DistinguishedName)"
            data-enabled="$(($r.Enabled).ToString().ToLowerInvariant())"
            data-adminlike="false"
            data-privileged="false"
            data-protectedbuiltin="false"
            data-protectedreason=""
            data-server="true"
            onchange="updateBulkSelection()"
        >
    </td>
    <td data-sort="$(New-SafeHtml $r.Name)">$(New-SafeHtml $r.Name)</td>
    <td data-sort="$(New-SafeHtml $r.DNSHostName)">$(New-SafeHtml $r.DNSHostName)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.Enabled))">$enabledBadge</td>
    <td data-sort="$(New-SafeHtml $r.RoleHint)">$roleBadge</td>
    <td data-sort="$(New-SafeHtml $r.OperatingSystem)">$(New-SafeHtml $r.OperatingSystem)</td>
    <td data-sort="$(New-SafeHtml $r.OperatingSystemVersion)">$(New-SafeHtml $r.OperatingSystemVersion)</td>
    <td data-sort="$(New-SafeHtml $r.LastLogonDateSort)">$(New-SafeHtml $r.LastLogonDate)</td>
    <td data-sort="$(New-SafeHtml $r.DaysSinceLastLogon)">$(New-SafeHtml $r.DaysSinceLastLogon)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsInactive))">$inactiveBadge</td>
    <td data-sort="$(New-SafeHtml $r.CanonicalName)">$(New-SafeHtml $r.CanonicalName)</td>
    <td data-sort="$(New-SafeHtml $r.RiskHint)">$(New-SafeHtml $r.RiskHint)</td>
</tr>
"@)
}

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AD DS Object Audit Report v2.5</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:#f7f9fc;color:#1f2937}
h1,h2,h3{margin-bottom:10px}
.meta,.summary,.section,.toolbar,.notes{background:#fff;border:1px solid #dbe2ea;border-radius:10px;padding:16px;margin-bottom:18px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.summary h2,.section h2{font-size:20px;margin-bottom:8px}
.summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
@media (max-width:1400px){.summary-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:1000px){.summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:640px){.summary-grid{grid-template-columns:1fr}}
.card{background:#f9fbfd;border:1px solid #dbe2ea;border-radius:10px;padding:14px 16px;cursor:pointer;transition:.15s ease;min-height:84px}
.card:hover{background:#eef4fa;border-color:#bfd3e6}
.card.active{background:#dbeafe;border-color:#60a5fa}
.card .label{font-size:13px;color:#6b7280;text-transform:uppercase;letter-spacing:.03em;line-height:1.35}
.card .value{font-size:28px;font-weight:700;margin-top:6px;line-height:1.15}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.toolbar button,.toolbar select,.toolbar input[type="search"],.toolbar input[type="text"]{border:1px solid #cbd5e1;background:#f8fafc;border-radius:8px;padding:8px 12px;font:inherit}
.toolbar button{cursor:pointer}
.toolbar button:hover{background:#eef2f7}
.toolbar input[type="search"]{min-width:240px}
table{width:max-content;min-width:100%;border-collapse:collapse;background:#fff;border:1px solid #dbe2ea}
th,td{border:1px solid #e5e7eb;padding:8px 10px;vertical-align:top;font-size:13px;white-space:nowrap}
th{background:#eef4fa;text-align:left;position:sticky;top:0;z-index:2;cursor:pointer;user-select:none}
th.no-sort{cursor:default}
th:hover{background:#dde9f5}
th.no-sort:hover{background:#eef4fa}
tr:nth-child(even) td{background:#fafcff}
tr[data-cleanup="true"] td{background:#fff7ed}
tr[data-disabled="true"] td{background:#f3f4f6;color:#4b5563}
tr[data-enabled="true"][data-inactive="true"] td{background:#fef3c7}
tr[data-privileged="true"] td{background:#efe9ff}
tr[data-protectedbuiltin="true"] td{background:#ffe4e6}
tr[data-locked="true"] td{background:#fee2e2}
tr[data-server="true"][data-inactive="true"] td{background:#ffe4e6}
tr[data-win10older="true"] td{background:#ecfccb}
tr[data-highrisk="true"] td{background:#fee2e2;font-weight:600}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;line-height:1.4;white-space:nowrap;margin-right:4px;margin-bottom:2px}
.badge-green{background:#dcfce7;color:#166534}
.badge-yellow{background:#fef3c7;color:#92400e}
.badge-red{background:#fee2e2;color:#991b1b}
.badge-gray{background:#e5e7eb;color:#374151}
.badge-purple{background:#ede9fe;color:#6d28d9}
.badge-blue{background:#dbeafe;color:#1d4ed8}
.muted{color:#6b7280;font-size:13px}
.hidden-row{display:none !important}
.tabs{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.tab-btn{border:1px solid #cbd5e1;background:#f8fafc;border-radius:8px;padding:8px 12px;cursor:pointer}
.tab-btn.active{background:#dbeafe;border-color:#60a5fa}
.table-wrap{overflow-x:auto;overflow-y:visible;max-width:100%;border:1px solid #dbe2ea;border-radius:10px;background:#fff}
.summary ul{margin:0;padding-left:18px}
.summary li{margin-bottom:8px;font-weight:500}
.finding-link,.finding-static{display:flex;align-items:center;gap:10px;width:100%;box-sizing:border-box}
.finding-link{text-align:left;border:1px solid #cbd5e1;background:#f8fafc;color:#1f2937;border-radius:8px;padding:10px 12px;font:inherit;font-weight:600;cursor:pointer;transition:.15s ease}
.finding-link:hover{background:#dbeafe;border-color:#60a5fa}
.finding-static{padding:10px 12px;border:1px solid #dbe2ea;background:#f8fafc;border-radius:8px}
.finding-badge{flex:0 0 auto;margin-right:0;margin-bottom:0}
.finding-text{flex:1 1 auto}
th:first-child,td:first-child{position:sticky;left:0;z-index:3;background:inherit;box-shadow:2px 0 0 #dbe2ea}
th:first-child{z-index:4;background:#eef4fa;min-width:52px;text-align:center}
td:first-child{text-align:center}
.bulk-toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:10px;margin-bottom:12px;padding:12px;background:#f8fafc;border:1px solid #dbe2ea;border-radius:10px}
.bulk-toolbar button{border:1px solid #cbd5e1;background:#fff;border-radius:8px;padding:8px 12px;font:inherit;cursor:pointer}
.bulk-toolbar button:hover{background:#eef2f7}
.modal-backdrop{position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:9999;display:none;align-items:center;justify-content:center;padding:24px}
.modal{width:min(1200px,96vw);max-height:92vh;overflow:auto;background:#fff;border-radius:14px;border:1px solid #dbe2ea;box-shadow:0 20px 60px rgba(0,0,0,.18);padding:20px}
.modal-grid{display:grid;grid-template-columns:1fr;gap:12px}
.modal label{font-weight:600;display:block;margin-bottom:6px}
.modal select,.modal input[type="text"],.modal textarea{width:100%;border:1px solid #cbd5e1;border-radius:8px;padding:10px 12px;font:inherit;box-sizing:border-box}
.modal textarea{font-family:Consolas,Menlo,monospace;min-height:340px;resize:vertical;white-space:pre}
.modal-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.modal-actions button{border:1px solid #cbd5e1;background:#f8fafc;border-radius:8px;padding:8px 12px;font:inherit;cursor:pointer}
.modal-actions button:hover{background:#eef2f7}
.warn-box{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:10px;padding:10px 12px;font-size:13px}
.warn-box-danger{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:10px;padding:10px 12px;font-size:13px}
.helper-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
@media (max-width:900px){.helper-grid{grid-template-columns:1fr}}
.check-inline{display:flex;align-items:center;gap:8px;margin-top:4px}
.check-inline input[type="checkbox"]{width:auto}
</style>
</head>
<body>
    <h1>AD DS Object Audit Report v2.5</h1>

    <div class="meta">
        <h2>Environment</h2>
        <p><strong>Domain:</strong> $(New-SafeHtml $domainInfo.DNSRoot)</p>
        <p><strong>Forest:</strong> $(New-SafeHtml $forestInfo.Name)</p>
        <p><strong>Generated:</strong> $(New-SafeHtml ((Get-Date).ToString("dd.MM.yyyy HH:mm")))</p>
        <p><strong>User inactivity threshold:</strong> $(New-SafeHtml "$OldUserDays days")</p>
        <p><strong>Computer inactivity threshold:</strong> $(New-SafeHtml "$OldComputerDays days")</p>
        <p><strong>Excluded containers/OUs:</strong> CN=Users, CN=Builtin, CN=Computers, OU=Domain Controllers</p>
    </div>

    <div class="summary">
        <h2>Top Findings</h2>
        <ul>
            $topFindingsHtml
        </ul>
    </div>

    <div class="tabs">
        <button class="tab-btn active" type="button" onclick="showTab('users')">Users</button>
        <button class="tab-btn" type="button" onclick="showTab('computers')">Computers</button>
        <button class="tab-btn" type="button" onclick="showTab('servers')">Servers</button>
    </div>

    <div id="usersTab" class="section">
        <h2>User Summary</h2>
        <p class="muted">Click a card to filter user rows.</p>
        <div class="summary-grid" id="userSummaryCards">
            <div class="card active" data-target="users" data-filter="all"><div class="label">All Users</div><div class="value">$userTotal</div></div>
            <div class="card" data-target="users" data-filter="cleanup"><div class="label">Cleanup Candidates</div><div class="value">$(Get-PercentText $userCleanupCount $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="enabled"><div class="label">Enabled</div><div class="value">$(Get-PercentText $userEnabledCount $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="disabled"><div class="label">Disabled</div><div class="value">$(Get-PercentText $userDisabledCount $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="inactive"><div class="label">Inactive</div><div class="value">$(Get-PercentText $userInactiveCount $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="nologon"><div class="label">No Last Logon</div><div class="value">$(Get-PercentText $userNoLastLogonCount $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="locked"><div class="label">Locked Out</div><div class="value">$(Get-PercentText $userLockedCount $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="pwdnever"><div class="label">Pwd Never Expires</div><div class="value">$(Get-PercentText $userPwdNeverExpires $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="adminlike"><div class="label">Admin-like</div><div class="value">$(Get-PercentText $userAdminLikeCount $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="privileged"><div class="label">Privileged Accounts</div><div class="value">$(Get-PercentText $userPrivilegedCount $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="privinactive"><div class="label">Privileged + Inactive</div><div class="value">$(Get-PercentText $userPrivilegedInactiveCount $userTotal)</div></div>
            <div class="card" data-target="users" data-filter="protectedbuiltin"><div class="label">Protected Built-in</div><div class="value">$(Get-PercentText $userProtectedBuiltInCount $userTotal)</div></div>
        </div>

        <div class="bulk-toolbar">
            <button type="button" onclick="toggleAllVisible('users', true)">Select visible</button>
            <button type="button" onclick="toggleAllVisible('users', false)">Unselect visible</button>
            <button type="button" onclick="openBulkActionModal()">Bulk actions</button>
            <button type="button" onclick="clearSelections()">Clear all selections</button>
            <span id="bulkSelectionInfoUsers" class="muted">0 selected in total</span>
        </div>

        <div class="toolbar">
            <button type="button" onclick="resetFilters('users')">Reset filters</button>
            <label>
                Rows per page:
                <select onchange="setPageSize('users', this.value)">
                    <option value="10" selected>10</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                    <option value="250">250</option>
                    <option value="500">500</option>
                    <option value="1000">1000</option>
                    <option value="all">ALL</option>
                </select>
            </label>
            <button type="button" onclick="prevPage('users')">Prev</button>
            <button type="button" onclick="nextPage('users')">Next</button>
            <input type="search" placeholder="Search users..." oninput="setSearch('users', this.value)">
            <span id="userResultInfo" class="muted"></span>
            <span id="userPageInfo" class="muted"></span>
        </div>

        <div class="table-wrap">
            <table id="userTable">
                <thead>
                    <tr>
                        <th class="no-sort"><input type="checkbox" onclick="toggleAllVisible('users', this.checked)"></th>
                        <th onclick="sortTable('userTable', 1)">Name</th>
                        <th onclick="sortTable('userTable', 2)">Display Name</th>
                        <th onclick="sortTable('userTable', 3)">SamAccountName</th>
                        <th onclick="sortTable('userTable', 4)">UPN</th>
                        <th onclick="sortTable('userTable', 5)">Enabled</th>
                        <th onclick="sortTable('userTable', 6)">Locked</th>
                        <th onclick="sortTable('userTable', 7)">Pwd Never Expires</th>
                        <th onclick="sortTable('userTable', 8)">Admin-like</th>
                        <th onclick="sortTable('userTable', 9)">Privileged / Protected</th>
                        <th onclick="sortTable('userTable', 10)">Last Logon</th>
                        <th onclick="sortTable('userTable', 11)">Days Since Logon</th>
                        <th onclick="sortTable('userTable', 12)">No Last Logon</th>
                        <th onclick="sortTable('userTable', 13)">Inactive</th>
                        <th onclick="sortTable('userTable', 14)">Department</th>
                        <th onclick="sortTable('userTable', 15)">Title</th>
                        <th onclick="sortTable('userTable', 16)">Canonical Name</th>
                        <th onclick="sortTable('userTable', 17)">Risk Hint</th>
                    </tr>
                </thead>
                <tbody>
                    $($userRows.ToString())
                </tbody>
            </table>
        </div>
    </div>

    <div id="computersTab" class="section" style="display:none;">
        <h2>Computer Summary</h2>
        <p class="muted">Computers-tab shows client computers only.</p>
        <div class="summary-grid" id="computerSummaryCards">
            <div class="card active" data-target="computers" data-filter="all"><div class="label">Client Computers</div><div class="value">$computerTotal</div></div>
            <div class="card" data-target="computers" data-filter="cleanup"><div class="label">Cleanup Candidates</div><div class="value">$(Get-PercentText $computerCleanupCount $computerTotal)</div></div>
            <div class="card" data-target="computers" data-filter="enabled"><div class="label">Enabled</div><div class="value">$(Get-PercentText $computerEnabledCount $computerTotal)</div></div>
            <div class="card" data-target="computers" data-filter="disabled"><div class="label">Disabled</div><div class="value">$(Get-PercentText $computerDisabledCount $computerTotal)</div></div>
            <div class="card" data-target="computers" data-filter="inactive"><div class="label">Inactive</div><div class="value">$(Get-PercentText $computerInactiveCount $computerTotal)</div></div>
            <div class="card" data-target="computers" data-filter="enabledinactive"><div class="label">Enabled + Inactive</div><div class="value">$(Get-PercentText $computerEnabledInactiveCount $computerTotal)</div></div>
            <div class="card" data-target="computers" data-filter="nologon"><div class="label">No Last Logon</div><div class="value">$(Get-PercentText $computerNoLastLogonCount $computerTotal)</div></div>
            <div class="card" data-target="computers" data-filter="win10older"><div class="label">Windows 10 / Older</div><div class="value">$(Get-PercentText $computerWin10OrOlderCount $computerTotal)</div></div>
            <div class="card" data-target="computers" data-filter="oldos"><div class="label">Legacy Client OS</div><div class="value">$(Get-PercentText $computerOldOsCount $computerTotal)</div></div>
        </div>

        <div class="bulk-toolbar">
            <button type="button" onclick="toggleAllVisible('computers', true)">Select visible</button>
            <button type="button" onclick="toggleAllVisible('computers', false)">Unselect visible</button>
            <button type="button" onclick="openBulkActionModal()">Bulk actions</button>
            <button type="button" onclick="clearSelections()">Clear all selections</button>
            <span id="bulkSelectionInfoComputers" class="muted">0 selected in total</span>
        </div>

        <div class="toolbar">
            <button type="button" onclick="resetFilters('computers')">Reset filters</button>
            <label>
                Rows per page:
                <select onchange="setPageSize('computers', this.value)">
                    <option value="10" selected>10</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                    <option value="250">250</option>
                    <option value="500">500</option>
                    <option value="1000">1000</option>
                    <option value="all">ALL</option>
                </select>
            </label>
            <button type="button" onclick="prevPage('computers')">Prev</button>
            <button type="button" onclick="nextPage('computers')">Next</button>
            <input type="search" placeholder="Search computers..." oninput="setSearch('computers', this.value)">
            <span id="computerResultInfo" class="muted"></span>
            <span id="computerPageInfo" class="muted"></span>
        </div>

        <div class="table-wrap">
            <table id="computerTable">
                <thead>
                    <tr>
                        <th class="no-sort"><input type="checkbox" onclick="toggleAllVisible('computers', this.checked)"></th>
                        <th onclick="sortTable('computerTable', 1)">Name</th>
                        <th onclick="sortTable('computerTable', 2)">DNS Hostname</th>
                        <th onclick="sortTable('computerTable', 3)">Enabled</th>
                        <th onclick="sortTable('computerTable', 4)">Role</th>
                        <th onclick="sortTable('computerTable', 5)">Windows 10 / Older</th>
                        <th onclick="sortTable('computerTable', 6)">Legacy Client OS</th>
                        <th onclick="sortTable('computerTable', 7)">Operating System</th>
                        <th onclick="sortTable('computerTable', 8)">OS Version</th>
                        <th onclick="sortTable('computerTable', 9)">Last Logon</th>
                        <th onclick="sortTable('computerTable', 10)">Days Since Logon</th>
                        <th onclick="sortTable('computerTable', 11)">No Last Logon</th>
                        <th onclick="sortTable('computerTable', 12)">Inactive</th>
                        <th onclick="sortTable('computerTable', 13)">Canonical Name</th>
                        <th onclick="sortTable('computerTable', 14)">Risk Hint</th>
                    </tr>
                </thead>
                <tbody>
                    $($computerRows.ToString())
                </tbody>
            </table>
        </div>
    </div>

    <div id="serversTab" class="section" style="display:none;">
        <h2>Server Summary</h2>
        <p class="muted">Servers-tab shows server operating systems only.</p>
        <div class="summary-grid" id="serverSummaryCards">
            <div class="card active" data-target="servers" data-filter="all"><div class="label">All Servers</div><div class="value">$serverTotal</div></div>
            <div class="card" data-target="servers" data-filter="active"><div class="label">Active</div><div class="value">$(Get-PercentText $serverActiveCount $serverTotal)</div></div>
            <div class="card" data-target="servers" data-filter="highrisk"><div class="label">Enabled + Inactive (High Risk)</div><div class="value">$(Get-PercentText $serverEnabledInactiveCount $serverTotal)</div></div>
            <div class="card" data-target="servers" data-filter="cleanup"><div class="label">Cleanup Candidates</div><div class="value">$(Get-PercentText $serverCleanupCount $serverTotal)</div></div>
            <div class="card" data-target="servers" data-filter="enabled"><div class="label">Enabled</div><div class="value">$(Get-PercentText $serverEnabledCount $serverTotal)</div></div>
            <div class="card" data-target="servers" data-filter="disabled"><div class="label">Disabled</div><div class="value">$(Get-PercentText $serverDisabledCount $serverTotal)</div></div>
            <div class="card" data-target="servers" data-filter="inactive"><div class="label">Inactive</div><div class="value">$(Get-PercentText $serverInactiveCount $serverTotal)</div></div>
        </div>

        <div class="bulk-toolbar">
            <button type="button" onclick="toggleAllVisible('servers', true)">Select visible</button>
            <button type="button" onclick="toggleAllVisible('servers', false)">Unselect visible</button>
            <button type="button" onclick="openBulkActionModal()">Bulk actions</button>
            <button type="button" onclick="clearSelections()">Clear all selections</button>
            <span id="bulkSelectionInfoServers" class="muted">0 selected in total</span>
        </div>

        <div class="toolbar">
            <button type="button" onclick="resetFilters('servers')">Reset filters</button>
            <label>
                Rows per page:
                <select onchange="setPageSize('servers', this.value)">
                    <option value="10" selected>10</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                    <option value="250">250</option>
                    <option value="500">500</option>
                    <option value="1000">1000</option>
                    <option value="all">ALL</option>
                </select>
            </label>
            <button type="button" onclick="prevPage('servers')">Prev</button>
            <button type="button" onclick="nextPage('servers')">Next</button>
            <input type="search" placeholder="Search servers..." oninput="setSearch('servers', this.value)">
            <span id="serverResultInfo" class="muted"></span>
            <span id="serverPageInfo" class="muted"></span>
        </div>

        <div class="table-wrap">
            <table id="serverTable">
                <thead>
                    <tr>
                        <th class="no-sort"><input type="checkbox" onclick="toggleAllVisible('servers', this.checked)"></th>
                        <th onclick="sortTable('serverTable', 1)">Name</th>
                        <th onclick="sortTable('serverTable', 2)">DNS Hostname</th>
                        <th onclick="sortTable('serverTable', 3)">Enabled</th>
                        <th onclick="sortTable('serverTable', 4)">Role</th>
                        <th onclick="sortTable('serverTable', 5)">Operating System</th>
                        <th onclick="sortTable('serverTable', 6)">OS Version</th>
                        <th onclick="sortTable('serverTable', 7)">Last Logon</th>
                        <th onclick="sortTable('serverTable', 8)">Days Since Logon</th>
                        <th onclick="sortTable('serverTable', 9)">Inactive</th>
                        <th onclick="sortTable('serverTable', 10)">Canonical Name</th>
                        <th onclick="sortTable('serverTable', 11)">Risk Hint</th>
                    </tr>
                </thead>
                <tbody>
                    $($serverRows.ToString())
                </tbody>
            </table>
        </div>
    </div>

    <div id="bulkModal" class="modal-backdrop" onclick="backdropClose(event)">
        <div class="modal">
            <h2>Bulk action preview</h2>
            <p id="bulkModalSummary" class="muted">0 object(s) selected.</p>

            <div class="warn-box">
                This report is still read-only. The modal only generates reviewable scripts or CSV output. No AD changes are executed from the browser.
            </div>

            <div id="bulkWarnings" class="warn-box-danger" style="display:none; margin-top:12px;"></div>

            <div class="modal-grid" style="margin-top:12px;">
                <div class="helper-grid">
                    <div>
                        <label for="bulkActionType">Action</label>
                        <select id="bulkActionType" onchange="renderBulkPreview()">
                            <option value="disable">Disable selected</option>
                            <option value="move">Move to quarantine OU</option>
                            <option value="disablemove">Disable and move to quarantine OU</option>
                            <option value="resetadmincount">Set adminCount=0 for disabled adminCount users</option>
                            <option value="delete">Generate delete script</option>
                            <option value="exportcsv">Export selected CSV</option>
                        </select>
                    </div>

                    <div>
                        <label for="bulkTargetMode">Target OU mode</label>
                        <select id="bulkTargetMode" onchange="handleTargetChange(); renderBulkPreview();">
                            <option value="computers">Koneet -> Disabled Computer Accounts</option>
                            <option value="users">Käyttäjät -> Disabled Users</option>
                            <option value="custom">Custom</option>
                        </select>
                    </div>
                </div>

                <div class="helper-grid">
                    <div>
                        <label for="bulkTargetOu">Target OU for move action</label>
                        <input type="text" id="bulkTargetOu" placeholder="OU=Quarantine,DC=contoso,DC=com" oninput="renderBulkPreview()" disabled>
                    </div>

                    <div>
                        <label for="bulkStampText">Description stamp text</label>
                        <input type="text" id="bulkStampText" placeholder="Quarantined from AD audit" oninput="renderBulkPreview()">
                    </div>
                </div>

                <div>
                    <div class="check-inline">
                        <input type="checkbox" id="bulkAddStamp" onchange="renderBulkPreview()">
                        <label for="bulkAddStamp" style="margin:0;font-weight:400;">Add description stamp for disable / move / disable+move actions</label>
                    </div>
                </div>

                <div>
                    <label for="bulkPreview">Preview</label>
                    <textarea id="bulkPreview" spellcheck="false"></textarea>
                </div>
            </div>

            <div class="modal-actions">
                <button type="button" onclick="copyBulkPreview()">Copy output</button>
                <button type="button" onclick="downloadBulkPreview()">Download</button>
                <button type="button" onclick="closeBulkActionModal()">Close</button>
            </div>
        </div>
    </div>

<script>
let userFilter = "all";
let computerFilter = "all";
let serverFilter = "all";
let currentSortState = {};

let pagingState = {
    users:     { page: 1, pageSize: 10, search: "" },
    computers: { page: 1, pageSize: 10, search: "" },
    servers:   { page: 1, pageSize: 10, search: "" }
};

const presetTargetOus = {
    computers: "OU=Disabled Computer Accounts,DC=example,DC=local",
    users: "OU=Disabled Users,DC=example,DC=local"
};

function showTab(tabName) {
    document.getElementById("usersTab").style.display = tabName === "users" ? "block" : "none";
    document.getElementById("computersTab").style.display = tabName === "computers" ? "block" : "none";
    document.getElementById("serversTab").style.display = tabName === "servers" ? "block" : "none";

    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));

    if (tabName === "users") document.querySelectorAll(".tab-btn")[0].classList.add("active");
    if (tabName === "computers") document.querySelectorAll(".tab-btn")[1].classList.add("active");
    if (tabName === "servers") document.querySelectorAll(".tab-btn")[2].classList.add("active");
}

function openFinding(target, filterName) {
    if (!target) return;

    showTab(target);
    applyFilter(target, filterName || "all");

    const sectionId =
        target === "users" ? "usersTab" :
        target === "computers" ? "computersTab" :
        "serversTab";

    const section = document.getElementById(sectionId);
    if (section) {
        section.scrollIntoView({ behavior: "smooth", block: "start" });
    }
}

function getRowsFor(target) {
    if (target === "users") return Array.from(document.querySelectorAll("#userTable tbody tr"));
    if (target === "servers") return Array.from(document.querySelectorAll("#serverTable tbody tr"));
    return Array.from(document.querySelectorAll("#computerTable tbody tr"));
}

function getFilterLabel(target, filterName) {
    if (filterName === "all") return "All";
    if (filterName === "cleanup") return "Cleanup Candidates";
    if (filterName === "enabled") return "Enabled";
    if (filterName === "disabled") return "Disabled";
    if (filterName === "inactive") return "Inactive";
    if (filterName === "nologon") return "No Last Logon";
    if (target === "users" && filterName === "locked") return "Locked Out";
    if (target === "users" && filterName === "pwdnever") return "Pwd Never Expires";
    if (target === "users" && filterName === "adminlike") return "Admin-like";
    if (target === "users" && filterName === "privileged") return "Privileged Accounts";
    if (target === "users" && filterName === "privinactive") return "Privileged + Inactive";
    if (target === "users" && filterName === "protectedbuiltin") return "Protected Built-in";
    if (target === "computers" && filterName === "oldos") return "Legacy Client OS";
    if (target === "computers" && filterName === "win10older") return "Windows 10 / Older";
    if (target === "computers" && filterName === "enabledinactive") return "Enabled + Inactive";
    if (target === "servers" && filterName === "active") return "Active";
    if (target === "servers" && filterName === "highrisk") return "Enabled + Inactive (High Risk)";
    return filterName;
}

function matchesFilter(row, target, filterName) {
    if (filterName === "all") return true;
    if (filterName === "cleanup") return row.dataset.cleanup === "true";
    if (filterName === "enabled") return row.dataset.enabled === "true";
    if (filterName === "disabled") return row.dataset.disabled === "true";
    if (filterName === "inactive") return row.dataset.inactive === "true";
    if (filterName === "nologon") return row.dataset.nologon === "true";

    if (target === "users") {
        if (filterName === "locked") return row.dataset.locked === "true";
        if (filterName === "pwdnever") return row.dataset.pwdnever === "true";
        if (filterName === "adminlike") return row.dataset.adminlike === "true";
        if (filterName === "privileged") return row.dataset.privileged === "true";
        if (filterName === "privinactive") return row.dataset.privinactive === "true";
        if (filterName === "protectedbuiltin") return row.dataset.protectedbuiltin === "true";
    }

    if (target === "computers") {
        if (filterName === "oldos") return row.dataset.oldos === "true";
        if (filterName === "win10older") return row.dataset.win10older === "true";
        if (filterName === "enabledinactive") return row.dataset.enabledinactive === "true";
    }

    if (target === "servers") {
        if (filterName === "active") return row.dataset.active === "true";
        if (filterName === "highrisk") return row.dataset.highrisk === "true";
    }

    return true;
}

function getCurrentFilter(target) {
    if (target === "users") return userFilter;
    if (target === "servers") return serverFilter;
    return computerFilter;
}

function setCurrentFilter(target, value) {
    if (target === "users") userFilter = value;
    else if (target === "servers") serverFilter = value;
    else computerFilter = value;
}

function matchesSearch(row, searchValue) {
    if (!searchValue) return true;
    return row.textContent.toLowerCase().includes(searchValue);
}

function getFilteredRows(target) {
    const rows = getRowsFor(target);
    const filterName = getCurrentFilter(target);
    const searchValue = (pagingState[target].search || "").toLowerCase().trim();

    return rows.filter(row => matchesFilter(row, target, filterName) && matchesSearch(row, searchValue));
}

function updatePaging(target) {
    const rows = getRowsFor(target);
    const filteredRows = getFilteredRows(target);
    const state = pagingState[target];
    const pageSize = state.pageSize;

    rows.forEach(row => row.classList.add("hidden-row"));

    if (pageSize === "all") {
        filteredRows.forEach(row => row.classList.remove("hidden-row"));
        state.page = 1;
    } else {
        const totalPages = Math.max(1, Math.ceil(filteredRows.length / pageSize));
        if (state.page > totalPages) state.page = totalPages;
        if (state.page < 1) state.page = 1;

        const start = (state.page - 1) * pageSize;
        const end = start + pageSize;

        filteredRows.slice(start, end).forEach(row => row.classList.remove("hidden-row"));
    }

    updateResultInfo(target);
    updatePageInfo(target);
}

function applyFilter(target, filterName) {
    setCurrentFilter(target, filterName);
    pagingState[target].page = 1;

    document.querySelectorAll('.card[data-target="' + target + '"]').forEach(card => {
        card.classList.toggle("active", card.dataset.filter === filterName);
    });

    updatePaging(target);
}

function resetFilters(target) {
    pagingState[target].search = "";
    const searchInput = target === "users"
        ? document.querySelector('#usersTab input[type="search"]')
        : target === "servers"
            ? document.querySelector('#serversTab input[type="search"]')
            : document.querySelector('#computersTab input[type="search"]');

    if (searchInput) searchInput.value = "";
    applyFilter(target, "all");
}

function setPageSize(target, value) {
    pagingState[target].pageSize = value === "all" ? "all" : Number(value);
    pagingState[target].page = 1;
    updatePaging(target);
}

function prevPage(target) {
    if (pagingState[target].pageSize === "all") return;
    pagingState[target].page--;
    updatePaging(target);
}

function nextPage(target) {
    if (pagingState[target].pageSize === "all") return;
    pagingState[target].page++;
    updatePaging(target);
}

function setSearch(target, value) {
    pagingState[target].search = value || "";
    pagingState[target].page = 1;
    updatePaging(target);
}

function updateResultInfo(target) {
    const total = getRowsFor(target).length;
    const filtered = getFilteredRows(target).length;
    const filterName = getCurrentFilter(target);

    const targetEl = target === "users"
        ? document.getElementById("userResultInfo")
        : target === "servers"
            ? document.getElementById("serverResultInfo")
            : document.getElementById("computerResultInfo");

    if (targetEl) {
        targetEl.textContent = "Showing " + filtered + " filtered rows of " + total + ". Active filter: " + getFilterLabel(target, filterName);
    }
}

function updatePageInfo(target) {
    const filtered = getFilteredRows(target).length;
    const state = pagingState[target];
    const pageSize = state.pageSize;

    let text = "";
    if (pageSize === "all") {
        text = "Page 1 / 1";
    } else {
        const totalPages = Math.max(1, Math.ceil(filtered / pageSize));
        text = "Page " + state.page + " / " + totalPages;
    }

    const el = target === "users"
        ? document.getElementById("userPageInfo")
        : target === "servers"
            ? document.getElementById("serverPageInfo")
            : document.getElementById("computerPageInfo");

    if (el) el.textContent = text;
}

function attachCardHandlers() {
    document.querySelectorAll(".card").forEach(card => {
        card.addEventListener("click", function () {
            applyFilter(this.dataset.target, this.dataset.filter);
        });
    });
}

function getCellValue(row, columnIndex) {
    const cell = row.children[columnIndex];
    if (!cell) return "";
    return (cell.getAttribute("data-sort") || cell.textContent || "").trim();
}

function parseSortableValue(value) {
    const lower = String(value || "").toLowerCase();

    if (lower === "true") return 1;
    if (lower === "false") return 0;

    const numeric = Number(value);
    if (!isNaN(numeric) && value !== "") return numeric;

    const time = Date.parse(value);
    if (!isNaN(time)) return time;

    return lower;
}

function sortTable(tableId, columnIndex) {
    const tbody = document.querySelector("#" + tableId + " tbody");
    const rows = Array.from(tbody.querySelectorAll("tr"));
    const key = tableId + ":" + columnIndex;

    if (!currentSortState[key]) {
        currentSortState[key] = { asc: true };
    } else {
        currentSortState[key].asc = !currentSortState[key].asc;
    }

    const asc = currentSortState[key].asc;

    rows.sort((a, b) => {
        const aVal = parseSortableValue(getCellValue(a, columnIndex));
        const bVal = parseSortableValue(getCellValue(b, columnIndex));

        if (aVal < bVal) return asc ? -1 : 1;
        if (aVal > bVal) return asc ? 1 : -1;
        return 0;
    });

    rows.forEach(row => tbody.appendChild(row));

    if (tableId === "userTable") updatePaging("users");
    else if (tableId === "serverTable") updatePaging("servers");
    else updatePaging("computers");
}

function getSelectedCheckboxes() {
    return Array.from(document.querySelectorAll(".row-select:checked"));
}

function updateBulkSelection() {
    const total = getSelectedCheckboxes().length;

    const usersEl = document.getElementById("bulkSelectionInfoUsers");
    const computersEl = document.getElementById("bulkSelectionInfoComputers");
    const serversEl = document.getElementById("bulkSelectionInfoServers");

    if (usersEl) usersEl.textContent = total + " selected in total";
    if (computersEl) computersEl.textContent = total + " selected in total";
    if (serversEl) serversEl.textContent = total + " selected in total";
}

function toggleAllVisible(target, checked) {
    const visibleRows = getRowsFor(target).filter(row => !row.classList.contains("hidden-row"));
    visibleRows.forEach(row => {
        const cb = row.querySelector(".row-select");
        if (cb) cb.checked = checked;
    });
    updateBulkSelection();
}

function clearSelections() {
    document.querySelectorAll(".row-select:checked").forEach(cb => cb.checked = false);
    updateBulkSelection();
    renderBulkPreview();
}

function getSelectedObjects() {
    return getSelectedCheckboxes().map(cb => ({
        target: cb.dataset.target || "",
        objectType: cb.dataset.objecttype || "",
        name: cb.dataset.name || "",
        displayName: cb.dataset.displayname || "",
        sam: cb.dataset.sam || "",
        upn: cb.dataset.upn || "",
        dn: cb.dataset.dn || "",
        enabled: cb.dataset.enabled === "true",
        adminLike: cb.dataset.adminlike === "true",
        privileged: cb.dataset.privileged === "true",
        protectedBuiltIn: cb.dataset.protectedbuiltin === "true",
        protectedReason: cb.dataset.protectedreason || "",
        server: cb.dataset.server === "true"
    }));
}

function openBulkActionModal() {
    document.getElementById("bulkModal").style.display = "flex";
    renderBulkPreview();
}

function closeBulkActionModal() {
    document.getElementById("bulkModal").style.display = "none";
}

function backdropClose(event) {
    if (event.target && event.target.id === "bulkModal") {
        closeBulkActionModal();
    }
}

function handleTargetChange() {
    const mode = document.getElementById("bulkTargetMode").value;
    const input = document.getElementById("bulkTargetOu");

    if (mode === "computers") {
        input.value = presetTargetOus.computers;
        input.disabled = true;
    } else if (mode === "users") {
        input.value = presetTargetOus.users;
        input.disabled = true;
    } else {
        input.value = "";
        input.disabled = false;
    }
}

function isLikelyValidTargetDn(value) {
    const s = String(value || "").trim();
    if (!s) return false;
    return /(^|,)(OU|CN)=[^,]+/i.test(s) && /(^|,)DC=[^,]+/i.test(s);
}

function escapePs(value) {
    return String(value || "").replace(/"/g, '""');
}

function csvEscape(value) {
    const s = String(value || "");
    return '"' + s.replace(/"/g, '""') + '"';
}

function isProtectedFromBulkActions(obj) {
    return obj.protectedBuiltIn === true;
}

function buildStampLines(obj, stampText) {
    if (!stampText) return [];

    if (obj.objectType === "User" && obj.sam) {
        return [
            '`$existingDescription = (Get-ADUser -Identity "' + escapePs(obj.sam) + '" -Properties Description).Description',
            '`$newDescription = if ([string]::IsNullOrWhiteSpace(`$existingDescription)) { "' + escapePs(stampText) + '" } else { `$existingDescription + " | ' + escapePs(stampText) + '" }',
            'Set-ADUser -Identity "' + escapePs(obj.sam) + '" -Description `$newDescription'
        ];
    }

    if (obj.objectType === "Computer" && obj.dn) {
        return [
            '`$existingDescription = (Get-ADComputer -Identity "' + escapePs(obj.dn) + '" -Properties Description).Description',
            '`$newDescription = if ([string]::IsNullOrWhiteSpace(`$existingDescription)) { "' + escapePs(stampText) + '" } else { `$existingDescription + " | ' + escapePs(stampText) + '" }',
            'Set-ADComputer -Identity "' + escapePs(obj.dn) + '" -Description `$newDescription'
        ];
    }

    return [];
}

function renderBulkWarnings(selected, action, blockedDelete) {
    const warningsEl = document.getElementById("bulkWarnings");
    let warnings = [];

    const privilegedCount = selected.filter(x => x.privileged).length;
    const protectedBuiltInCount = selected.filter(x => x.protectedBuiltIn).length;
    const serverCount = selected.filter(x => x.server).length;
    const enabledCount = selected.filter(x => x.enabled).length;
    const resetAdminEligibleCount = selected.filter(x => x.objectType === "User" && !x.enabled && x.adminLike).length;

    if (protectedBuiltInCount > 0) warnings.push(protectedBuiltInCount + " protected built-in account(s) selected");
    if (privilegedCount > 0) warnings.push(privilegedCount + " privileged object(s) selected");
    if (serverCount > 0) warnings.push(serverCount + " server object(s) selected");
    if (enabledCount > 0) warnings.push(enabledCount + " enabled object(s) selected");

    if (action === "resetadmincount" && resetAdminEligibleCount > 0) {
        warnings.push(resetAdminEligibleCount + " disabled user(s) with adminCount/admin-like flag eligible for reset");
    }

    if (action === "delete" && blockedDelete.length > 0) {
        warnings.push("Delete script generation is blocked for risky objects (protected built-in / privileged / server / enabled)");
    }

    if (warnings.length === 0) {
        warningsEl.style.display = "none";
        warningsEl.innerHTML = "";
        return;
    }

    warningsEl.style.display = "block";
    warningsEl.innerHTML = warnings.map(x => "• " + x).join("<br>");
}

function renderBulkPreview() {
    const selected = getSelectedObjects();
    const action = document.getElementById("bulkActionType").value;
    const targetMode = document.getElementById("bulkTargetMode").value;
    const targetOu = (document.getElementById("bulkTargetOu").value || "").trim();
    const addStamp = document.getElementById("bulkAddStamp").checked;
    const stampTextRaw = (document.getElementById("bulkStampText").value || "").trim();
    const stampText = stampTextRaw || "Quarantined from AD audit";
    const preview = document.getElementById("bulkPreview");
    const summary = document.getElementById("bulkModalSummary");

    const userCount = selected.filter(x => x.objectType === "User").length;
    const computerCount = selected.filter(x => x.objectType === "Computer").length;
    const privilegedCount = selected.filter(x => x.privileged).length;
    const protectedBuiltInCount = selected.filter(x => x.protectedBuiltIn).length;
    const serverCount = selected.filter(x => x.server).length;
    const enabledCount = selected.filter(x => x.enabled).length;
    const resetAdminEligibleCount = selected.filter(x => x.objectType === "User" && !x.enabled && x.adminLike).length;
    const blockedDelete = selected.filter(x => x.protectedBuiltIn || x.privileged || x.server || x.enabled);

    summary.textContent =
        selected.length + " object(s) selected | Users: " + userCount +
        " | Computers: " + computerCount +
        " | Protected built-in: " + protectedBuiltInCount +
        " | Privileged: " + privilegedCount +
        " | Servers: " + serverCount +
        " | Enabled: " + enabledCount +
        " | adminCount reset eligible: " + resetAdminEligibleCount +
        " | Delete blocked: " + blockedDelete.length;

    renderBulkWarnings(selected, action, blockedDelete);

    if (selected.length === 0) {
        preview.value = "# No objects selected";
        return;
    }

    if ((action === "move" || action === "disablemove")) {
        if (!targetOu) {
            preview.value = "# Enter target OU first";
            return;
        }

        if (!isLikelyValidTargetDn(targetOu)) {
            preview.value = "# Target OU / container path looks invalid";
            return;
        }

        const hasUsers = selected.some(x => x.objectType === "User");
        const hasComputers = selected.some(x => x.objectType === "Computer");

        if (targetMode === "computers" && hasUsers) {
            preview.value = "# Mixed or user selection detected.\n# 'Koneet' preset can only be used for Computer objects.\n# Use 'Käyttäjät' or 'Custom' instead.";
            return;
        }

        if (targetMode === "users" && hasComputers) {
            preview.value = "# Mixed or computer selection detected.\n# 'Käyttäjät' preset can only be used for User objects.\n# Use 'Koneet' or 'Custom' instead.";
            return;
        }
    }

    let lines = [];

    if (action === "exportcsv") {
        lines.push("ObjectType,Name,DisplayName,SamAccountName,UPN,DN,Enabled,AdminLike,ProtectedBuiltIn,ProtectedReason,Privileged,Server,Target");
        selected.forEach(obj => {
            lines.push([
                csvEscape(obj.objectType),
                csvEscape(obj.name),
                csvEscape(obj.displayName),
                csvEscape(obj.sam),
                csvEscape(obj.upn),
                csvEscape(obj.dn),
                csvEscape(String(obj.enabled)),
                csvEscape(String(obj.adminLike)),
                csvEscape(String(obj.protectedBuiltIn)),
                csvEscape(obj.protectedReason),
                csvEscape(String(obj.privileged)),
                csvEscape(String(obj.server)),
                csvEscape("")
            ].join(","));
        });

        preview.value = lines.join("\n");
        return;
    }

    lines.push('`$ErrorActionPreference = "Stop"');
    lines.push('Import-Module ActiveDirectory');
    lines.push('');
    lines.push('# Generated by AD DS Object Audit Report v2.5');
    lines.push('# Generated at: ' + new Date().toISOString());
    lines.push('# Selected objects: ' + selected.length);
    lines.push('# Action: ' + action);
    if (addStamp && action !== "delete" && action !== "resetadmincount") {
        lines.push('# Description stamp enabled: ' + stampText);
    }
    lines.push('');
    lines.push('if (-not (Test-Path "C:\\Temp")) { New-Item -ItemType Directory -Path "C:\\Temp" -Force | Out-Null }');
    lines.push('Start-Transcript -Path ("C:\\Temp\\AD_BulkAction_" + (Get-Date -Format "ddMMyyyy_HHmmss") + ".log")');
    lines.push('');

    if (action === "disable") {
        selected.forEach(obj => {
            if (isProtectedFromBulkActions(obj)) {
                lines.push('# BLOCKED: ' + escapePs(obj.objectType) + ' | ' + escapePs(obj.name) + ' | protected built-in account');
                lines.push('');
                return;
            }

            if (obj.objectType === "User") {
                if (obj.sam) {
                    lines.push('Disable-ADAccount -Identity "' + escapePs(obj.sam) + '"');
                    if (addStamp) buildStampLines(obj, stampText).forEach(line => lines.push(line));
                } else {
                    lines.push('# Skipped user without SamAccountName: ' + escapePs(obj.name));
                }
            } else {
                if (obj.dn) {
                    lines.push('Disable-ADAccount -Identity "' + escapePs(obj.dn) + '"');
                    if (addStamp) buildStampLines(obj, stampText).forEach(line => lines.push(line));
                } else {
                    lines.push('# Skipped computer without DN: ' + escapePs(obj.name));
                }
            }
            lines.push('');
        });
    }
    else if (action === "move") {
        selected.forEach(obj => {
            if (isProtectedFromBulkActions(obj)) {
                lines.push('# BLOCKED: ' + escapePs(obj.objectType) + ' | ' + escapePs(obj.name) + ' | protected built-in account');
                lines.push('');
                return;
            }

            if (obj.dn) {
                if (addStamp) buildStampLines(obj, stampText).forEach(line => lines.push(line));
                lines.push('Move-ADObject -Identity "' + escapePs(obj.dn) + '" -TargetPath "' + escapePs(targetOu) + '"');
            } else {
                lines.push('# Skipped object without DN: ' + escapePs(obj.name));
            }
            lines.push('');
        });
    }
    else if (action === "disablemove") {
        selected.forEach(obj => {
            if (isProtectedFromBulkActions(obj)) {
                lines.push('# BLOCKED: ' + escapePs(obj.objectType) + ' | ' + escapePs(obj.name) + ' | protected built-in account');
                lines.push('');
                return;
            }

            if (obj.objectType === "User") {
                if (obj.sam) lines.push('Disable-ADAccount -Identity "' + escapePs(obj.sam) + '"');
                else lines.push('# Skipped disable for user without SamAccountName: ' + escapePs(obj.name));
            } else {
                if (obj.dn) lines.push('Disable-ADAccount -Identity "' + escapePs(obj.dn) + '"');
                else lines.push('# Skipped disable for computer without DN: ' + escapePs(obj.name));
            }

            if (addStamp) buildStampLines(obj, stampText).forEach(line => lines.push(line));

            if (obj.dn) {
                lines.push('Move-ADObject -Identity "' + escapePs(obj.dn) + '" -TargetPath "' + escapePs(targetOu) + '"');
            } else {
                lines.push('# Skipped move due to missing DN: ' + escapePs(obj.name));
            }

            lines.push('');
        });
    }
    else if (action === "resetadmincount") {
        const eligible = selected.filter(obj =>
            obj.objectType === "User" &&
            obj.enabled === false &&
            obj.adminLike === true
        );

        const ineligible = selected.filter(obj =>
            !(obj.objectType === "User" && obj.enabled === false && obj.adminLike === true)
        );

        if (ineligible.length > 0) {
            lines.push('# Some selected objects are not eligible for adminCount reset');
            lines.push('# Requirement: User object + disabled + adminCount/admin-like flag');
            lines.push('');

            ineligible.forEach(obj => {
                let reasons = [];
                if (obj.objectType !== "User") reasons.push("not a user");
                if (obj.enabled) reasons.push("enabled");
                if (!obj.adminLike) reasons.push("adminCount/admin-like flag not present");

                lines.push('# SKIPPED: ' + escapePs(obj.objectType) + ' | ' + escapePs(obj.name) + ' | ' + reasons.join(", "));
            });

            lines.push('');
            lines.push('# Conditionally eligible targets below');
            lines.push('# Final safety check is done at execution time: disabled + adminCount/admin-like + NOT member of privileged groups');
            lines.push('');
        }

        if (eligible.length === 0) {
            lines.push('# No eligible disabled adminCount users selected');
        } else {
            lines.push('`$PrivilegedGroups = @(');
            lines.push('    "Domain Admins",');
            lines.push('    "Enterprise Admins",');
            lines.push('    "Schema Admins",');
            lines.push('    "Administrators",');
            lines.push('    "Account Operators",');
            lines.push('    "Server Operators",');
            lines.push('    "Backup Operators",');
            lines.push('    "Print Operators",');
            lines.push('    "DnsAdmins",');
            lines.push('    "Key Admins",');
            lines.push('    "Enterprise Key Admins",');
            lines.push('    "Protected Users"');
            lines.push(')');
            lines.push('');

            eligible.forEach(obj => {
                const identity = obj.sam ? escapePs(obj.sam) : escapePs(obj.dn);

                if (!identity) {
                    lines.push('# Skipped user without SamAccountName/DN: ' + escapePs(obj.name));
                    lines.push('');
                    return;
                }

                lines.push('# Processing: ' + escapePs(obj.name || obj.sam || obj.dn));
                lines.push('`$adUser = `$null');
                lines.push('try {');
                lines.push('    `$adUser = Get-ADUser -Identity "' + identity + '" -Properties Enabled,adminCount');
                lines.push('} catch {');
                lines.push('    Write-Host "SKIP: user not found -> ' + identity + '" -ForegroundColor Red');
                lines.push('}');
                lines.push('');
                lines.push('if (-not `$adUser) {');
                lines.push('    Write-Host "SKIP: unable to continue for -> ' + identity + '" -ForegroundColor Red');
                lines.push('}');
                lines.push('elseif (`$adUser.Enabled -eq `$true) {');
                lines.push('    Write-Host "SKIP: still enabled -> ' + identity + '" -ForegroundColor DarkYellow');
                lines.push('}');
                lines.push('elseif (`$adUser.adminCount -ne 1) {');
                lines.push('    Write-Host "SKIP: adminCount is not 1 -> ' + identity + '" -ForegroundColor DarkYellow');
                lines.push('}');
                lines.push('else {');
                lines.push('    `$groupNames = @(Get-ADPrincipalGroupMembership -Identity "' + identity + '" | Select-Object -ExpandProperty Name)');
                lines.push('    `$matchedPrivilegedGroups = @(`$groupNames | Where-Object { `$PrivilegedGroups -contains `$_ })');
                lines.push('');
                lines.push('    if (`$matchedPrivilegedGroups.Count -gt 0) {');
                lines.push('        Write-Host ("SKIP: still privileged -> ' + identity + ' | " + (`$matchedPrivilegedGroups -join ", ")) -ForegroundColor Red');
                lines.push('    }');
                lines.push('    else {');
                lines.push('        Set-ADUser -Identity "' + identity + '" -Replace @{adminCount=0}');
                lines.push('        Write-Host "OK: adminCount reset to 0 -> ' + identity + '" -ForegroundColor Green');
                lines.push('        # Alternative cleanup form if needed:');
                lines.push('        # Set-ADUser -Identity "' + identity + '" -Clear adminCount');
                lines.push('    }');
                lines.push('}');
                lines.push('');
            });

            lines.push('# NOTE: Resetting adminCount does not remove ACL inheritance protections by itself.');
            lines.push('# If needed, review AdminSDHolder effects and inheritance separately.');
        }
    }
    else if (action === "delete") {
        if (blockedDelete.length > 0) {
            lines.push('# Delete blocked for risky objects');
            lines.push('# Remove blocked objects from selection or use disable/move first.');
            lines.push('');

            blockedDelete.forEach(obj => {
                let reasons = [];
                if (obj.protectedBuiltIn) reasons.push("protected built-in");
                if (obj.privileged) reasons.push("privileged");
                if (obj.server) reasons.push("server");
                if (obj.enabled) reasons.push("enabled");

                lines.push('# BLOCKED: ' + escapePs(obj.objectType) + ' | ' + escapePs(obj.name) + ' | ' + reasons.join(", "));
            });

            lines.push('');
            lines.push('# Allowed delete targets below');
            lines.push('');
        }

        const allowedDelete = selected.filter(obj => !(obj.protectedBuiltIn || obj.privileged || obj.server || obj.enabled));

        if (allowedDelete.length === 0) {
            lines.push('# No allowed delete targets remain after safety checks');
        } else {
            allowedDelete.forEach(obj => {
                if (obj.objectType === "User") {
                    if (obj.sam) lines.push('Remove-ADUser -Identity "' + escapePs(obj.sam) + '" -Confirm:`$true');
                    else lines.push('# Skipped user without SamAccountName: ' + escapePs(obj.name));
                } else {
                    if (obj.dn) lines.push('Remove-ADComputer -Identity "' + escapePs(obj.dn) + '" -Confirm:`$true');
                    else lines.push('# Skipped computer without DN: ' + escapePs(obj.name));
                }
            });
        }

        lines.push('');
        lines.push('# NOTE: Description stamp is intentionally not applied to delete actions');
    }

    lines.push('');
    lines.push('Stop-Transcript');

    preview.value = lines.join("\n");
}

async function copyBulkPreview() {
    const preview = document.getElementById("bulkPreview");
    try {
        await navigator.clipboard.writeText(preview.value || "");
        alert("Output copied to clipboard.");
    } catch (e) {
        preview.select();
        document.execCommand("copy");
        alert("Output copied to clipboard.");
    }
}

function downloadBulkPreview() {
    const preview = document.getElementById("bulkPreview").value || "";
    const action = document.getElementById("bulkActionType").value || "bulk";
    const isCsv = action === "exportcsv";
    const extension = isCsv ? "csv" : "ps1";
    const mimeType = isCsv ? "text/csv;charset=utf-8" : "text/plain;charset=utf-8";

    const blob = new Blob([preview], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ad-bulk-" + action + "." + extension;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

attachCardHandlers();
handleTargetChange();
applyFilter("users", "all");
applyFilter("computers", "all");
applyFilter("servers", "all");
updateBulkSelection();
</script>
</body>
</html>
"@

Set-Content -Path $htmlPath -Value $html -Encoding UTF8

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "HTML         : $htmlPath"
Write-Host ""
Write-Host "This was a read-only audit. No AD changes were made." -ForegroundColor Yellow
Write-Host "The generated HTML can preview safe PowerShell bulk action scripts, adminCount reset scripts, and CSV exports for manual review." -ForegroundColor Yellow
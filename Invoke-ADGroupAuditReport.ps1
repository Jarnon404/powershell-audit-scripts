<#
.SYNOPSIS
    Active Directory Group Audit Dashboard.

.DESCRIPTION
    Auditoi Active Directory -ryhmät, jäsenyydet, tyhjät ryhmät, riskiluokat ja ryhmähallinnan löydökset HTML-dashboardiksi.

.REQUIREMENTS
    - ActiveDirectory PowerShell -moduuli ja lukuoikeus AD-ryhmiin

.OUTPUTS
    - HTML/CSV-raportit AD-ryhmistä ja jäsenyyksistä

.EXAMPLE
    .\Invoke-ADGroupAuditReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Invoke-ADGroupAuditReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY COLLECTION: The audit collection is intended to be read-only. The generated report may include optional bulk-action helper snippets or CSV exports for manual review only. Review generated helper code separately and run it only if you intentionally choose to do so.
#>

param(
    [string]$OutputFolder = (Join-Path $PSScriptRoot "output\adgroups"),
    [string]$SearchBase = "",
    [int]$MaxMemberListPreview = 20,
    [switch]$IncludeRecursiveMemberCount,
    [int]$StaleYears = 3
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
    return "<span class='badge $Class'>" + ([System.Net.WebUtility]::HtmlEncode([string]$Text)) + "</span>"
}

function Get-DateText {
    param($DateValue)
    if ($null -eq $DateValue) { return "" }

    try {
        return ([datetime]$DateValue).ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        return [string]$DateValue
    }
}

function Get-StaleScore {
    param(
        [int]$DirectMemberCount,
        [bool]$IsPrivileged,
        [string]$Description,
        [datetime]$WhenChanged,
        [datetime]$CutoffDate,
        [bool]$MemberReadError
    )

    $score = 0

    if ($MemberReadError) { $score += 40 }
    if ($IsPrivileged) { $score -= 100 }
    if ($DirectMemberCount -eq 0) { $score += 40 }
    if ([string]::IsNullOrWhiteSpace($Description)) { $score += 20 }

    try {
        if ($WhenChanged -lt $CutoffDate) {
            $score += 30
        }
    }
    catch {}

    if ($score -lt 0) { $score = 0 }
    return $score
}

function Get-StaleLevel {
    param(
        [int]$StaleScore,
        [bool]$IsPrivileged
    )

    if ($IsPrivileged) { return "Protected" }
    if ($StaleScore -ge 70) { return "High" }
    if ($StaleScore -ge 40) { return "Medium" }
    return "Low"
}

function Get-CleanupSuggestion {
    param(
        [int]$DirectMemberCount,
        [int]$RecursiveMemberCount,
        [bool]$IsPrivileged,
        [string]$Description,
        [bool]$MemberReadError,
        [int]$StaleScore
    )

    if ($MemberReadError) {
        return "Review: member enumeration failed"
    }

    if ($IsPrivileged) {
        return "Review manually (privileged group)"
    }

    if ($DirectMemberCount -eq 0 -and $StaleScore -ge 70) {
        return "Strong review candidate"
    }

    if ($DirectMemberCount -eq 0) {
        return "Review: empty group"
    }

    if ($RecursiveMemberCount -ge 250) {
        return "Review: large membership"
    }

    if ([string]::IsNullOrWhiteSpace($Description)) {
        return "Review: no description"
    }

    if ($StaleScore -ge 40) {
        return "Review: stale indicators"
    }

    return "OK"
}

function Get-GroupRiskLevel {
    param(
        [int]$DirectMemberCount,
        [int]$RecursiveMemberCount,
        [bool]$IsPrivileged,
        [bool]$MemberReadError
    )

    if ($MemberReadError) { return "High" }
    if ($IsPrivileged) { return "High" }
    if ($RecursiveMemberCount -ge 1000) { return "High" }
    if ($RecursiveMemberCount -ge 250) { return "Medium" }
    if ($DirectMemberCount -eq 0) { return "Medium" }
    return "Low"
}

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath   = Join-Path $OutputFolder ("groups_report_{0}.csv" -f $timestamp)
$htmlPath  = Join-Path $OutputFolder "index.html"

$domainInfo = Get-ADDomain
$staleCutoffDate = (Get-Date).AddYears(-$StaleYears)

$privilegedGroupNames = @(
    "Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators",
    "Group Policy Creator Owners",
    "DnsAdmins",
    "Cert Publishers",
    "Remote Desktop Users",
    "Protected Users",
    "Key Admins",
    "Enterprise Key Admins"
)

Write-Host "Haetaan AD-ryhmät..." -ForegroundColor Cyan

$groupProperties = @(
    "SamAccountName",
    "GroupCategory",
    "GroupScope",
    "whenCreated",
    "whenChanged",
    "DistinguishedName",
    "Description"
)

$allGroups = if ([string]::IsNullOrWhiteSpace($SearchBase)) {
    Get-ADGroup -Filter * -Properties $groupProperties
}
else {
    Get-ADGroup -Filter * -SearchBase $SearchBase -Properties $groupProperties
}

$groups = @(
    $allGroups |
    Where-Object {
        $_.DistinguishedName -notmatch '(?i),CN=Users,' -and
        $_.DistinguishedName -notmatch '(?i),CN=Builtin,' -and
        $_.DistinguishedName -notmatch '(?i),OU=Microsoft Exchange Security Groups,' -and
        $_.DistinguishedName -notmatch '(?i),OU=Microsoft CRM,'
    } |
    Sort-Object Name
)

$total = $groups.Count
$counter = 0
$results = [System.Collections.ArrayList]::new()

foreach ($group in $groups) {
    $counter++
    Write-Host ("Processing {0} / {1}: {2}" -f $counter, $total, $group.Name)

    $directMembers = @()
    $recursiveMemberCount = 0
    $memberPreview = ""
    $memberPreviewShort = ""
    $memberTypes = ""
    $memberReadError = $false

    try {
        $directMembers = @(Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop)
    }
    catch {
        $memberReadError = $true
        $directMembers = @()
    }

    $directMemberCount = $directMembers.Count

    if ($IncludeRecursiveMemberCount -and -not $memberReadError) {
        try {
            $recursiveMembers = @(Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop)
            $recursiveMemberCount = $recursiveMembers.Count
        }
        catch {
            $memberReadError = $true
            $recursiveMemberCount = 0
        }
    }
    else {
        $recursiveMemberCount = $directMemberCount
    }

    if ($directMemberCount -gt 0) {
        $memberNames = @(
            $directMembers |
            ForEach-Object {
                if (-not [string]::IsNullOrWhiteSpace($_.Name)) { $_.Name }
                else { $_.DistinguishedName }
            }
        )

        $memberObjectClasses = @(
            $directMembers |
            ForEach-Object {
                if (-not [string]::IsNullOrWhiteSpace($_.objectClass)) { $_.objectClass }
                else { "unknown" }
            }
        )

        $memberTypes = ($memberObjectClasses | Sort-Object -Unique) -join ", "
        $memberPreview = $memberNames -join "; "

        if ($memberNames.Count -le $MaxMemberListPreview) {
            $memberPreviewShort = $memberPreview
        }
        else {
            $memberPreviewShort = (($memberNames | Select-Object -First $MaxMemberListPreview) -join "; ") + " ... (+" + ($memberNames.Count - $MaxMemberListPreview) + " more)"
        }
    }

    $isPrivileged = $privilegedGroupNames -contains $group.Name
    $isEmpty = ($directMemberCount -eq 0)

    $staleScore = Get-StaleScore `
        -DirectMemberCount $directMemberCount `
        -IsPrivileged $isPrivileged `
        -Description $group.Description `
        -WhenChanged $group.whenChanged `
        -CutoffDate $staleCutoffDate `
        -MemberReadError $memberReadError

    $staleLevel = Get-StaleLevel -StaleScore $staleScore -IsPrivileged $isPrivileged

    $cleanupSuggestion = Get-CleanupSuggestion `
        -DirectMemberCount $directMemberCount `
        -RecursiveMemberCount $recursiveMemberCount `
        -IsPrivileged $isPrivileged `
        -Description $group.Description `
        -MemberReadError $memberReadError `
        -StaleScore $staleScore

    $riskLevel = Get-GroupRiskLevel `
        -DirectMemberCount $directMemberCount `
        -RecursiveMemberCount $recursiveMemberCount `
        -IsPrivileged $isPrivileged `
        -MemberReadError $memberReadError

    [void]$results.Add([PSCustomObject]@{
        Name                 = $group.Name
        SamAccountName       = $group.SamAccountName
        DistinguishedName    = $group.DistinguishedName
        Description          = $group.Description
        Category             = $group.GroupCategory
        Scope                = $group.GroupScope
        DirectMemberCount    = $directMemberCount
        RecursiveMemberCount = $recursiveMemberCount
        MemberTypes          = $memberTypes
        MembersPreview       = $memberPreviewShort
        MembersFull          = $memberPreview
        WhenCreated          = $group.whenCreated
        WhenChanged          = $group.whenChanged
        IsPrivileged         = $isPrivileged
        IsEmpty              = $isEmpty
        MemberReadError      = $memberReadError
        RiskLevel            = $riskLevel
        StaleScore           = $staleScore
        StaleLevel           = $staleLevel
        CleanupSuggestion    = $cleanupSuggestion
    })
}

$results |
    Sort-Object Name |
    Select-Object `
        Name,
        SamAccountName,
        Category,
        Scope,
        DirectMemberCount,
        RecursiveMemberCount,
        MemberTypes,
        Description,
        MembersPreview,
        MembersFull,
        WhenCreated,
        WhenChanged,
        IsPrivileged,
        IsEmpty,
        MemberReadError,
        RiskLevel,
        StaleScore,
        StaleLevel,
        CleanupSuggestion,
        DistinguishedName |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$totalGroups       = $results.Count
$emptyGroups       = ($results | Where-Object { $_.IsEmpty -eq $true } | Measure-Object).Count
$privilegedGroups  = ($results | Where-Object { $_.IsPrivileged -eq $true } | Measure-Object).Count
$highRiskGroups    = ($results | Where-Object { $_.RiskLevel -eq "High" } | Measure-Object).Count
$mediumRiskGroups  = ($results | Where-Object { $_.RiskLevel -eq "Medium" } | Measure-Object).Count
$lowRiskGroups     = ($results | Where-Object { $_.RiskLevel -eq "Low" } | Measure-Object).Count
$memberErrorCount  = ($results | Where-Object { $_.MemberReadError -eq $true } | Measure-Object).Count
$staleHighCount    = ($results | Where-Object { $_.StaleLevel -eq "High" } | Measure-Object).Count
$emptyNonPrivCount = ($results | Where-Object { $_.IsEmpty -eq $true -and $_.IsPrivileged -eq $false } | Measure-Object).Count
$strongReviewCount = ($results | Where-Object { $_.CleanupSuggestion -eq "Strong review candidate" } | Measure-Object).Count

$topFindings = @()

if ($memberErrorCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$memberErrorCount group(s) have member enumeration errors"
        Filter    = "error"
        BadgeText = "Review"
        BadgeCss  = "badge-red"
    }
}
if ($highRiskGroups -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$highRiskGroups high-risk group(s) need manual review"
        Filter    = "high"
        BadgeText = "Risk"
        BadgeCss  = "badge-red"
    }
}
if ($strongReviewCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$strongReviewCount strong review candidate(s) found"
        Filter    = "strong-review"
        BadgeText = "Cleanup"
        BadgeCss  = "badge-yellow"
    }
}
if ($staleHighCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$staleHighCount stale-high group(s) match multiple stale indicators"
        Filter    = "stale"
        BadgeText = "Stale"
        BadgeCss  = "badge-blue"
    }
}
if ($emptyNonPrivCount -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$emptyNonPrivCount empty non-privileged group(s) are easier review candidates"
        Filter    = "empty-nonpriv"
        BadgeText = "Groups"
        BadgeCss  = "badge-purple"
    }
}
if ($privilegedGroups -gt 0) {
    $topFindings += [pscustomobject]@{
        Text      = "$privilegedGroups privileged group(s) are excluded from bulk actions"
        Filter    = "privileged"
        BadgeText = "Protected"
        BadgeCss  = "badge-gray"
    }
}
if ($topFindings.Count -eq 0) {
    $topFindings += [pscustomobject]@{
        Text      = "No obvious high-priority findings detected from current heuristics"
        Filter    = ""
        BadgeText = "Info"
        BadgeCss  = "badge-gray"
    }
}

$topFindingsHtml = ""
foreach ($f in $topFindings) {
    $badgeHtml = '<span class="badge finding-badge ' + (New-SafeHtml $f.BadgeCss) + '">' + (New-SafeHtml $f.BadgeText) + '</span>'

    if ([string]::IsNullOrWhiteSpace($f.Filter)) {
        $topFindingsHtml += '<li><span class="finding-static">' + $badgeHtml + '<span class="finding-text">' + (New-SafeHtml $f.Text) + '</span></span></li>'
    }
    else {
        $topFindingsHtml += '<li><button type="button" class="finding-link" data-finding-filter="' + (New-SafeHtml $f.Filter) + '">' + $badgeHtml + '<span class="finding-text">' + (New-SafeHtml $f.Text) + '</span></button></li>'
    }
}

$htmlRows = foreach ($row in ($results | Sort-Object Name)) {
    $badges = [System.Collections.ArrayList]::new()

    if ($row.IsPrivileged) {
        [void]$badges.Add((Get-BadgeHtml -Text "Privileged" -Class "badge-purple"))
    }

    if ($row.IsEmpty) {
        [void]$badges.Add((Get-BadgeHtml -Text "Empty" -Class "badge-yellow"))
    }
    else {
        [void]$badges.Add((Get-BadgeHtml -Text "Has Members" -Class "badge-green"))
    }

    if ($row.MemberReadError) {
        [void]$badges.Add((Get-BadgeHtml -Text "Member Read Error" -Class "badge-red"))
    }

    if ($row.RiskLevel -eq "High") {
        [void]$badges.Add((Get-BadgeHtml -Text "High Risk" -Class "badge-red"))
    }
    elseif ($row.RiskLevel -eq "Medium") {
        [void]$badges.Add((Get-BadgeHtml -Text "Medium Risk" -Class "badge-yellow"))
    }
    else {
        [void]$badges.Add((Get-BadgeHtml -Text "Low Risk" -Class "badge-green"))
    }

    if ($row.StaleLevel -eq "High") {
        [void]$badges.Add((Get-BadgeHtml -Text "Stale High" -Class "badge-yellow"))
    }
    elseif ($row.StaleLevel -eq "Medium") {
        [void]$badges.Add((Get-BadgeHtml -Text "Stale Medium" -Class "badge-blue"))
    }
    elseif ($row.StaleLevel -eq "Protected") {
        [void]$badges.Add((Get-BadgeHtml -Text "Protected" -Class "badge-gray"))
    }

    $riskAttr = switch ($row.RiskLevel) {
        "High"   { "high" }
        "Medium" { "medium" }
        default  { "low" }
    }

    $staleAttr = switch ($row.StaleLevel) {
        "High"      { "high" }
        "Medium"    { "medium" }
        "Protected" { "protected" }
        default     { "low" }
    }

    $privAttr  = if ($row.IsPrivileged) { "yes" } else { "no" }
    $emptyAttr = if ($row.IsEmpty) { "yes" } else { "no" }
    $errorAttr = if ($row.MemberReadError) { "yes" } else { "no" }

    $membersPreviewShortHtml = New-SafeHtml $row.MembersPreview
    $membersFullHtml = New-SafeHtml $row.MembersFull
    $groupNameHtml = New-SafeHtml $row.Name
    $samHtml = New-SafeHtml $row.SamAccountName
    $dnHtml = New-SafeHtml $row.DistinguishedName
    $cleanupHtml = New-SafeHtml $row.CleanupSuggestion
    $selectDisabled = if ($row.IsPrivileged) { " disabled='disabled'" } else { "" }
    $selectNote = if ($row.IsPrivileged) {
        "<div class='pick-note blocked'>Privileged group - blocked</div>"
    }
    else {
        "<div class='pick-note'>Valittavissa bulk-esikatseluun</div>"
    }

    $showExpand = $false
    if (-not [string]::IsNullOrWhiteSpace([string]$row.MembersFull)) {
        if ([string]$row.MembersFull -ne [string]$row.MembersPreview) {
            $showExpand = $true
        }
    }

    if ($showExpand) {
        $memberCellHtml = @"
<td class='member-cell'>
    <span class='member-preview-short'>$membersPreviewShortHtml</span>
    <div class='member-preview-full'>$membersFullHtml</div>
    <div class='member-actions'>
        <button type='button' class='member-toggle'>Näytä lisää</button>
        <button type='button' class='member-modal-open'
            data-group-name="$groupNameHtml"
            data-members-full="$membersFullHtml">Avaa popup</button>
    </div>
</td>
"@
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$row.MembersFull)) {
        $memberCellHtml = @"
<td class='member-cell'>
    <span class='member-preview-short'>$membersPreviewShortHtml</span>
    <div class='member-actions'>
        <button type='button' class='member-modal-open'
            data-group-name="$groupNameHtml"
            data-members-full="$membersFullHtml">Avaa popup</button>
    </div>
</td>
"@
    }
    else {
        $memberCellHtml = @"
<td class='member-cell'>
    <span class='member-preview-short'></span>
</td>
"@
    }

@"
<tr
    data-risk="$riskAttr"
    data-stale="$staleAttr"
    data-empty="$emptyAttr"
    data-privileged="$privAttr"
    data-error="$errorAttr"
    data-name="$groupNameHtml"
    data-sam="$samHtml"
    data-dn="$dnHtml"
    data-cleanup="$cleanupHtml">
    <td class='pick-col' data-sort-value=''>
        <label class='row-pick'>
            <input type='checkbox' class='row-select'$selectDisabled>
            <span></span>
        </label>
    </td>
    <td data-sort-value="$(New-SafeHtml $row.Name)">
        <div class='name-cell'>
            $selectNote
            <div><strong>$(New-SafeHtml $row.Name)</strong></div>
            <div class='dn-inline'>$dnHtml</div>
        </div>
    </td>
    <td data-sort-value="$(New-SafeHtml $row.SamAccountName)">$(New-SafeHtml $row.SamAccountName)</td>
    <td data-sort-value="$(New-SafeHtml $row.Category)">$(New-SafeHtml $row.Category)</td>
    <td data-sort-value="$(New-SafeHtml $row.Scope)">$(New-SafeHtml $row.Scope)</td>
    <td class='num' data-sort-value='$($row.DirectMemberCount)'>$($row.DirectMemberCount)</td>
    <td class='num' data-sort-value='$($row.RecursiveMemberCount)'>$($row.RecursiveMemberCount)</td>
    <td data-sort-value="$(New-SafeHtml $row.MemberTypes)">$(New-SafeHtml $row.MemberTypes)</td>
    <td data-sort-value="$(New-SafeHtml $row.Description)">$(New-SafeHtml $row.Description)</td>
    $memberCellHtml
    <td class='num' data-sort-value='$($row.StaleScore)'>$($row.StaleScore)</td>
    <td data-sort-value="$(Get-DateText $row.WhenCreated)">$(Get-DateText $row.WhenCreated)</td>
    <td data-sort-value="$(Get-DateText $row.WhenChanged)">$(Get-DateText $row.WhenChanged)</td>
    <td>$(($badges -join " "))</td>
    <td data-sort-value="$cleanupHtml">$cleanupHtml</td>
</tr>
"@
}

$effectiveSearchBase = if ([string]::IsNullOrWhiteSpace($SearchBase)) { "[domain root]" } else { $SearchBase }
$recursiveEnabledText = if ($IncludeRecursiveMemberCount) { "Yes" } else { "No" }

$htmlTemplate = @'
<!doctype html>
<html lang="fi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ADDS Groups Audit Report v2.9</title>
<style>
    :root{
        --bg:#f3f6fb;
        --card:#ffffff;
        --card2:#f8fbff;
        --fg:#0f172a;
        --muted:#475569;
        --border:#d9e2ef;
        --accent:#2563eb;
        --accent2:#dbeafe;
        --accent3:#eff6ff;
        --ok:#166534;
        --warn:#92400e;
        --danger:#991b1b;
        --overlay:rgba(15,23,42,.35);
        --shadow:0 10px 30px rgba(15,23,42,.08);
    }
    *{box-sizing:border-box}
    html{scroll-behavior:smooth}
    body{
        margin:0;
        padding:24px;
        font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;
        color:var(--fg);
        background:linear-gradient(180deg,#f8fbff 0%, #eef4fb 100%);
    }
    h1,h2,h3,h4{margin-top:0}
    .wrap{max-width:1900px;margin:0 auto}
    .card{
        background:var(--card);
        border:1px solid var(--border);
        border-radius:18px;
        padding:20px;
        margin-bottom:20px;
        box-shadow:var(--shadow);
    }
    .muted{color:var(--muted)}

    .meta-grid{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
        gap:12px;
        margin-top:16px;
    }
    .meta-item{
        padding:14px 16px;
        border:1px solid var(--border);
        border-radius:14px;
        background:var(--card2);
    }
    .meta-item .k{
        color:var(--muted);
        font-size:12px;
        text-transform:uppercase;
        letter-spacing:.06em;
        margin-bottom:6px;
        font-weight:700;
    }
    .meta-item .v{
        color:var(--fg);
        word-break:break-word;
        font-weight:600;
    }

    .grid{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
        gap:14px;
        margin-top:16px;
    }
    .stat{
        display:block;
        width:100%;
        text-align:left;
        text-decoration:none;
        color:var(--fg);
        background:linear-gradient(180deg,#ffffff 0%, #f8fbff 100%);
        border:1px solid var(--border);
        border-radius:16px;
        padding:16px 18px;
        min-height:92px;
        box-shadow:0 8px 18px rgba(15,23,42,.04);
        transition:transform .15s ease, box-shadow .15s ease, border-color .15s ease, outline-color .15s ease;
        cursor:pointer;
        appearance:none;
        font:inherit;
    }
    .stat:hover{
        transform:translateY(-1px);
        border-color:#b7cae5;
        box-shadow:0 12px 24px rgba(15,23,42,.07);
    }
    .stat:focus-visible{
        outline:2px solid var(--accent);
        outline-offset:2px;
    }
    .stat.active{
        border-color:var(--accent);
        background:linear-gradient(180deg,#ffffff 0%, #eef6ff 100%);
        box-shadow:0 0 0 3px rgba(37,99,235,.10), 0 12px 24px rgba(15,23,42,.07);
    }
    .stat .label{
        color:var(--muted);
        font-size:12px;
        text-transform:uppercase;
        letter-spacing:.08em;
        margin-bottom:8px;
        font-weight:700;
    }
    .stat .value{
        font-size:40px;
        line-height:1;
        font-weight:800;
        letter-spacing:-0.02em;
    }
    .stat.total .value{ color:#0f172a; }
    .stat.empty .value{ color:#d97706; }
    .stat.priv .value{ color:#be123c; }
    .stat.high .value{ color:#dc2626; }
    .stat.medium .value{ color:#ca8a04; }
    .stat.low .value{ color:#16a34a; }
    .stat.error .value{ color:#e11d48; }
    .stat.stale .value{ color:#ea580c; }
    .stat.review .value{ color:#a16207; }

    .summary{
        margin-top:18px;
        padding:18px;
        background:#fbfdff;
        border:1px solid var(--border);
        border-radius:16px;
    }
    .summary h2{
        margin:0 0 12px 0;
        font-size:22px;
    }
    .summary ul{
        margin:0;
        padding-left:18px;
    }
    .summary li + li{
        margin-top:10px;
    }

    .finding-link,
    .finding-static{
        width:100%;
        display:flex;
        align-items:flex-start;
        gap:10px;
        text-align:left;
        font:inherit;
        color:var(--fg);
        background:transparent;
        border:0;
        padding:0;
    }
    .finding-link{ cursor:pointer; }
    .finding-link:hover .finding-text{
        color:#0f172a;
        text-decoration:underline;
        text-underline-offset:2px;
    }
    .finding-badge{
        flex:0 0 auto;
        margin-right:0;
        margin-bottom:0;
    }
    .finding-text{
        flex:1 1 auto;
        color:var(--muted);
    }

    .toolbar{
        display:flex;
        flex-wrap:wrap;
        align-items:flex-end;
        justify-content:space-between;
        gap:14px;
        margin-top:18px;
    }
    .toolbar-left,
    .toolbar-right{
        display:flex;
        flex-wrap:wrap;
        align-items:flex-end;
        gap:10px;
    }
    .toolbar-card{
        display:flex;
        align-items:center;
        gap:10px;
        padding:10px 12px;
        background:#f8fbff;
        border:1px solid #d9e2ef;
        border-radius:16px;
        box-shadow:0 4px 10px rgba(15,23,42,.04);
    }
    .toolbar-label{
        font-size:12px;
        font-weight:700;
        color:#475569;
        line-height:1.2;
    }

    .filter-pill{
        display:inline-flex;
        align-items:center;
        gap:8px;
        border:1px solid #d9e2ef;
        background:#f8fbff;
        color:#0f172a;
        border-radius:999px;
        padding:9px 14px;
        font-size:13px;
        min-height:42px;
    }
    .filter-pill button{
        border:0;
        background:transparent;
        color:#2563eb;
        cursor:pointer;
        font:inherit;
        font-weight:700;
        padding:0;
    }
    .filter-pill button:hover{
        text-decoration:underline;
    }

    .search-box{
        min-width:320px;
        max-width:460px;
        width:100%;
    }

    .search-box input,
    .toolbar select,
    .modal select,
    .modal input,
    .modal textarea{
        width:100%;
        padding:10px 12px;
        border-radius:12px;
        border:1px solid #cdd9ea;
        background:#ffffff;
        color:#0f172a;
        font:inherit;
        outline:none;
    }
    .search-box input{
        height:42px;
        padding:0 14px;
        border-radius:14px;
        box-shadow:0 2px 6px rgba(15,23,42,.03);
    }
    .search-box input:focus,
    .toolbar select:focus,
    .modal select:focus,
    .modal input:focus,
    .modal textarea:focus{
        border-color:#2563eb;
        box-shadow:0 0 0 3px rgba(37,99,235,.12);
    }
    .search-box input:disabled,
    .toolbar select:disabled,
    .modal select:disabled,
    .modal input:disabled,
    .modal textarea:disabled{
        background:#f1f5f9;
        color:#64748b;
        cursor:not-allowed;
    }

    .compact-select{
        min-width:84px;
        width:84px;
        height:42px;
    }

    table{
        width:100%;
        border-collapse:collapse;
        font-size:13px;
        background:#fff;
    }
    th, td{
        border:1px solid #e2e8f0;
        padding:10px;
        text-align:left;
        vertical-align:top;
    }
    th{
        position:sticky;
        top:0;
        background:#edf4ff;
        z-index:1;
        white-space:nowrap;
    }
    th.sortable{
        cursor:pointer;
        user-select:none;
    }
    th.sortable:hover{
        background:#e2eeff;
    }
    th .sort-ind{
        margin-left:6px;
        color:#64748b;
        font-size:11px;
    }
    td.num{
        text-align:right;
        white-space:nowrap;
    }
    .table-wrap{
        overflow:auto;
        border-radius:12px;
        margin-top:16px;
        border:1px solid var(--border);
        background:#fff;
    }

    .badge{
        display:inline-block;
        padding:2px 8px;
        border-radius:999px;
        font-size:11px;
        font-weight:700;
        line-height:1.4;
        white-space:nowrap;
        margin-right:4px;
        margin-bottom:2px;
    }
    .badge-green{background:#dcfce7;color:#166534}
    .badge-yellow{background:#fef3c7;color:#92400e}
    .badge-red{background:#fee2e2;color:#991b1b}
    .badge-gray{background:#e5e7eb;color:#374151}
    .badge-purple{background:#ede9fe;color:#6d28d9}
    .badge-blue{background:#dbeafe;color:#1d4ed8}

    .foot{
        margin-top:12px;
        color:var(--muted);
        font-size:12px;
    }
    .hidden-row{ display:none !important; }
    .page-hidden{ display:none !important; }

    .member-cell{
        min-width:320px;
        max-width:520px;
    }
    .member-preview-short{
        display:block;
        white-space:normal;
        word-break:break-word;
    }
    .member-preview-full{
        display:none;
        margin-top:8px;
        white-space:normal;
        word-break:break-word;
        color:#334155;
        max-height:160px;
        overflow:auto;
        padding:8px;
        border:1px solid #d9e2ef;
        border-radius:10px;
        background:#f8fbff;
    }
    .member-cell.expanded .member-preview-short{ display:none; }
    .member-cell.expanded .member-preview-full{ display:block; }
    .member-actions{
        display:flex;
        flex-wrap:wrap;
        gap:8px;
        margin-top:8px;
    }

    .btn,
    .pager-btn,
    .member-toggle,
    .member-modal-open,
    .modal-close,
    .modal-btn{
        display:inline-flex;
        align-items:center;
        justify-content:center;
        gap:8px;
        min-height:42px;
        padding:0 16px;
        border:1px solid #bfd1ea;
        background:#ffffff;
        color:#0f172a;
        border-radius:12px;
        font-size:13px;
        font-weight:700;
        cursor:pointer;
        transition:all .15s ease;
        box-shadow:0 2px 6px rgba(15,23,42,.03);
    }
    .btn:hover,
    .pager-btn:hover,
    .member-toggle:hover,
    .member-modal-open:hover,
    .modal-close:hover,
    .modal-btn:hover{
        background:#eff6ff;
        border-color:#93c5fd;
    }
    .btn-primary{
        background:#2563eb;
        border-color:#2563eb;
        color:#ffffff;
    }
    .btn-primary:hover{
        background:#1d4ed8;
        border-color:#1d4ed8;
    }
    .btn-secondary{
        background:#ffffff;
        color:#0f172a;
    }
    .btn:disabled,
    .pager-btn:disabled,
    .member-toggle:disabled,
    .member-modal-open:disabled,
    .modal-close:disabled,
    .modal-btn:disabled{
        opacity:.55;
        cursor:not-allowed;
    }

    .dn-inline{
        margin-top:4px;
        color:#64748b;
        font-size:11px;
        word-break:break-word;
    }

    .pager{
        display:flex;
        flex-wrap:wrap;
        align-items:center;
        justify-content:space-between;
        gap:10px;
        margin-top:14px;
    }
    .pager-left, .pager-right{
        display:flex;
        flex-wrap:wrap;
        align-items:center;
        gap:8px;
    }
    .pager-info{
        color:var(--muted);
        font-size:13px;
    }

    .modal{
        position:fixed;
        inset:0;
        display:none;
        align-items:center;
        justify-content:center;
        background:var(--overlay);
        z-index:9999;
        padding:24px;
    }
    .modal.open{ display:flex; }

    .modal-dialog{
        width:min(900px, 100%);
        max-height:min(86vh, 900px);
        display:flex;
        flex-direction:column;
        background:#ffffff;
        border:1px solid #d9e2ef;
        border-radius:18px;
        box-shadow:0 24px 60px rgba(15,23,42,.18);
        overflow:hidden;
    }
    .modal-dialog-wide{
        width:min(1240px, 100%);
    }

    .modal-header{
        display:flex;
        align-items:center;
        justify-content:space-between;
        gap:16px;
        padding:16px 18px;
        border-bottom:1px solid var(--border);
        background:#f8fbff;
    }
    .modal-title-wrap{ min-width:0; }
    .modal-title{
        margin:0;
        font-size:20px;
    }
    .modal-subtitle{
        margin-top:4px;
        color:var(--muted);
        font-size:13px;
        word-break:break-word;
    }
    .modal-body{
        padding:18px;
        overflow:auto;
    }
    .member-list-box{
        white-space:pre-wrap;
        word-break:break-word;
        background:#f8fbff;
        border:1px solid var(--border);
        border-radius:12px;
        padding:14px;
        color:#0f172a;
        line-height:1.55;
    }
    .modal-hint{
        margin-top:12px;
        color:var(--muted);
        font-size:12px;
    }

    .name-cell{
        display:flex;
        flex-direction:column;
        gap:6px;
    }
    .row-pick{
        display:inline-flex;
        align-items:center;
        gap:8px;
        font-size:12px;
        color:#0f172a;
        width:max-content;
    }
    .row-pick input{
        accent-color:#2563eb;
    }
    .pick-note{
        font-size:11px;
        color:#2563eb;
    }
    .pick-note.blocked{
        color:#be123c;
    }

    .script-textarea{
        width:100%;
        min-height:420px;
        resize:vertical;
        padding:14px;
        border-radius:12px;
        border:1px solid #d9e2ef;
        background:#fbfdff;
        color:#0f172a;
        font:12px/1.45 Consolas, Monaco, 'Courier New', monospace;
        outline:none;
    }

    .warning-box{
        background:#fff7ed;
        border:1px solid #fdba74;
        color:#9a3412;
        border-radius:14px;
        padding:12px 14px;
        font-size:13px;
    }
    .warning-box-danger{
        background:#fef2f2;
        border:1px solid #fca5a5;
        color:#991b1b;
        border-radius:14px;
        padding:12px 14px;
        font-size:13px;
    }

    .helper-grid{
        display:grid;
        grid-template-columns:repeat(2,minmax(0,1fr));
        gap:12px;
    }
    @media (max-width:900px){
        .helper-grid{
            grid-template-columns:1fr;
        }
    }

    .form-section{
        margin-top:12px;
        padding:16px;
        border:1px solid var(--border);
        border-radius:16px;
        background:#fbfdff;
    }
    .form-section h4{
        margin:0 0 12px 0;
        font-size:15px;
    }
    .form-help{
        margin-top:6px;
        color:#64748b;
        font-size:12px;
    }
    .is-hidden{
        display:none !important;
    }

    .modal-actions{
        display:flex;
        flex-wrap:wrap;
        gap:10px;
        justify-content:flex-end;
        margin-top:16px;
    }

    .action-log-badge{
        display:inline-block;
        padding:2px 8px;
        border-radius:999px;
        font-size:11px;
        font-weight:700;
        line-height:1.4;
    }
    .action-log-badge.ok{background:#dcfce7;color:#166534;}
    .action-log-badge.warn{background:#fef3c7;color:#92400e;}
    .action-log-badge.danger{background:#fee2e2;color:#991b1b;}

    .pick-col{
        width:56px;
        min-width:56px;
        text-align:center;
        vertical-align:middle;
    }
    th .row-pick{
        justify-content:center;
    }
    .pick-col .row-pick{
        justify-content:center;
        width:100%;
    }
    .pick-col input[type="checkbox"],
    th input[type="checkbox"]{
        width:16px;
        height:16px;
    }
</style>
</head>
<body>
<div class="wrap">

    <div class="card">
        <h1>ADDS Groups Audit Report v2.9</h1>

        <div class="meta-grid">
            <div class="meta-item">
                <div class="k">Domain</div>
                <div class="v">__DOMAIN__</div>
            </div>
            <div class="meta-item">
                <div class="k">Search Base</div>
                <div class="v">__SEARCHBASE__</div>
            </div>
            <div class="meta-item">
                <div class="k">Recursive Count Enabled</div>
                <div class="v">__RECURSIVE__</div>
            </div>
            <div class="meta-item">
                <div class="k">Stale Threshold</div>
                <div class="v">__STALEYEARS__</div>
            </div>
            <div class="meta-item">
                <div class="k">Generated</div>
                <div class="v">__GENERATED__</div>
            </div>
        </div>

        <div class="grid">
            <button type="button" class="stat total active" data-filter="all">
                <div class="label">Ryhmät yhteensä</div>
                <div class="value">__TOTALGROUPS__</div>
            </button>
            <button type="button" class="stat empty" data-filter="empty">
                <div class="label">Tyhjät ryhmät</div>
                <div class="value">__EMPTYGROUPS__</div>
            </button>
            <button type="button" class="stat review" data-filter="empty-nonpriv">
                <div class="label">Tyhjät ei-privileged</div>
                <div class="value">__EMPTYNONPRIV__</div>
            </button>
            <button type="button" class="stat priv" data-filter="privileged">
                <div class="label">Privileged ryhmät</div>
                <div class="value">__PRIVGROUPS__</div>
            </button>
            <button type="button" class="stat high" data-filter="high">
                <div class="label">High Risk</div>
                <div class="value">__HIGHRISK__</div>
            </button>
            <button type="button" class="stat medium" data-filter="medium">
                <div class="label">Medium Risk</div>
                <div class="value">__MEDIUMRISK__</div>
            </button>
            <button type="button" class="stat low" data-filter="low">
                <div class="label">Low Risk</div>
                <div class="value">__LOWRISK__</div>
            </button>
            <button type="button" class="stat error" data-filter="error">
                <div class="label">Member Read Errors</div>
                <div class="value">__MEMBERERRORS__</div>
            </button>
            <button type="button" class="stat stale" data-filter="stale">
                <div class="label">Stale High</div>
                <div class="value">__STALEHIGH__</div>
            </button>
            <button type="button" class="stat review" data-filter="strong-review">
                <div class="label">Strong Review</div>
                <div class="value">__STRONGREVIEW__</div>
            </button>
        </div>

        <div class="summary">
            <h2>Top Findings</h2>
            <ul>
                __TOPFINDINGS__
            </ul>
        </div>

        <div class="summary">
            <h2>Selite</h2>
            <ul>
                <li><span class="finding-static"><span class="badge finding-badge badge-red">High Risk</span><span class="finding-text">Privileged-ryhmä, jäsenlukivirhe tai erittäin suuri rekursiivinen jäsenmäärä.</span></span></li>
                <li><span class="finding-static"><span class="badge finding-badge badge-blue">Stale Score</span><span class="finding-text">Pisteytys vanhentumisen merkeille, esim. tyhjyys, kuvauksen puute ja pitkä muuttumattomuus.</span></span></li>
                <li><span class="finding-static"><span class="badge finding-badge badge-yellow">Strong Review</span><span class="finding-text">Ei-privileged, tyhjä ja samalla useita stale-indikaattoreita.</span></span></li>
                <li><span class="finding-static"><span class="badge finding-badge badge-purple">Cleanup Suggestion</span><span class="finding-text">Tarkistusvihje, ei automaattinen poisto.</span></span></li>
            </ul>
        </div>
    </div>

    <div class="card" id="groups-section">
        <h2>Ryhmät</h2>

        <div class="toolbar">
            <div class="toolbar-left">
                <div class="filter-pill">
                    Aktiivinen suodatin: <strong id="activeFilterLabel">Kaikki</strong>
                    <button type="button" id="clearFilterBtn">Tyhjennä</button>
                </div>

                <div class="filter-pill">
                    Näytetään: <strong id="visibleRowCount">__TOTALGROUPS__</strong> / __TOTALGROUPS__
                </div>
            </div>

            <div class="toolbar-right">
                <div class="toolbar-card">
                    <div class="toolbar-label">Rows per page</div>
                    <select id="rowsPerPage" class="compact-select">
                        <option value="10">10</option>
                        <option value="25" selected>25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                        <option value="all">All</option>
                    </select>
                </div>

                <button type="button" class="pager-btn btn-secondary" id="selectVisibleBtn">Valitse näkyvät</button>
                <button type="button" class="pager-btn btn-secondary" id="clearSelectionBtn">Tyhjennä valinnat</button>
                <button type="button" class="pager-btn btn-primary" id="openBulkModalBtn">Bulk actions</button>

                <div class="search-box">
                    <input type="text" id="tableSearch" placeholder="Hae nimellä, samAccountName:lla, DN:llä, kuvauksesta, member typeistä tai cleanup-tekstistä">
                </div>
            </div>
        </div>

        <div class="foot">
            Valittuna bulk-esikatseluun: <strong id="selectedDeleteCount">0</strong>
        </div>

        <div class="table-wrap">
            <table id="groupsTable">
                <thead>
                    <tr>
                        <th>
                            <label class="row-pick">
                                <input type="checkbox" id="selectAllVisibleCheckbox">
                                <span>Kaikki</span>
                            </label>
                        </th>
                        <th class="sortable" data-col="1" data-type="text">Name <span class="sort-ind">↕</span></th>
                        <th class="sortable" data-col="2" data-type="text">SamAccountName <span class="sort-ind">↕</span></th>
                        <th class="sortable" data-col="3" data-type="text">Category <span class="sort-ind">↕</span></th>
                        <th class="sortable" data-col="4" data-type="text">Scope <span class="sort-ind">↕</span></th>
                        <th class="sortable" data-col="5" data-type="number">Direct Members <span class="sort-ind">↕</span></th>
                        <th class="sortable" data-col="6" data-type="number">Recursive Members <span class="sort-ind">↕</span></th>
                        <th class="sortable" data-col="7" data-type="text">Member Types <span class="sort-ind">↕</span></th>
                        <th class="sortable" data-col="8" data-type="text">Description <span class="sort-ind">↕</span></th>
                        <th>Members Preview</th>
                        <th class="sortable" data-col="10" data-type="number">Stale Score <span class="sort-ind">↕</span></th>
                        <th class="sortable" data-col="11" data-type="text">Created <span class="sort-ind">↕</span></th>
                        <th class="sortable" data-col="12" data-type="text">Changed <span class="sort-ind">↕</span></th>
                        <th>Status</th>
                        <th class="sortable" data-col="14" data-type="text">Cleanup Suggestion <span class="sort-ind">↕</span></th>
                    </tr>
                </thead>
                <tbody>
__HTMLROWS__
                </tbody>
            </table>
        </div>

        <div class="pager">
            <div class="pager-left">
                <button type="button" class="pager-btn" id="firstPageBtn">« First</button>
                <button type="button" class="pager-btn" id="prevPageBtn">‹ Prev</button>
                <button type="button" class="pager-btn" id="nextPageBtn">Next ›</button>
                <button type="button" class="pager-btn" id="lastPageBtn">Last »</button>
            </div>
            <div class="pager-right">
                <div class="pager-info" id="pageInfo">Page 1 / 1</div>
            </div>
        </div>
    </div>
</div>

<div class="modal" id="membersModal" aria-hidden="true">
    <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="membersModalTitle">
        <div class="modal-header">
            <div class="modal-title-wrap">
                <h3 class="modal-title" id="membersModalTitle">Group Members</h3>
                <div class="modal-subtitle" id="membersModalSubtitle"></div>
            </div>
            <button type="button" class="modal-close" id="membersModalClose">Close</button>
        </div>
        <div class="modal-body">
            <div class="member-list-box" id="membersModalBody"></div>
            <div class="modal-hint">Esc sulkee ikkunan. Klikkaus taustaan sulkee myös.</div>
        </div>
    </div>
</div>

<div class="modal" id="bulkModal" aria-hidden="true">
    <div class="modal-dialog modal-dialog-wide" role="dialog" aria-modal="true" aria-labelledby="bulkModalTitle">
        <div class="modal-header">
            <div class="modal-title-wrap">
                <h3 class="modal-title" id="bulkModalTitle">Bulk action preview</h3>
                <div class="modal-subtitle" id="bulkModalSubtitle">Read-only audit. Modal only generates reviewable PowerShell or CSV output.</div>
            </div>
            <button type="button" class="modal-close" id="bulkModalClose">Close</button>
        </div>
        <div class="modal-body">
            <p id="bulkModalSummary" class="modal-hint" style="margin-top:0;">0 object(s) selected.</p>

            <div class="warning-box" style="margin-top:12px;">
                Tämä raportti on edelleen read-only. Modal generoi vain tarkistettavan PowerShell- tai CSV-ulostulon. Selain ei tee AD-muutoksia.
            </div>

            <div id="bulkWarnings" class="warning-box-danger is-hidden" style="margin-top:12px;"></div>

            <div class="form-section">
                <h4>Action settings</h4>
                <div class="helper-grid">
                    <div>
                        <label for="bulkActionType">Action</label>
                        <select id="bulkActionType">
                            <option value="report">Generate ReportOnly script</option>
                            <option value="move">Generate MoveAndTag script</option>
                            <option value="delete">Generate DeleteAndLog script</option>
                            <option value="exportcsv">Export selected CSV</option>
                        </select>
                        <div class="form-help">Valitse generoidaanko tarkistusskripti, siirtoskripti, poistologiskripti vai CSV-exportti.</div>
                    </div>

                    <div id="bulkDeleteModeWrap">
                        <label for="bulkDeleteMode">Delete mode</label>
                        <select id="bulkDeleteMode">
                            <option value="whatif" selected>WhatIf preview</option>
                            <option value="live">Live delete</option>
                        </select>
                        <div class="form-help">WhatIf on turvallinen preview. Live delete tekee sen mitä ihmiset yleensä katuvat myöhemmin.</div>
                    </div>
                </div>

                <div class="helper-grid" style="margin-top:12px;">
                    <div id="bulkTargetOuWrap">
                        <label for="bulkTargetOu">Target OU for move action</label>
                        <input type="text" id="bulkTargetOu" value="OU=Disabled Groups,OU=Groups,DC=example,DC=local">
                        <div class="form-help">Kohde-OU, johon MoveAndTag-skripti siirtää valitut ei-privileged ryhmät.</div>
                    </div>

                    <div id="bulkPrefixWrap">
                        <label for="bulkPrefix">Prefix for move action</label>
                        <input type="text" id="bulkPrefix" value="DISABLED_">
                        <div class="form-help">Lisätään nimeen ennen siirtoa, jos prefiksiä ei vielä ole.</div>
                    </div>
                </div>
            </div>

            <div class="form-section">
                <h4>Preview</h4>
                <textarea id="bulkPreview" class="script-textarea" spellcheck="false"></textarea>
            </div>

            <div class="modal-actions">
                <button type="button" class="modal-btn btn-secondary" id="copyBulkPreviewBtn">Copy output</button>
                <button type="button" class="modal-btn btn-secondary" id="downloadBulkPreviewBtn">Download</button>
                <button type="button" class="modal-btn btn-primary" id="closeBulkModalFooterBtn">Close</button>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
    try {
        console.log('AD Groups Audit UI loaded');

        function qs(id) {
            return document.getElementById(id);
        }

        function qsa(selector, root) {
            return Array.prototype.slice.call((root || document).querySelectorAll(selector));
        }

        function findParentByClass(el, className) {
            while (el && el !== document.body) {
                if (el.classList && el.classList.contains(className)) {
                    return el;
                }
                el = el.parentNode;
            }
            return null;
        }

        var statButtons = qsa('.stat[data-filter]');
        var clearFilterBtn = qs('clearFilterBtn');
        var activeFilterLabel = qs('activeFilterLabel');
        var visibleRowCount = qs('visibleRowCount');
        var selectedDeleteCount = qs('selectedDeleteCount');
        var searchInput = qs('tableSearch');
        var rowsPerPageSelect = qs('rowsPerPage');
        var table = qs('groupsTable');
        var tbody = table ? table.querySelector('tbody') : null;
        var headers = table ? qsa('th.sortable', table) : [];
        var selectAllVisibleCheckbox = qs('selectAllVisibleCheckbox');

        var firstPageBtn = qs('firstPageBtn');
        var prevPageBtn = qs('prevPageBtn');
        var nextPageBtn = qs('nextPageBtn');
        var lastPageBtn = qs('lastPageBtn');
        var pageInfo = qs('pageInfo');

        var selectVisibleBtn = qs('selectVisibleBtn');
        var clearSelectionBtn = qs('clearSelectionBtn');
        var openBulkModalBtn = qs('openBulkModalBtn');

        var membersModal = qs('membersModal');
        var membersModalClose = qs('membersModalClose');
        var membersModalTitle = qs('membersModalTitle');
        var membersModalSubtitle = qs('membersModalSubtitle');
        var membersModalBody = qs('membersModalBody');

        var bulkModal = qs('bulkModal');
        var bulkModalClose = qs('bulkModalClose');
        var closeBulkModalFooterBtn = qs('closeBulkModalFooterBtn');
        var bulkModalSummary = qs('bulkModalSummary');
        var bulkWarnings = qs('bulkWarnings');
        var bulkPreview = qs('bulkPreview');
        var bulkActionType = qs('bulkActionType');
        var bulkDeleteMode = qs('bulkDeleteMode');
        var bulkTargetOu = qs('bulkTargetOu');
        var bulkPrefix = qs('bulkPrefix');
        var bulkDeleteModeWrap = qs('bulkDeleteModeWrap');
        var bulkTargetOuWrap = qs('bulkTargetOuWrap');
        var bulkPrefixWrap = qs('bulkPrefixWrap');
        var copyBulkPreviewBtn = qs('copyBulkPreviewBtn');
        var downloadBulkPreviewBtn = qs('downloadBulkPreviewBtn');

        if (!table || !tbody) {
            console.error('groupsTable / tbody not found');
            return;
        }

        var currentFilter = 'all';
        var currentSortCol = null;
        var currentSortDir = 'asc';
        var currentPage = 1;
        var lastFocusedButton = null;

        function getAllRows() {
            return qsa('tr', tbody);
        }

        function getRowsPerPage() {
            var value = rowsPerPageSelect ? rowsPerPageSelect.value : '25';
            if (value === 'all') {
                return null;
            }
            return Number(value);
        }

        function getSelectedRows() {
            return getAllRows().filter(function (row) {
                var cb = row.querySelector('.row-select');
                return cb && cb.checked;
            });
        }

        function getVisibleRows() {
            return getAllRows().filter(function (row) {
                return !row.classList.contains('hidden-row') && !row.classList.contains('page-hidden');
            });
        }

        function getVisibleSelectableRows() {
            return getVisibleRows().filter(function (row) {
                var cb = row.querySelector('.row-select');
                return cb && !cb.disabled;
            });
        }

        function updateSelectedDeleteCount() {
            if (selectedDeleteCount) {
                selectedDeleteCount.textContent = String(getSelectedRows().length);
            }
        }

        function updateHeaderSelectAllState() {
            if (!selectAllVisibleCheckbox) {
                return;
            }

            var visibleSelectable = getVisibleSelectableRows();
            var checkedVisible = visibleSelectable.filter(function (row) {
                var cb = row.querySelector('.row-select');
                return cb && cb.checked;
            });

            if (visibleSelectable.length === 0) {
                selectAllVisibleCheckbox.checked = false;
                selectAllVisibleCheckbox.indeterminate = false;
                return;
            }

            if (checkedVisible.length === 0) {
                selectAllVisibleCheckbox.checked = false;
                selectAllVisibleCheckbox.indeterminate = false;
                return;
            }

            if (checkedVisible.length === visibleSelectable.length) {
                selectAllVisibleCheckbox.checked = true;
                selectAllVisibleCheckbox.indeterminate = false;
                return;
            }

            selectAllVisibleCheckbox.checked = false;
            selectAllVisibleCheckbox.indeterminate = true;
        }

        function filterLabelText(filter) {
            switch (filter) {
                case 'empty': return 'Tyhjät ryhmät';
                case 'empty-nonpriv': return 'Tyhjät ei-privileged';
                case 'privileged': return 'Privileged ryhmät';
                case 'high': return 'High Risk';
                case 'medium': return 'Medium Risk';
                case 'low': return 'Low Risk';
                case 'error': return 'Member Read Errors';
                case 'stale': return 'Stale High';
                case 'strong-review': return 'Strong Review';
                default: return 'Kaikki';
            }
        }

        function rowMatchesFilter(row, filter) {
            if (filter === 'all') return true;
            if (filter === 'empty') return row.dataset.empty === 'yes';
            if (filter === 'empty-nonpriv') return row.dataset.empty === 'yes' && row.dataset.privileged !== 'yes';
            if (filter === 'privileged') return row.dataset.privileged === 'yes';
            if (filter === 'high') return row.dataset.risk === 'high';
            if (filter === 'medium') return row.dataset.risk === 'medium';
            if (filter === 'low') return row.dataset.risk === 'low';
            if (filter === 'error') return row.dataset.error === 'yes';
            if (filter === 'stale') return row.dataset.stale === 'high';
            if (filter === 'strong-review') {
                var cleanupText = (row.dataset.cleanup || '').trim().toLowerCase();
                return cleanupText === 'strong review candidate';
            }
            return true;
        }

        function rowMatchesSearch(row, searchTerm) {
            if (!searchTerm) {
                return true;
            }

            var cells = Array.prototype.slice.call(row.cells);
            var haystack = [
                row.dataset.name || '',
                row.dataset.sam || '',
                row.dataset.dn || '',
                row.dataset.cleanup || '',
                cells[1] ? cells[1].innerText : '',
                cells[2] ? cells[2].innerText : '',
                cells[3] ? cells[3].innerText : '',
                cells[4] ? cells[4].innerText : '',
                cells[7] ? cells[7].innerText : '',
                cells[8] ? cells[8].innerText : '',
                cells[9] ? cells[9].innerText : '',
                cells[13] ? cells[13].innerText : '',
                cells[14] ? cells[14].innerText : ''
            ].join(' ').toLowerCase();

            return haystack.indexOf(searchTerm) !== -1;
        }

        function getFilteredRows() {
            var rows = getAllRows();
            var searchTerm = (searchInput ? searchInput.value : '').trim().toLowerCase();

            return rows.filter(function (row) {
                return rowMatchesFilter(row, currentFilter) && rowMatchesSearch(row, searchTerm);
            });
        }

        function updatePagination() {
            var allRows = getAllRows();
            var filteredRows = getFilteredRows();
            var rowsPerPage = getRowsPerPage();

            allRows.forEach(function (row) {
                row.classList.add('hidden-row');
                row.classList.remove('page-hidden');
            });

            filteredRows.forEach(function (row) {
                row.classList.remove('hidden-row');
            });

            var totalPages = 1;

            if (rowsPerPage && filteredRows.length > 0) {
                totalPages = Math.ceil(filteredRows.length / rowsPerPage);

                if (currentPage > totalPages) currentPage = totalPages;
                if (currentPage < 1) currentPage = 1;

                var start = (currentPage - 1) * rowsPerPage;
                var end = start + rowsPerPage;

                filteredRows.forEach(function (row, idx) {
                    if (idx < start || idx >= end) {
                        row.classList.add('page-hidden');
                    } else {
                        row.classList.remove('page-hidden');
                    }
                });
            } else {
                currentPage = 1;
                totalPages = 1;

                filteredRows.forEach(function (row) {
                    row.classList.remove('page-hidden');
                });
            }

            if (visibleRowCount) {
                visibleRowCount.textContent = String(filteredRows.length);
            }

            if (activeFilterLabel) {
                activeFilterLabel.textContent = filterLabelText(currentFilter);
            }

            statButtons.forEach(function (btn) {
                btn.classList.toggle('active', btn.dataset.filter === currentFilter);
            });

            if (pageInfo) {
                pageInfo.textContent = rowsPerPage
                    ? ('Page ' + currentPage + ' / ' + totalPages)
                    : 'Page 1 / 1 (All rows)';
            }

            var disablePaging = !rowsPerPage || filteredRows.length === 0 || totalPages <= 1;

            if (firstPageBtn) firstPageBtn.disabled = disablePaging || currentPage === 1;
            if (prevPageBtn) prevPageBtn.disabled = disablePaging || currentPage === 1;
            if (nextPageBtn) nextPageBtn.disabled = disablePaging || currentPage === totalPages;
            if (lastPageBtn) lastPageBtn.disabled = disablePaging || currentPage === totalPages;

            updateSelectedDeleteCount();
            updateHeaderSelectAllState();
        }

        function applyFilters(resetPage) {
            if (resetPage) {
                currentPage = 1;
            }
            updatePagination();
        }

        function getCellValue(row, colIndex) {
            var cell = row.cells[colIndex];
            if (!cell) {
                return '';
            }
            return (cell.getAttribute('data-sort-value') || cell.innerText || '').trim();
        }

        function sortTable(colIndex, type) {
            var rows = getAllRows();

            if (currentSortCol === colIndex) {
                currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
            } else {
                currentSortCol = colIndex;
                currentSortDir = 'asc';
            }

            rows.sort(function (a, b) {
                var aVal = getCellValue(a, colIndex);
                var bVal = getCellValue(b, colIndex);

                if (type === 'number') {
                    aVal = Number(aVal);
                    bVal = Number(bVal);
                } else {
                    aVal = aVal.toLowerCase();
                    bVal = bVal.toLowerCase();
                }

                if (aVal < bVal) return currentSortDir === 'asc' ? -1 : 1;
                if (aVal > bVal) return currentSortDir === 'asc' ? 1 : -1;
                return 0;
            });

            rows.forEach(function (row) {
                tbody.appendChild(row);
            });

            headers.forEach(function (th) {
                var ind = th.querySelector('.sort-ind');
                if (ind) {
                    ind.textContent = '↕';
                }
            });

            for (var i = 0; i < headers.length; i++) {
                if (Number(headers[i].dataset.col) === colIndex) {
                    var activeInd = headers[i].querySelector('.sort-ind');
                    if (activeInd) {
                        activeInd.textContent = currentSortDir === 'asc' ? '↑' : '↓';
                    }
                    break;
                }
            }

            applyFilters(false);
        }

        function openMembersModal(groupName, membersText, buttonRef) {
            lastFocusedButton = buttonRef || null;

            if (membersModalTitle) membersModalTitle.textContent = 'Group Members';
            if (membersModalSubtitle) membersModalSubtitle.textContent = groupName || '';
            if (membersModalBody) membersModalBody.textContent = membersText || '';

            if (membersModal) {
                membersModal.classList.add('open');
                membersModal.setAttribute('aria-hidden', 'false');
            }

            document.body.style.overflow = 'hidden';

            if (membersModalClose) {
                membersModalClose.focus();
            }
        }

        function closeMembersModal() {
            if (membersModal) {
                membersModal.classList.remove('open');
                membersModal.setAttribute('aria-hidden', 'true');
            }

            document.body.style.overflow = '';

            if (lastFocusedButton) {
                lastFocusedButton.focus();
            }
        }

        function openFinding(filter) {
            currentFilter = filter || 'all';
            applyFilters(true);

            var section = qs('groups-section');
            if (section) {
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }

        function handleBulkActionUI() {
            var action = bulkActionType ? bulkActionType.value : 'report';
            var isDelete = action === 'delete';
            var isMove = action === 'move';

            if (bulkDeleteMode) bulkDeleteMode.disabled = !isDelete;
            if (bulkTargetOu) bulkTargetOu.disabled = !isMove;
            if (bulkPrefix) bulkPrefix.disabled = !isMove;

            if (bulkDeleteModeWrap) bulkDeleteModeWrap.classList.toggle('is-hidden', !isDelete);
            if (bulkTargetOuWrap) bulkTargetOuWrap.classList.toggle('is-hidden', !isMove);
            if (bulkPrefixWrap) bulkPrefixWrap.classList.toggle('is-hidden', !isMove);
        }

        function updateBulkWarnings(items, action, useWhatIf) {
            if (!bulkWarnings) {
                return;
            }

            var warnings = [];
            var privilegedCount = items.filter(function (item) {
                return item.privileged;
            }).length;

            if (items.length === 0) {
                warnings.push('No objects selected.');
            }

            if (privilegedCount > 0) {
                warnings.push(privilegedCount + ' privileged group(s) selected. Delete and move scripts block privileged groups.');
            }

            if (action === 'delete' && !useWhatIf) {
                warnings.push('Live delete mode selected. Review the generated script very carefully before running it.');
            }

            if (action === 'delete' && items.length > 0) {
                warnings.push('DeleteAndLog script is intended for manually reviewed cleanup candidates only.');
            }

            if (action === 'move' && items.length > 0) {
                warnings.push('MoveAndTag script renames non-privileged groups with the selected prefix and moves them to the target OU.');
            }

            if (warnings.length === 0) {
                bulkWarnings.classList.add('is-hidden');
                bulkWarnings.innerHTML = '';
                return;
            }

            bulkWarnings.classList.remove('is-hidden');
            bulkWarnings.innerHTML = warnings.map(function (x) {
                return '• ' + x;
            }).join('<br>');
        }

        function psQuote(value) {
            return "'" + String(value || '').replace(/'/g, "''") + "'";
        }

        function escapePs(value) {
            return String(value || '')
                .replace(/`/g, '``')
                .replace(/"/g, '`"');
        }

        function buildTargetsBlock(items) {
            var lines = [];
            lines.push("$Targets = @(");

            items.forEach(function (item, index) {
                var row = "    [pscustomobject]@{ Name = " + psQuote(item.name) +
                    "; SamAccountName = " + psQuote(item.sam) +
                    "; DistinguishedName = " + psQuote(item.dn) + " }";

                if (index < items.length - 1) {
                    row += ",";
                }

                lines.push(row);
            });

            lines.push(")");
            return lines.join("\r\n");
        }

        function buildLoggingFunctions() {
            return [
                "function New-SafeHtml {",
                "    param([object]$Text)",
                "    if ($null -eq $Text) { return '' }",
                "    return [System.Net.WebUtility]::HtmlEncode([string]$Text)",
                "}",
                "",
                "function Get-DateText {",
                "    param($DateValue)",
                "    if ($null -eq $DateValue) { return '' }",
                "    try { return ([datetime]$DateValue).ToString('yyyy-MM-dd HH:mm:ss') }",
                "    catch { return [string]$DateValue }",
                "}",
                "",
                "function Write-ActionHtmlReport {",
                "    param(",
                "        [Parameter(Mandatory)]$Results,",
                "        [Parameter(Mandatory)][string]$HtmlPath,",
                "        [Parameter(Mandatory)][string]$Title",
                "    )",
                "",
                "    $rowBuilder = New-Object System.Text.StringBuilder",
                "",
                "    foreach ($r in $Results) {",
                "        $rowClass = switch ($r.Status) {",
                "            'Deleted'      { 'ok-row' }",
                "            'Moved'        { 'warn-row' }",
                "            'WouldProcess' { 'warn-row' }",
                "            'Blocked'      { 'warn-row' }",
                "            'Failed'       { 'danger-row' }",
                "            'NotFound'     { 'danger-row' }",
                "            default        { '' }",
                "        }",
                "",
                "        $statusBadgeClass = switch ($r.Status) {",
                "            'Deleted'      { 'action-log-badge ok' }",
                "            'Moved'        { 'action-log-badge warn' }",
                "            'WouldProcess' { 'action-log-badge warn' }",
                "            'Blocked'      { 'action-log-badge warn' }",
                "            'Failed'       { 'action-log-badge danger' }",
                "            'NotFound'     { 'action-log-badge danger' }",
                "            default        { 'action-log-badge warn' }",
                "        }",
                "",
                "        $rowHtml = '<tr class=\"' + (New-SafeHtml $rowClass) + '\">' +",
                "            '<td>' + (New-SafeHtml $r.Time) + '</td>' +",
                "            '<td>' + (New-SafeHtml $r.Name) + '</td>' +",
                "            '<td>' + (New-SafeHtml $r.SamAccountName) + '</td>' +",
                "            '<td><span class=\"' + (New-SafeHtml $statusBadgeClass) + '\">' + (New-SafeHtml $r.Status) + '</span></td>' +",
                "            '<td>' + (New-SafeHtml $r.Action) + '</td>' +",
                "            '<td>' + (New-SafeHtml $r.Message) + '</td>' +",
                "            '<td>' + (New-SafeHtml $r.DistinguishedName) + '</td>' +",
                "            '<td>' + (New-SafeHtml $r.NewDistinguishedName) + '</td>' +",
                "            '<td>' + (New-SafeHtml ([string]$r.IsPrivileged)) + '</td>' +",
                "            '</tr>'",
                "",
                "        [void]$rowBuilder.AppendLine($rowHtml)",
                "    }",
                "",
                "    $totalCount   = @($Results).Count",
                "    $successCount = @($Results | Where-Object { $_.Status -in @('Deleted','Moved','WouldProcess') }).Count",
                "    $blockedCount = @($Results | Where-Object { $_.Status -eq 'Blocked' }).Count",
                "    $failedCount  = @($Results | Where-Object { $_.Status -in @('Failed','NotFound') }).Count",
                "",
                '    $html = @"',
                "<!doctype html>",
                "<html lang='fi'>",
                "<head>",
                "<meta charset='utf-8'>",
                "<meta name='viewport' content='width=device-width, initial-scale=1'>",
                "<title>$Title</title>",
                "<style>",
                "body { font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; background: #f3f6fb; color: #0f172a; }",
                ".card { background: #ffffff; border: 1px solid #d9e2ef; border-radius: 16px; padding: 18px; margin-bottom: 18px; box-shadow: 0 10px 24px rgba(15,23,42,.06); }",
                ".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }",
                ".stat { background: #f8fbff; border: 1px solid #d9e2ef; border-radius: 12px; padding: 12px; }",
                ".stat .k { color: #475569; font-size: 12px; text-transform: uppercase; margin-bottom: 6px; font-weight: 700; }",
                ".stat .v { font-size: 28px; font-weight: 800; }",
                "table { width: 100%; border-collapse: collapse; background: #ffffff; }",
                "th, td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; vertical-align: top; font-size: 13px; }",
                "th { background: #edf4ff; position: sticky; top: 0; }",
                ".ok-row td { background: #f0fdf4; }",
                ".warn-row td { background: #fffbeb; }",
                ".danger-row td, .bad-row td { background: #fef2f2; }",
                ".action-log-badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; line-height:1.4; }",
                ".action-log-badge.ok { background:#dcfce7; color:#166534; }",
                ".action-log-badge.warn { background:#fef3c7; color:#92400e; }",
                ".action-log-badge.danger { background:#fee2e2; color:#991b1b; }",
                ".muted { color:#475569; }",
                "</style>",
                "</head>",
                "<body>",
                "<div class='card'>",
                "<h1>$Title</h1>",
                "<p class='muted'>Generated: $(Get-DateText (Get-Date))</p>",
                "<div class='grid'>",
                "<div class='stat'><div class='k'>Targets</div><div class='v'>$totalCount</div></div>",
                "<div class='stat'><div class='k'>Success / Preview</div><div class='v'>$successCount</div></div>",
                "<div class='stat'><div class='k'>Blocked</div><div class='v'>$blockedCount</div></div>",
                "<div class='stat'><div class='k'>Failed / NotFound</div><div class='v'>$failedCount</div></div>",
                "</div>",
                "</div>",
                "<div class='card'>",
                "<h2>Results</h2>",
                "<table>",
                "<thead>",
                "<tr>",
                "<th>Time</th>",
                "<th>Name</th>",
                "<th>SamAccountName</th>",
                "<th>Status</th>",
                "<th>Action</th>",
                "<th>Message</th>",
                "<th>DistinguishedName</th>",
                "<th>NewDistinguishedName</th>",
                "<th>Privileged</th>",
                "</tr>",
                "</thead>",
                "<tbody>",
                "$($rowBuilder.ToString())",
                "</tbody>",
                "</table>",
                "</div>",
                "</body>",
                "</html>",
                '"@',
                "",
                "    [System.IO.File]::WriteAllText($HtmlPath, $html, [System.Text.UTF8Encoding]::new($false))",
                "}"
            ].join("\r\n");
        }

        function buildCommonHeader(actionName) {
            return [
                "param(",
                "    [string]$OutputFolder = 'C:\\Temp\\ADGroupActions'",
                ")",
                "",
                "$ErrorActionPreference = 'Stop'",
                "Import-Module ActiveDirectory -ErrorAction Stop",
                "",
                "if (-not (Test-Path -LiteralPath $OutputFolder)) {",
                "    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null",
                "}",
                "",
                "$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'",
                "$csvPath   = Join-Path $OutputFolder ('" + actionName + "_' + $timestamp + '.csv')",
                "$htmlPath  = Join-Path $OutputFolder ('" + actionName + "_' + $timestamp + '.html')",
                "",
                "$PrivilegedGroupNames = @(",
                "    'Administrators',",
                "    'Domain Admins',",
                "    'Enterprise Admins',",
                "    'Schema Admins',",
                "    'Account Operators',",
                "    'Server Operators',",
                "    'Backup Operators',",
                "    'Print Operators',",
                "    'Group Policy Creator Owners',",
                "    'DnsAdmins',",
                "    'Cert Publishers',",
                "    'Remote Desktop Users',",
                "    'Protected Users',",
                "    'Key Admins',",
                "    'Enterprise Key Admins'",
                ")",
                ""
            ].join("\r\n");
        }

        function buildReportOnlyScript(items) {
            return [
                buildCommonHeader("ReportOnly"),
                buildLoggingFunctions(),
                "",
                buildTargetsBlock(items),
                "",
                "$results = [System.Collections.ArrayList]::new()",
                "",
                "foreach ($t in $Targets) {",
                "    Write-Host ('Processing: {0}' -f $t.Name) -ForegroundColor Cyan",
                "",
                "    $status = ''",
                "    $message = ''",
                "    $isPrivileged = $false",
                "",
                "    try {",
                "        $g = Get-ADGroup -Identity $t.DistinguishedName -Properties SamAccountName -ErrorAction Stop",
                "        $isPrivileged = $PrivilegedGroupNames -contains $g.Name",
                "        $status = 'WouldProcess'",
                "        $message = 'Preview only. No changes made.'",
                "    }",
                "    catch {",
                "        $status = 'NotFound'",
                "        $message = $_.Exception.Message",
                "    }",
                "",
                "    [void]$results.Add([pscustomobject]@{",
                "        Time                 = Get-DateText (Get-Date)",
                "        Name                 = $t.Name",
                "        SamAccountName       = $t.SamAccountName",
                "        DistinguishedName    = $t.DistinguishedName",
                "        NewDistinguishedName = ''",
                "        Status               = $status",
                "        Action               = 'ReportOnly'",
                "        Message              = $message",
                "        IsPrivileged         = $isPrivileged",
                "    })",
                "}",
                "",
                "$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8",
                "Write-ActionHtmlReport -Results $results -HtmlPath $htmlPath -Title 'AD Group ReportOnly Log'",
                "",
                "Write-Host ''",
                "Write-Host 'Done.' -ForegroundColor Green",
                "Write-Host ('CSV : {0}' -f $csvPath)",
                "Write-Host ('HTML: {0}' -f $htmlPath)"
            ].join("\r\n");
        }

        function buildMoveScript(items, targetOu, prefix) {
            return [
                "param(",
                "    [string]$OutputFolder = 'C:\\Temp\\ADGroupActions',",
                "    [string]$TargetOu = '" + escapePs(targetOu || 'OU=Disabled Groups,OU=Groups,DC=example,DC=local') + "',",
                "    [string]$Prefix = '" + escapePs(prefix || 'DISABLED_') + "'",
                ")",
                "",
                "$ErrorActionPreference = 'Stop'",
                "Import-Module ActiveDirectory -ErrorAction Stop",
                "",
                "if (-not (Test-Path -LiteralPath $OutputFolder)) {",
                "    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null",
                "}",
                "",
                "$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'",
                "$csvPath   = Join-Path $OutputFolder ('MoveAndTag_' + $timestamp + '.csv')",
                "$htmlPath  = Join-Path $OutputFolder ('MoveAndTag_' + $timestamp + '.html')",
                "",
                "$PrivilegedGroupNames = @(",
                "    'Administrators',",
                "    'Domain Admins',",
                "    'Enterprise Admins',",
                "    'Schema Admins',",
                "    'Account Operators',",
                "    'Server Operators',",
                "    'Backup Operators',",
                "    'Print Operators',",
                "    'Group Policy Creator Owners',",
                "    'DnsAdmins',",
                "    'Cert Publishers',",
                "    'Remote Desktop Users',",
                "    'Protected Users',",
                "    'Key Admins',",
                "    'Enterprise Key Admins'",
                ")",
                "",
                buildLoggingFunctions(),
                "",
                buildTargetsBlock(items),
                "",
                "Get-ADOrganizationalUnit -Identity $TargetOu -ErrorAction Stop | Out-Null",
                "",
                "$results = [System.Collections.ArrayList]::new()",
                "",
                "foreach ($t in $Targets) {",
                "    Write-Host ('Processing: {0}' -f $t.Name) -ForegroundColor Cyan",
                "",
                "    $status = ''",
                "    $message = ''",
                "    $isPrivileged = $false",
                "    $newDn = ''",
                "",
                "    try {",
                "        $g = Get-ADGroup -Identity $t.DistinguishedName -Properties DistinguishedName,Name,SamAccountName -ErrorAction Stop",
                "        $isPrivileged = $PrivilegedGroupNames -contains $g.Name",
                "",
                "        if ($isPrivileged) {",
                "            $status = 'Blocked'",
                "            $message = 'Privileged group blocked'",
                "        }",
                "        else {",
                "            $newName = $g.Name",
                "            if ($newName -notlike ($Prefix + '*')) {",
                "                $newName = $Prefix + $newName",
                "                Rename-ADObject -Identity $g.DistinguishedName -NewName $newName -ErrorAction Stop",
                "                $g = Get-ADGroup -Identity $g.SamAccountName -Properties DistinguishedName,Name,SamAccountName -ErrorAction Stop",
                "            }",
                "",
                "            Move-ADObject -Identity $g.DistinguishedName -TargetPath $TargetOu -ErrorAction Stop",
                "            $g2 = Get-ADGroup -Identity $g.SamAccountName -Properties DistinguishedName -ErrorAction Stop",
                "            $newDn = $g2.DistinguishedName",
                "            $status = 'Moved'",
                "            $message = 'Renamed and moved to quarantine OU'",
                "        }",
                "    }",
                "    catch {",
                "        $status = 'Failed'",
                "        $message = $_.Exception.Message",
                "    }",
                "",
                "    [void]$results.Add([pscustomobject]@{",
                "        Time                 = Get-DateText (Get-Date)",
                "        Name                 = $t.Name",
                "        SamAccountName       = $t.SamAccountName",
                "        DistinguishedName    = $t.DistinguishedName",
                "        NewDistinguishedName = $newDn",
                "        Status               = $status",
                "        Action               = 'MoveAndTag'",
                "        Message              = $message",
                "        IsPrivileged         = $isPrivileged",
                "    })",
                "}",
                "",
                "$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8",
                "Write-ActionHtmlReport -Results $results -HtmlPath $htmlPath -Title 'AD Group MoveAndTag Log'",
                "",
                "Write-Host ''",
                "Write-Host 'Done.' -ForegroundColor Green",
                "Write-Host ('CSV : {0}' -f $csvPath)",
                "Write-Host ('HTML: {0}' -f $htmlPath)"
            ].join("\r\n");
        }

        function buildDeleteScript(items, useWhatIf) {
            return [
                "param(",
                "    [string]$OutputFolder = 'C:\\Temp\\ADGroupActions'",
                ")",
                "",
                "$WhatIfMode = " + (useWhatIf ? '$true' : '$false'),
                "",
                "$ErrorActionPreference = 'Stop'",
                "Import-Module ActiveDirectory -ErrorAction Stop",
                "",
                "if (-not (Test-Path -LiteralPath $OutputFolder)) {",
                "    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null",
                "}",
                "",
                "$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'",
                "$csvPath   = Join-Path $OutputFolder ('DeleteAndLog_' + $timestamp + '.csv')",
                "$htmlPath  = Join-Path $OutputFolder ('DeleteAndLog_' + $timestamp + '.html')",
                "",
                "$PrivilegedGroupNames = @(",
                "    'Administrators',",
                "    'Domain Admins',",
                "    'Enterprise Admins',",
                "    'Schema Admins',",
                "    'Account Operators',",
                "    'Server Operators',",
                "    'Backup Operators',",
                "    'Print Operators',",
                "    'Group Policy Creator Owners',",
                "    'DnsAdmins',",
                "    'Cert Publishers',",
                "    'Remote Desktop Users',",
                "    'Protected Users',",
                "    'Key Admins',",
                "    'Enterprise Key Admins'",
                ")",
                "",
                buildLoggingFunctions(),
                "",
                buildTargetsBlock(items),
                "",
                "$results = [System.Collections.ArrayList]::new()",
                "",
                "foreach ($t in $Targets) {",
                "    Write-Host ('Processing: {0}' -f $t.Name) -ForegroundColor Cyan",
                "",
                "    $status = ''",
                "    $message = ''",
                "    $isPrivileged = $false",
                "",
                "    try {",
                "        $g = Get-ADGroup -Identity $t.DistinguishedName -Properties DistinguishedName,Name -ErrorAction Stop",
                "        $isPrivileged = $PrivilegedGroupNames -contains $g.Name",
                "",
                "        if ($isPrivileged) {",
                "            $status = 'Blocked'",
                "            $message = 'Privileged group blocked'",
                "        }",
                "        else {",
                "            if ($WhatIfMode) {",
                "                Remove-ADGroup -Identity $g.DistinguishedName -Confirm:`$false -WhatIf -ErrorAction Stop",
                "                $status = 'WouldProcess'",
                "                $message = 'WhatIf preview. No deletion performed.'",
                "            }",
                "            else {",
                "                Remove-ADGroup -Identity $g.DistinguishedName -Confirm:`$false -ErrorAction Stop",
                "                $status = 'Deleted'",
                "                $message = 'Group deleted'",
                "            }",
                "        }",
                "    }",
                "    catch {",
                "        if (-not $status) {",
                "            $status = 'Failed'",
                "            $message = $_.Exception.Message",
                "        }",
                "    }",
                "",
                "    [void]$results.Add([pscustomobject]@{",
                "        Time                 = Get-DateText (Get-Date)",
                "        Name                 = $t.Name",
                "        SamAccountName       = $t.SamAccountName",
                "        DistinguishedName    = $t.DistinguishedName",
                "        NewDistinguishedName = ''",
                "        Status               = $status",
                "        Action               = 'DeleteAndLog'",
                "        Message              = $message",
                "        IsPrivileged         = $isPrivileged",
                "    })",
                "}",
                "",
                "$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8",
                "Write-ActionHtmlReport -Results $results -HtmlPath $htmlPath -Title 'AD Group DeleteAndLog Log'",
                "",
                "Write-Host ''",
                "Write-Host 'Done.' -ForegroundColor Green",
                "Write-Host ('CSV : {0}' -f $csvPath)",
                "Write-Host ('HTML: {0}' -f $htmlPath)"
            ].join("\r\n");
        }

        function getSelectedItems() {
            var selectedRows = getSelectedRows();

            return selectedRows.map(function (row) {
                return {
                    name: row.dataset.name || '',
                    sam: row.dataset.sam || '',
                    dn: row.dataset.dn || '',
                    privileged: row.dataset.privileged === 'yes',
                    cleanup: row.dataset.cleanup || ''
                };
            });
        }

        function buildSelectedCsv(items) {
            var lines = ['Name,SamAccountName,DistinguishedName,Privileged,CleanupSuggestion'];

            function csv(v) {
                var s = String(v == null ? '' : v);
                if (s.indexOf('"') !== -1 || s.indexOf(',') !== -1 || s.indexOf(String.fromCharCode(10)) !== -1 || s.indexOf(String.fromCharCode(13)) !== -1) {
                    return '"' + s.replace(/"/g, '""') + '"';
                }
                return s;
            }

            items.forEach(function (item) {
                lines.push([
                    csv(item.name),
                    csv(item.sam),
                    csv(item.dn),
                    csv(item.privileged ? 'Yes' : 'No'),
                    csv(item.cleanup)
                ].join(','));
            });

            return lines.join(String.fromCharCode(10));
        }

        function renderBulkPreview() {
            var items = getSelectedItems();

            if (!bulkPreview || !bulkActionType) {
                return;
            }

            var action = bulkActionType.value || 'report';
            var useWhatIf = !bulkDeleteMode || bulkDeleteMode.value !== 'live';
            var targetOu = bulkTargetOu ? bulkTargetOu.value : 'OU=Disabled Groups,OU=Groups,DC=example,DC=local';
            var prefix = bulkPrefix ? bulkPrefix.value : 'DISABLED_';

            handleBulkActionUI();
            updateBulkWarnings(items, action, useWhatIf);

            if (action === 'report') {
                bulkPreview.value = buildReportOnlyScript(items);
            }
            else if (action === 'move') {
                bulkPreview.value = buildMoveScript(items, targetOu, prefix);
            }
            else if (action === 'delete') {
                bulkPreview.value = buildDeleteScript(items, useWhatIf);
            }
            else if (action === 'exportcsv') {
                bulkPreview.value = buildSelectedCsv(items);
            }
        }

        async function copyBulkPreview() {
            var text = bulkPreview ? bulkPreview.value : '';

            try {
                await navigator.clipboard.writeText(text || '');
            } catch (e) {
                if (bulkPreview) {
                    bulkPreview.focus();
                    bulkPreview.select();
                    document.execCommand('copy');
                }
            }
        }

        function downloadBulkPreview() {
            var action = bulkActionType ? bulkActionType.value : 'bulk';
            var isCsv = action === 'exportcsv';
            var extension = isCsv ? 'csv' : 'ps1';
            var mimeType = isCsv ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8';
            var content = bulkPreview ? bulkPreview.value : '';
            var blob = new Blob([content], { type: mimeType });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');

            a.href = url;
            a.download = 'ad-groups-' + action + '.' + extension;
            document.body.appendChild(a);
            a.click();
            a.remove();

            URL.revokeObjectURL(url);
        }

        function openBulkActionModal() {
            var selectedRows = getSelectedRows();

            if (selectedRows.length === 0) {
                alert('Valitse ensin vähintään yksi ryhmä.');
                return;
            }

            if (bulkModalSummary) {
                bulkModalSummary.textContent = selectedRows.length + ' object(s) selected.';
            }

            if (bulkModal) {
                bulkModal.classList.add('open');
                bulkModal.setAttribute('aria-hidden', 'false');
            }

            document.body.style.overflow = 'hidden';
            handleBulkActionUI();
            renderBulkPreview();

            if (bulkModalClose) {
                bulkModalClose.focus();
            }
        }

        function closeBulkActionModal() {
            if (bulkModal) {
                bulkModal.classList.remove('open');
                bulkModal.setAttribute('aria-hidden', 'true');
            }
            document.body.style.overflow = '';
        }

        statButtons.forEach(function (btn) {
            btn.addEventListener('click', function () {
                currentFilter = this.dataset.filter || 'all';
                applyFilters(true);

                var section = qs('groups-section');
                if (section) {
                    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });

        if (clearFilterBtn) {
            clearFilterBtn.addEventListener('click', function () {
                currentFilter = 'all';

                if (searchInput) {
                    searchInput.value = '';
                }

                if (rowsPerPageSelect) {
                    rowsPerPageSelect.value = '25';
                }

                applyFilters(true);
            });
        }

        if (searchInput) {
            searchInput.addEventListener('input', function () {
                applyFilters(true);
            });
        }

        if (rowsPerPageSelect) {
            rowsPerPageSelect.addEventListener('change', function () {
                applyFilters(true);
            });
        }

        headers.forEach(function (th) {
            th.addEventListener('click', function () {
                sortTable(Number(this.dataset.col), this.dataset.type || 'text');
            });
        });

        if (firstPageBtn) {
            firstPageBtn.addEventListener('click', function () {
                currentPage = 1;
                updatePagination();
            });
        }

        if (prevPageBtn) {
            prevPageBtn.addEventListener('click', function () {
                if (currentPage > 1) {
                    currentPage--;
                    updatePagination();
                }
            });
        }

        if (nextPageBtn) {
            nextPageBtn.addEventListener('click', function () {
                var rowsPerPage = getRowsPerPage();
                var filteredRows = getFilteredRows();
                var totalPages = rowsPerPage ? Math.ceil(filteredRows.length / rowsPerPage) : 1;

                if (currentPage < totalPages) {
                    currentPage++;
                    updatePagination();
                }
            });
        }

        if (lastPageBtn) {
            lastPageBtn.addEventListener('click', function () {
                var rowsPerPage = getRowsPerPage();
                var filteredRows = getFilteredRows();
                var totalPages = rowsPerPage ? Math.ceil(filteredRows.length / rowsPerPage) : 1;

                currentPage = totalPages;
                updatePagination();
            });
        }

        if (tbody) {
            tbody.addEventListener('click', function (e) {
                var toggleBtn = findParentByClass(e.target, 'member-toggle');
                if (toggleBtn) {
                    var cell = findParentByClass(toggleBtn, 'member-cell');
                    if (!cell) return;

                    cell.classList.toggle('expanded');
                    toggleBtn.textContent = cell.classList.contains('expanded') ? 'Näytä vähemmän' : 'Näytä lisää';
                    return;
                }

                var modalBtn = findParentByClass(e.target, 'member-modal-open');
                if (modalBtn) {
                    lastFocusedButton = modalBtn;
                    var groupName = modalBtn.getAttribute('data-group-name') || '';
                    var membersText = modalBtn.getAttribute('data-members-full') || '';
                    openMembersModal(groupName, membersText, modalBtn);
                }
            });

            tbody.addEventListener('change', function (e) {
                if (e.target && e.target.classList && e.target.classList.contains('row-select')) {
                    updateSelectedDeleteCount();
                    updateHeaderSelectAllState();
                }
            });
        }

        if (selectVisibleBtn) {
            selectVisibleBtn.addEventListener('click', function () {
                getVisibleSelectableRows().forEach(function (row) {
                    var cb = row.querySelector('.row-select');
                    if (cb) cb.checked = true;
                });
                updateSelectedDeleteCount();
                updateHeaderSelectAllState();
            });
        }

        if (clearSelectionBtn) {
            clearSelectionBtn.addEventListener('click', function () {
                getAllRows().forEach(function (row) {
                    var cb = row.querySelector('.row-select');
                    if (cb) cb.checked = false;
                });
                updateSelectedDeleteCount();
                updateHeaderSelectAllState();
            });
        }

        if (selectAllVisibleCheckbox) {
            selectAllVisibleCheckbox.addEventListener('change', function () {
                var shouldCheck = this.checked;

                getVisibleSelectableRows().forEach(function (row) {
                    var cb = row.querySelector('.row-select');
                    if (cb) cb.checked = shouldCheck;
                });

                updateSelectedDeleteCount();
                updateHeaderSelectAllState();
            });
        }

        if (openBulkModalBtn) {
            openBulkModalBtn.addEventListener('click', openBulkActionModal);
        }

        qsa('.finding-link').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openFinding(this.getAttribute('data-finding-filter') || 'all');
            });
        });

        if (membersModalClose) {
            membersModalClose.addEventListener('click', closeMembersModal);
        }

        if (membersModal) {
            membersModal.addEventListener('click', function (e) {
                if (e.target === membersModal) {
                    closeMembersModal();
                }
            });
        }

        if (bulkModalClose) {
            bulkModalClose.addEventListener('click', closeBulkActionModal);
        }

        if (closeBulkModalFooterBtn) {
            closeBulkModalFooterBtn.addEventListener('click', closeBulkActionModal);
        }

        if (copyBulkPreviewBtn) {
            copyBulkPreviewBtn.addEventListener('click', copyBulkPreview);
        }

        if (downloadBulkPreviewBtn) {
            downloadBulkPreviewBtn.addEventListener('click', downloadBulkPreview);
        }

        if (bulkActionType) {
            bulkActionType.addEventListener('change', function () {
                handleBulkActionUI();
                renderBulkPreview();
            });
        }

        if (bulkDeleteMode) {
            bulkDeleteMode.addEventListener('change', renderBulkPreview);
        }

        if (bulkTargetOu) {
            bulkTargetOu.addEventListener('input', renderBulkPreview);
        }

        if (bulkPrefix) {
            bulkPrefix.addEventListener('input', renderBulkPreview);
        }

        if (bulkModal) {
            bulkModal.addEventListener('click', function (e) {
                if (e.target === bulkModal) {
                    closeBulkActionModal();
                }
            });
        }

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && membersModal && membersModal.classList.contains('open')) {
                closeMembersModal();
            }
            if (e.key === 'Escape' && bulkModal && bulkModal.classList.contains('open')) {
                closeBulkActionModal();
            }
        });

        handleBulkActionUI();
        applyFilters(true);
    }
    catch (err) {
        console.error('AD Groups Audit UI init failed:', err);
        alert('UI initialization failed. Check browser console (F12).');
    }
});
</script>
</body>
</html>
'@

$html = $htmlTemplate
$html = $html.Replace('__DOMAIN__', (New-SafeHtml $domainInfo.DNSRoot))
$html = $html.Replace('__SEARCHBASE__', (New-SafeHtml $effectiveSearchBase))
$html = $html.Replace('__RECURSIVE__', (New-SafeHtml $recursiveEnabledText))
$html = $html.Replace('__STALEYEARS__', (New-SafeHtml "$StaleYears year(s)"))
$html = $html.Replace('__GENERATED__', (New-SafeHtml (Get-DateText (Get-Date))))
$html = $html.Replace('__TOTALGROUPS__', [string]$totalGroups)
$html = $html.Replace('__EMPTYGROUPS__', [string]$emptyGroups)
$html = $html.Replace('__EMPTYNONPRIV__', [string]$emptyNonPrivCount)
$html = $html.Replace('__PRIVGROUPS__', [string]$privilegedGroups)
$html = $html.Replace('__HIGHRISK__', [string]$highRiskGroups)
$html = $html.Replace('__MEDIUMRISK__', [string]$mediumRiskGroups)
$html = $html.Replace('__LOWRISK__', [string]$lowRiskGroups)
$html = $html.Replace('__MEMBERERRORS__', [string]$memberErrorCount)
$html = $html.Replace('__STALEHIGH__', [string]$staleHighCount)
$html = $html.Replace('__STRONGREVIEW__', [string]$strongReviewCount)
$html = $html.Replace('__TOPFINDINGS__', $topFindingsHtml)
$html = $html.Replace('__HTMLROWS__', ($htmlRows -join "`r`n"))

[System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Valmis." -ForegroundColor Green
Write-Host "CSV : $csvPath"
Write-Host "HTML: $htmlPath"
Write-Host ""
Write-Host "Huom: Tämä skripti on read-only. Se ei tee muutoksia Active Directoryyn." -ForegroundColor Yellow
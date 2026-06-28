<#
.SYNOPSIS
    Group Policy Object Audit Dashboard.

.DESCRIPTION
    Kerää Group Policy -objektien perustiedot, linkitykset, periytymiset ja vanhentuneisiin GPO:ihin liittyvät havainnot.

.REQUIREMENTS
    - GroupPolicy- ja ActiveDirectory-moduulit, lukuoikeus GPO-tietoihin

.OUTPUTS
    - HTML/CSV-raportit GPO-objekteista ja löydöksistä

.EXAMPLE
    .\Invoke-GPOAuditReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Invoke-GPOAuditReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY COLLECTION: The audit collection is intended to be read-only. The generated report may include optional cleanup/helper PowerShell snippets such as Backup-GPO or Remove-GPO examples for manual review only. Review generated helper code separately and run it only if you intentionally choose to do so.
#>

param(
    [string]$OutputFolder = (Join-Path $PSScriptRoot "output\gpo"),
    [int]$OldGpoYears = 2,
    [int]$RowsPerPage = 10
)

$ErrorActionPreference = "Stop"

$ExcludedGpoNames = @(
    "Default Domain Controllers Policy",
    "Default Domain Policy"
)

function New-SafeHtml {
    param([object]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Convert-ToJsStringLiteral {
    param([AllowNull()][string]$Text)

    if ($null -eq $Text) { return "" }

    $s = [string]$Text
    $s = $s -replace '\\', '\\\\'
    $s = $s -replace "'", "\'"
    $s = $s -replace "`r", '\r'
    $s = $s -replace "`n", '\n'
    $s = $s -replace '</', '<\/'
    return $s
}

function Get-DateText {
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

function Get-BoolText {
    param([object]$Value)

    if ($null -eq $Value) { return "" }

    try {
        if ([bool]$Value) { return "Yes" }
        return "No"
    }
    catch {
        return [string]$Value
    }
}

function Get-GpoStatusText {
    param([object]$GpoStatus)

    if ($null -eq $GpoStatus) { return "" }

    switch ($GpoStatus.ToString()) {
        "AllSettingsEnabled"       { return "Enabled" }
        "AllSettingsDisabled"      { return "Disabled" }
        "UserSettingsDisabled"     { return "Computer only" }
        "ComputerSettingsDisabled" { return "User only" }
        default                    { return $GpoStatus.ToString() }
    }
}

function Get-XmlNodeText {
    param(
        [xml]$Xml,
        [string]$XPath
    )

    try {
        $node = $Xml.SelectSingleNode($XPath)
        if ($node -and $node.InnerText) {
            return $node.InnerText.Trim()
        }
    }
    catch {}

    return $null
}

function Get-GpoSecurityFilteringText {
    param([xml]$Xml)

    $names = New-Object System.Collections.Generic.List[string]

    try {
        $permNodes = $Xml.SelectNodes("//*[local-name()='SecurityDescriptor']/*[local-name()='Permissions']")
        foreach ($perm in $permNodes) {
            $permType = ""
            $trusteeName = ""

            try { $permType = $perm.PermissionType.InnerText.Trim() } catch {}
            try { $trusteeName = $perm.Trustee.Name.InnerText.Trim() } catch {}

            if ($permType -eq "GpoApply" -and -not [string]::IsNullOrWhiteSpace($trusteeName)) {
                if (-not $names.Contains($trusteeName)) {
                    [void]$names.Add($trusteeName)
                }
            }
        }
    }
    catch {}

    if ($names.Count -eq 0) { return "" }
    return ($names -join "; ")
}

function Test-GpoLikelyEmpty {
    param([xml]$Xml)

    if ($null -eq $Xml) {
        return $false
    }

    try {
        $computerNode = $Xml.SelectSingleNode("//*[local-name()='Computer']/*[local-name()='ExtensionData']")
        $userNode     = $Xml.SelectSingleNode("//*[local-name()='User']/*[local-name()='ExtensionData']")

        $computerHasContent = $false
        $userHasContent     = $false

        if ($computerNode -and -not [string]::IsNullOrWhiteSpace($computerNode.InnerXml)) {
            $computerInner = $computerNode.InnerXml.Trim()
            if ($computerInner -match '<') {
                $computerHasContent = $true
            }
        }

        if ($userNode -and -not [string]::IsNullOrWhiteSpace($userNode.InnerXml)) {
            $userInner = $userNode.InnerXml.Trim()
            if ($userInner -match '<') {
                $userHasContent = $true
            }
        }

        return (-not $computerHasContent -and -not $userHasContent)
    }
    catch {
        return $false
    }
}

function Add-GpoLinkRecord {
    param(
        [hashtable]$Map,
        [Guid]$GpoId,
        [string]$TargetType,
        [string]$TargetName,
        [string]$TargetDn
    )

    $key = $GpoId.Guid.ToLowerInvariant()

    if (-not $Map.ContainsKey($key)) {
        $Map[$key] = New-Object System.Collections.Generic.List[object]
    }

    $targetLabel = $TargetType
    if (-not [string]::IsNullOrWhiteSpace($TargetName)) {
        $targetLabel += ": $TargetName"
    }

    $record = [pscustomobject]@{
        TargetType = $TargetType
        TargetName = $TargetName
        TargetDn   = $TargetDn
        Label      = $targetLabel
    }

    $existing = $Map[$key] | Where-Object {
        $_.TargetDn -eq $TargetDn -and $_.TargetType -eq $TargetType
    }

    if (-not $existing) {
        [void]$Map[$key].Add($record)
    }
}

function Add-GpoLinksFromGpLink {
    param(
        [hashtable]$Map,
        [string]$GpLink,
        [string]$TargetType,
        [string]$TargetName,
        [string]$TargetDn
    )

    if ([string]::IsNullOrWhiteSpace($GpLink)) { return }

    $matches = [regex]::Matches($GpLink, '\[LDAP://(?<path>[^;]+);(?<opt>\d+)\]')

    foreach ($m in $matches) {
        $path = $m.Groups["path"].Value

        $guidMatch = [regex]::Match(
            $path,
            'CN=\{(?<guid>[0-9A-Fa-f\-]+)\},CN=Policies,CN=System,',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )

        if ($guidMatch.Success) {
            try {
                $guid = [Guid]$guidMatch.Groups["guid"].Value
                Add-GpoLinkRecord -Map $Map -GpoId $guid -TargetType $TargetType -TargetName $TargetName -TargetDn $TargetDn
            }
            catch {}
        }
    }
}

function Get-GpoLinkMapFromAd {
    param(
        [string]$DomainDn,
        [string]$ConfigNc,
        [string]$DomainDnsRoot
    )

    $map = @{}

    try {
        $domainObj = Get-ADObject -Identity $DomainDn -Properties gPLink, distinguishedName, name
        Add-GpoLinksFromGpLink -Map $map -GpLink $domainObj.gPLink -TargetType "Domain" -TargetName $DomainDnsRoot -TargetDn $domainObj.DistinguishedName
    }
    catch {
        Write-Warning "Failed to read domain gPLink from $DomainDn. $_"
    }

    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Properties gPLink, distinguishedName, name
        foreach ($ou in $ous) {
            Add-GpoLinksFromGpLink -Map $map -GpLink $ou.gPLink -TargetType "OU" -TargetName $ou.Name -TargetDn $ou.DistinguishedName
        }
    }
    catch {
        Write-Warning "Failed to enumerate OU gPLink values. $_"
    }

    try {
        $sitesBase = "CN=Sites,$ConfigNc"
        $sites = Get-ADObject -SearchBase $sitesBase -LDAPFilter "(objectClass=site)" -Properties gPLink, distinguishedName, name
        foreach ($site in $sites) {
            Add-GpoLinksFromGpLink -Map $map -GpLink $site.gPLink -TargetType "Site" -TargetName $site.Name -TargetDn $site.DistinguishedName
        }
    }
    catch {
        Write-Warning "Failed to enumerate site gPLink values. $_"
    }

    return $map
}

function Get-CleanupHint {
    param(
        [bool]$IsUnlinked,
        [bool]$IsDisabled,
        [bool]$IsOld,
        [bool]$IsLikelyEmpty
    )

    if ($IsUnlinked -and $IsDisabled -and $IsOld) {
        return "HIGH CONFIDENCE - review for delete"
    }
    elseif ($IsUnlinked -and $IsDisabled) {
        return "SAFE DELETE CANDIDATE"
    }
    elseif ($IsUnlinked -and $IsOld) {
        return "LIKELY REMOVABLE (verify)"
    }
    elseif ($IsDisabled -and $IsOld) {
        return "REVIEW (disabled + old)"
    }
    elseif ($IsUnlinked) {
        return "UNLINKED - investigate"
    }
    elseif ($IsLikelyEmpty) {
        return "LIKELY EMPTY - verify"
    }
    elseif ($IsOld) {
        return "OLD - verify usage"
    }

    return "ACTIVE"
}

function Get-HtmlBadge {
    param(
        [string]$Text,
        [string]$ClassName
    )

    return '<span class="badge ' + (New-SafeHtml $ClassName) + '">' + (New-SafeHtml $Text) + '</span>'
}

function Get-StatusBadgeClass {
    param([string]$Status)

    switch ($Status) {
        "Enabled"       { return "badge-green" }
        "Disabled"      { return "badge-red" }
        "Computer only" { return "badge-blue" }
        "User only"     { return "badge-purple" }
        default         { return "badge-gray" }
    }
}

function Get-CleanupBadgeClass {
    param([string]$CleanupHint)

    if ($CleanupHint -match "^HIGH CONFIDENCE") { return "badge-red" }
    if ($CleanupHint -match "^SAFE DELETE CANDIDATE") { return "badge-red" }
    if ($CleanupHint -match "^LIKELY REMOVABLE") { return "badge-yellow" }
    if ($CleanupHint -match "^REVIEW") { return "badge-yellow" }
    if ($CleanupHint -match "^LIKELY EMPTY") { return "badge-yellow" }
    if ($CleanupHint -match "^OLD") { return "badge-yellow" }
    return "badge-green"
}

function New-FindingBlock {
    param(
        [int]$Count,
        [string]$FilterName,
        [string]$BadgeClass,
        [string]$Label
    )

    $badgeHtml = '<span class="badge ' + (New-SafeHtml $BadgeClass) + ' finding-badge">' + (New-SafeHtml $Count) + '</span>'
    $textHtml  = '<span class="finding-text">' + (New-SafeHtml $Label) + '</span>'

    if ($Count -gt 0) {
        return '<button type="button" class="finding-link" data-filter="' + (New-SafeHtml $FilterName) + '">' + $badgeHtml + $textHtml + '</button>'
    }

    return '<div class="finding-static">' + $badgeHtml + $textHtml + '</div>'
}

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

$htmlPath = Join-Path $OutputFolder "index.html"

$domainInfo = Get-ADDomain
$forestInfo = Get-ADForest
$rootDse    = Get-ADRootDSE
$cutoffDate = (Get-Date).AddYears(-$OldGpoYears)

Write-Host "Building GPO link map from AD gPLink attributes..." -ForegroundColor Cyan
$linkMap = Get-GpoLinkMapFromAd -DomainDn $domainInfo.DistinguishedName -ConfigNc $rootDse.ConfigurationNamingContext -DomainDnsRoot $domainInfo.DNSRoot

Write-Host "Enumerating all GPOs..." -ForegroundColor Cyan
$allGpos = Get-GPO -All |
    Where-Object { $_.DisplayName -notin $ExcludedGpoNames } |
    Sort-Object DisplayName

$results = foreach ($gpo in $allGpos) {
    Write-Host ("Processing: {0}" -f $gpo.DisplayName)

    $xmlString = $null
    $xml = $null

    try {
        $xmlString = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $xml = [xml]$xmlString
    }
    catch {
        Write-Warning ("Failed to read XML report for GPO: {0}. {1}" -f $gpo.DisplayName, $_)
    }

    $gpoKey = $gpo.Id.Guid.ToLowerInvariant()
    $links = @()

    if ($linkMap.ContainsKey($gpoKey)) {
        $links = @($linkMap[$gpoKey] | Sort-Object TargetType, TargetName, TargetDn)
    }

    $linkCount  = @($links).Count
    $isUnlinked = ($linkCount -eq 0)

    $statusText = Get-GpoStatusText -GpoStatus $gpo.GpoStatus
    $isDisabled = ($gpo.GpoStatus.ToString() -eq "AllSettingsDisabled")
    $isOld      = ($gpo.ModificationTime -lt $cutoffDate)

    $isLikelyEmpty      = $false
    $computerEnabled    = ""
    $userEnabled        = ""
    $securityFiltering  = ""
    $wmiFilterName      = ""
    $wmiFilterPath      = ""

    if ($xml) {
        $isLikelyEmpty     = Test-GpoLikelyEmpty -Xml $xml
        $computerEnabled   = Get-XmlNodeText -Xml $xml -XPath "//*[local-name()='Computer']/*[local-name()='Enabled']"
        $userEnabled       = Get-XmlNodeText -Xml $xml -XPath "//*[local-name()='User']/*[local-name()='Enabled']"
        $securityFiltering = Get-GpoSecurityFilteringText -Xml $xml
        $wmiFilterName     = Get-XmlNodeText -Xml $xml -XPath "//*[local-name()='WMIFilter']/*[local-name()='Name']"
        $wmiFilterPath     = Get-XmlNodeText -Xml $xml -XPath "//*[local-name()='WMIFilter']/*[local-name()='Filter']"
    }

    if (-not $computerEnabled) { $computerEnabled = "" }
    if (-not $userEnabled) { $userEnabled = "" }
    if (-not $securityFiltering) { $securityFiltering = "" }
    if (-not $wmiFilterName) { $wmiFilterName = "" }
    if (-not $wmiFilterPath) { $wmiFilterPath = "" }

    $linkTargets = ""
    if ($linkCount -gt 0) {
        $linkTargets = (($links | ForEach-Object { $_.Label }) -join " | ")
    }

    $cleanupHint = Get-CleanupHint -IsUnlinked $isUnlinked -IsDisabled $isDisabled -IsOld $isOld -IsLikelyEmpty $isLikelyEmpty

    [pscustomobject][ordered]@{
        Domain            = $domainInfo.DNSRoot
        Forest            = $forestInfo.Name
        GpoName           = $gpo.DisplayName
        GpoId             = $gpo.Id.Guid
        Created           = Get-DateText $gpo.CreationTime
        Modified          = Get-DateText $gpo.ModificationTime
        Owner             = $gpo.Owner
        Status            = $statusText
        ComputerEnabled   = $computerEnabled
        UserEnabled       = $userEnabled
        LinkCount         = $linkCount
        LinkTargets       = $linkTargets
        IsUnlinked        = $isUnlinked
        IsDisabled        = $isDisabled
        IsOld             = $isOld
        IsLikelyEmpty     = $isLikelyEmpty
        SecurityFiltering = $securityFiltering
        WmiFilterName     = $wmiFilterName
        WmiFilterQuery    = $wmiFilterPath
        Comment           = $gpo.Description
        CleanupHint       = $cleanupHint
    }
}

$cleanupCandidates = @(
    $results | Where-Object {
        $_.CleanupHint -in @(
            "HIGH CONFIDENCE - review for delete",
            "SAFE DELETE CANDIDATE",
            "LIKELY REMOVABLE (verify)"
        )
    }
)

$totalCount       = @($results).Count
$linkedCount      = @($results | Where-Object { -not $_.IsUnlinked }).Count
$unlinkedCount    = @($results | Where-Object { $_.IsUnlinked }).Count
$disabledCount    = @($results | Where-Object { $_.IsDisabled }).Count
$oldCount         = @($results | Where-Object { $_.IsOld }).Count
$likelyEmptyCount = @($results | Where-Object { $_.IsLikelyEmpty }).Count
$wmiFilteredCount = @($results | Where-Object { -not [string]::IsNullOrWhiteSpace($_.WmiFilterName) }).Count

$cleanupCandidatesCount = @(
    $results | Where-Object {
        $_.IsUnlinked -or $_.IsDisabled -or $_.IsOld
    }
).Count

$highConfidenceCount = @(
    $results | Where-Object {
        $_.IsUnlinked -and $_.IsDisabled -and $_.IsOld
    }
).Count

$excludedText = ($ExcludedGpoNames -join "; ")

$guidLines = @()
$nameLines = @()
$quotedNameLines = @()

foreach ($c in $cleanupCandidates) {
    $guidLines += [string]$c.GpoId
    $nameLines += [string]$c.GpoName
    $quotedNameLines += ("'{0}'" -f ([string]$c.GpoName).Replace("'", "''"))
}

$cleanupGuidText = ($guidLines -join "`r`n")
$cleanupNameText = ($nameLines -join "`r`n")
$cleanupQuotedNamesText = ($quotedNameLines -join ",`r`n    ")

if ([string]::IsNullOrWhiteSpace($cleanupQuotedNamesText)) {
    $cleanupQuotedNamesText = "'<no candidates>'"
}

$backupOnlyScript = @"
Import-Module GroupPolicy -ErrorAction Stop

`$BackupRoot = "C:\Temp\GPO-Backups"
`$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
`$backupPath = Join-Path `$BackupRoot ("GPO_Cleanup_Backup_" + `$timestamp)

New-Item -ItemType Directory -Path `$backupPath -Force | Out-Null

`$gpoNames = @(
    $cleanupQuotedNamesText
)

foreach (`$name in `$gpoNames) {
    Write-Host ("Backing up: {0}" -f `$name) -ForegroundColor Yellow
    Backup-GPO -Name `$name -Path `$backupPath -Comment ("Pre-cleanup backup for " + `$name + " at " + (Get-Date)) -ErrorAction Stop | Out-Null
}

Write-Host ""
Write-Host "Backup completed: `$backupPath" -ForegroundColor Green
"@

$backupRemoveScript = @"
Import-Module GroupPolicy -ErrorAction Stop

param(
    [switch]`$WhatIf
)

`$BackupRoot = "C:\Temp\GPO-Backups"
`$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
`$backupPath = Join-Path `$BackupRoot ("GPO_Delete_Batch_" + `$timestamp)

New-Item -ItemType Directory -Path `$backupPath -Force | Out-Null

`$gpoNames = @(
    $cleanupQuotedNamesText
)

foreach (`$name in `$gpoNames) {
    Write-Host ("Processing: {0}" -f `$name) -ForegroundColor Yellow

    Backup-GPO -Name `$name -Path `$backupPath -Comment ("Pre-delete backup for " + `$name + " at " + (Get-Date)) -ErrorAction Stop | Out-Null
    Write-Host "  Backup OK" -ForegroundColor Green

    if (`$WhatIf) {
        Write-Host ("  WHATIF: Remove-GPO -Name {0}" -f `$name) -ForegroundColor Magenta
    }
    else {
        Remove-GPO -Name `$name -Confirm:`$false -ErrorAction Stop
        Write-Host "  Remove OK" -ForegroundColor Green
    }

    Write-Host ""
}

Write-Host ("Backups stored in: {0}" -f `$backupPath) -ForegroundColor Cyan
"@

$detailsJsBuilder = New-Object System.Text.StringBuilder
$null = $detailsJsBuilder.AppendLine("const gpoDetails = {")

foreach ($r in $results) {
    $safeGpoNameForPs = $r.GpoName.Replace("'", "''")

    $singleBackupScript = @"
Import-Module GroupPolicy -ErrorAction Stop

`$BackupRoot = "C:\Temp\GPO-Backups"
`$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
`$backupPath = Join-Path `$BackupRoot ("GPO_Single_Backup_" + `$timestamp)

New-Item -ItemType Directory -Path `$backupPath -Force | Out-Null

Backup-GPO -Name '$safeGpoNameForPs' -Path `$backupPath -Comment ("Manual backup for $safeGpoNameForPs at " + (Get-Date)) -ErrorAction Stop | Out-Null

Write-Host ("Backup completed: {0}" -f `$backupPath) -ForegroundColor Green
"@

    $singleBackupRemoveScript = @"
Import-Module GroupPolicy -ErrorAction Stop

param(
    [switch]`$WhatIf
)

`$BackupRoot = "C:\Temp\GPO-Backups"
`$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
`$backupPath = Join-Path `$BackupRoot ("GPO_Single_Delete_" + `$timestamp)

New-Item -ItemType Directory -Path `$backupPath -Force | Out-Null

Backup-GPO -Name '$safeGpoNameForPs' -Path `$backupPath -Comment ("Pre-delete backup for $safeGpoNameForPs at " + (Get-Date)) -ErrorAction Stop | Out-Null
Write-Host "Backup OK" -ForegroundColor Green

if (`$WhatIf) {
    Write-Host "WHATIF: Remove-GPO -Name '$safeGpoNameForPs'" -ForegroundColor Magenta
}
else {
    Remove-GPO -Name '$safeGpoNameForPs' -Confirm:`$false -ErrorAction Stop
    Write-Host "Remove OK" -ForegroundColor Green
}

Write-Host ("Backups stored in: {0}" -f `$backupPath) -ForegroundColor Cyan
"@

    $singleReportScript = @"
Import-Module GroupPolicy -ErrorAction Stop

Get-GPO -Guid '$($r.GpoId)' | Format-List *
Get-GPOReport -Guid '$($r.GpoId)' -ReportType Html -Path ("C:\Temp\GPO_$($r.GpoId)_Report.html")
"@

    $detailJson = @"
'$($r.GpoId)': {
    gpoName: '$([string](Convert-ToJsStringLiteral $r.GpoName))',
    gpoId: '$([string](Convert-ToJsStringLiteral $r.GpoId))',
    status: '$([string](Convert-ToJsStringLiteral $r.Status))',
    owner: '$([string](Convert-ToJsStringLiteral $r.Owner))',
    created: '$([string](Convert-ToJsStringLiteral $r.Created))',
    modified: '$([string](Convert-ToJsStringLiteral $r.Modified))',
    linkCount: '$([string](Convert-ToJsStringLiteral ([string]$r.LinkCount)))',
    linkTargets: '$([string](Convert-ToJsStringLiteral $r.LinkTargets))',
    isUnlinked: '$([string](Convert-ToJsStringLiteral ([string]$r.IsUnlinked)))',
    isDisabled: '$([string](Convert-ToJsStringLiteral ([string]$r.IsDisabled)))',
    isOld: '$([string](Convert-ToJsStringLiteral ([string]$r.IsOld)))',
    isLikelyEmpty: '$([string](Convert-ToJsStringLiteral ([string]$r.IsLikelyEmpty)))',
    computerEnabled: '$([string](Convert-ToJsStringLiteral $r.ComputerEnabled))',
    userEnabled: '$([string](Convert-ToJsStringLiteral $r.UserEnabled))',
    securityFiltering: '$([string](Convert-ToJsStringLiteral $r.SecurityFiltering))',
    wmiFilterName: '$([string](Convert-ToJsStringLiteral $r.WmiFilterName))',
    wmiFilterQuery: '$([string](Convert-ToJsStringLiteral $r.WmiFilterQuery))',
    comment: '$([string](Convert-ToJsStringLiteral $r.Comment))',
    cleanupHint: '$([string](Convert-ToJsStringLiteral $r.CleanupHint))',
    scriptReport: '$([string](Convert-ToJsStringLiteral $singleReportScript))',
    scriptBackup: '$([string](Convert-ToJsStringLiteral $singleBackupScript))',
    scriptBackupRemove: '$([string](Convert-ToJsStringLiteral $singleBackupRemoveScript))'
},
"@
    $null = $detailsJsBuilder.AppendLine($detailJson)
}

$null = $detailsJsBuilder.AppendLine("};")
$detailsJs = $detailsJsBuilder.ToString()

$rowBuilder = New-Object System.Text.StringBuilder

$index = 0
foreach ($r in $results) {
    $index++

    $statusBadge  = Get-HtmlBadge -Text $r.Status -ClassName (Get-StatusBadgeClass -Status $r.Status)
    $cleanupBadge = Get-HtmlBadge -Text $r.CleanupHint -ClassName (Get-CleanupBadgeClass -CleanupHint $r.CleanupHint)

    $linkCountBadge = if ([int]$r.LinkCount -gt 0) {
        Get-HtmlBadge -Text ([string]$r.LinkCount) -ClassName "badge-green"
    } else {
        Get-HtmlBadge -Text ([string]$r.LinkCount) -ClassName "badge-red"
    }

    $wmiBadge = if (-not [string]::IsNullOrWhiteSpace($r.WmiFilterName)) {
        Get-HtmlBadge -Text $r.WmiFilterName -ClassName "badge-blue"
    } else {
        Get-HtmlBadge -Text "None" -ClassName "badge-gray"
    }

    $actionButtons = @"
<div class="action-cell">
    <button type="button" class="btn-small" onclick="openDetailModal('$(New-SafeHtml $r.GpoId)')">Details</button>
</div>
"@

    $cleanupAttr  = if ($r.IsUnlinked -or $r.IsDisabled -or $r.IsOld) { "true" } else { "false" }
    $highRiskAttr = if ($r.IsUnlinked -and $r.IsDisabled -and $r.IsOld) { "true" } else { "false" }

    $null = $rowBuilder.AppendLine(@"
<tr
    data-gpoid="$(New-SafeHtml $r.GpoId)"
    data-gponame="$(New-SafeHtml $r.GpoName)"
    data-status="$(New-SafeHtml $r.Status)"
    data-linkcount="$(New-SafeHtml ([string]$r.LinkCount))"
    data-linktargets="$(New-SafeHtml $r.LinkTargets)"
    data-unlinked="$(($r.IsUnlinked).ToString().ToLowerInvariant())"
    data-disabled="$(($r.IsDisabled).ToString().ToLowerInvariant())"
    data-old="$(($r.IsOld).ToString().ToLowerInvariant())"
    data-empty="$(($r.IsLikelyEmpty).ToString().ToLowerInvariant())"
    data-securityfiltering="$(New-SafeHtml $r.SecurityFiltering)"
    data-wmi="$(if([string]::IsNullOrWhiteSpace($r.WmiFilterName)){'false'}else{'true'})"
    data-wmifiltername="$(New-SafeHtml $r.WmiFilterName)"
    data-owner="$(New-SafeHtml $r.Owner)"
    data-modified="$(New-SafeHtml $r.Modified)"
    data-comment="$(New-SafeHtml $r.Comment)"
    data-cleanuphint="$(New-SafeHtml $r.CleanupHint)"
    data-cleanup="$cleanupAttr"
    data-highrisk="$highRiskAttr"
>
    <td data-sort="$index">$index</td>
    <td data-sort="$(New-SafeHtml $r.GpoName)">$(New-SafeHtml $r.GpoName)</td>
    <td data-sort="$(New-SafeHtml $r.GpoId)"><code>$(New-SafeHtml $r.GpoId)</code></td>
    <td data-sort="$(New-SafeHtml $r.Status)">$statusBadge</td>
    <td data-sort="$(New-SafeHtml ([string]$r.LinkCount))">$linkCountBadge</td>
    <td data-sort="$(New-SafeHtml $r.LinkTargets)">$(New-SafeHtml $r.LinkTargets)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsUnlinked))">$(Get-BoolText $r.IsUnlinked)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsDisabled))">$(Get-BoolText $r.IsDisabled)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsOld))">$(Get-BoolText $r.IsOld)</td>
    <td data-sort="$(New-SafeHtml ([string]$r.IsLikelyEmpty))">$(Get-BoolText $r.IsLikelyEmpty)</td>
    <td data-sort="$(New-SafeHtml $r.SecurityFiltering)">$(New-SafeHtml $r.SecurityFiltering)</td>
    <td data-sort="$(New-SafeHtml $r.WmiFilterName)">$wmiBadge</td>
    <td data-sort="$(New-SafeHtml $r.Owner)">$(New-SafeHtml $r.Owner)</td>
    <td data-sort="$(New-SafeHtml $r.Modified)">$(New-SafeHtml $r.Modified)</td>
    <td data-sort="$(New-SafeHtml $r.Comment)">$(New-SafeHtml $r.Comment)</td>
    <td data-sort="$(New-SafeHtml $r.CleanupHint)">$cleanupBadge</td>
    <td class="no-wrap" data-sort="$(New-SafeHtml $r.GpoName)">$actionButtons</td>
</tr>
"@)
}

$topFindingsHtml = @(
    (New-FindingBlock -Count $highConfidenceCount    -FilterName "highconfidence" -BadgeClass "badge-red"    -Label "High Confidence")
    (New-FindingBlock -Count $cleanupCandidatesCount -FilterName "cleanup"        -BadgeClass "badge-yellow" -Label "Cleanup Candidates")
    (New-FindingBlock -Count $likelyEmptyCount       -FilterName "empty"          -BadgeClass "badge-yellow" -Label "Likely Empty")
    (New-FindingBlock -Count $disabledCount          -FilterName "disabled"       -BadgeClass "badge-gray"   -Label "Disabled")
    (New-FindingBlock -Count $unlinkedCount          -FilterName "unlinked"       -BadgeClass "badge-yellow" -Label "Unlinked")
    (New-FindingBlock -Count $linkedCount            -FilterName "linked"         -BadgeClass "badge-green"  -Label "Linked")
    (New-FindingBlock -Count $wmiFilteredCount       -FilterName "wmi"            -BadgeClass "badge-blue"   -Label "WMI Filtered")
) -join "`r`n"

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GPO Audit Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:#f7f9fc;color:#1f2937}
h1,h2,h3{margin-bottom:10px}
.meta,.summary,.section,.toolbar,.notes{background:#fff;border:1px solid #dbe2ea;border-radius:10px;padding:16px;margin-bottom:18px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.summary h2,.section h2{font-size:20px;margin-bottom:8px}
.summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
@media (max-width:1400px){.summary-grid{grid-template-columns:repeat(3,1fr)}}
@media (max-width:1000px){.summary-grid{grid-template-columns:repeat(2,1fr)}}
@media (max-width:640px){.summary-grid{grid-template-columns:1fr}}
.card{background:#f9fbfd;border:1px solid #dbe2ea;border-radius:10px;padding:14px 16px;cursor:pointer;transition:.15s ease;min-height:84px}
.card:hover{background:#eef4fa;border-color:#bfd3e6}
.card.active{background:#dbeafe;border-color:#60a5fa}
.card .label{font-size:13px;color:#6b7280;text-transform:uppercase}
.card .value{font-size:28px;font-weight:700;margin-top:6px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.toolbar button,.toolbar select,.toolbar input{border:1px solid #cbd5e1;background:#f8fafc;border-radius:8px;padding:8px 12px;font:inherit}
.toolbar button{cursor:pointer}
.toolbar button:hover{background:#eef2f7}
table{width:max-content;min-width:100%;border-collapse:collapse;background:#fff;border:1px solid #dbe2ea}
th,td{border:1px solid #e5e7eb;padding:8px 10px;font-size:13px;white-space:nowrap}
th{background:#eef4fa;position:sticky;top:0;z-index:2;cursor:pointer}
th.no-sort{cursor:default}
tr:nth-child(even) td{background:#fafcff}
tr[data-cleanup="true"] td{background:#fff7ed}
tr[data-disabled="true"] td{background:#f3f4f6;color:#4b5563}
tr[data-highrisk="true"] td{background:#fee2e2;font-weight:600}
.hidden-row{display:none !important}
th:first-child,td:first-child{position:sticky;left:0;z-index:3;min-width:52px;width:52px;text-align:center;box-shadow:2px 0 0 #dbe2ea}
th:first-child{z-index:5;background:#eef4fa}
th:nth-child(2),td:nth-child(2){position:sticky;left:52px;z-index:3;min-width:220px;max-width:220px;box-shadow:2px 0 0 #dbe2ea}
th:nth-child(2){z-index:5;background:#eef4fa}
tr:nth-child(even) td:nth-child(1),tr:nth-child(even) td:nth-child(2){background:#fafcff}
tr[data-cleanup="true"] td:nth-child(1),tr[data-cleanup="true"] td:nth-child(2){background:#fff7ed}
tr[data-disabled="true"] td:nth-child(1),tr[data-disabled="true"] td:nth-child(2){background:#f3f4f6;color:#4b5563}
tr[data-highrisk="true"] td:nth-child(1),tr[data-highrisk="true"] td:nth-child(2){background:#fee2e2}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;margin:2px 2px 2px 0}
.badge-green{background:#dcfce7;color:#166534}
.badge-yellow{background:#fef3c7;color:#92400e}
.badge-red{background:#fee2e2;color:#991b1b}
.badge-gray{background:#e5e7eb;color:#374151}
.badge-purple{background:#ede9fe;color:#6d28d9}
.badge-blue{background:#dbeafe;color:#1d4ed8}
.muted{color:#6b7280;font-size:13px}
.summary ul{margin:0;padding-left:18px}
.summary li{margin-bottom:8px;font-weight:500}
.finding-link,.finding-static{display:flex;align-items:center;gap:10px;width:100%;box-sizing:border-box}
.finding-link{text-align:left;border:1px solid #cbd5e1;background:#f8fafc;color:#1f2937;border-radius:8px;padding:10px 12px;font:inherit;font-weight:600;cursor:pointer;transition:.15s ease}
.finding-link:hover{background:#dbeafe;border-color:#60a5fa}
.finding-link.active{background:#dbeafe;border-color:#60a5fa}
.finding-static{padding:10px 12px;border:1px solid #dbe2ea;background:#f8fafc;border-radius:8px}
.finding-badge{flex:0 0 auto;margin-right:0;margin-bottom:0}
.finding-text{flex:1 1 auto}
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
.result-line{margin-top:10px}
.no-wrap{white-space:nowrap}
.detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-bottom:12px}
@media (max-width:900px){.detail-grid{grid-template-columns:1fr}}
.detail-item{border:1px solid #dbe2ea;border-radius:10px;padding:12px;background:#f9fbfd}
.detail-item .name{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.03em;margin-bottom:6px}
.detail-item .data{font-weight:600;white-space:pre-wrap;word-break:break-word}
.codebox{font-family:Consolas,Menlo,monospace}
.table-wrap{position:relative;overflow-x:auto;border:1px solid #dbe2ea;border-radius:10px;background:#fff;scrollbar-color:#cbd5e1 #f1f5f9;scrollbar-width:thin}
.table-wrap::-webkit-scrollbar{height:10px}
.table-wrap::-webkit-scrollbar-track{background:#f1f5f9}
.table-wrap::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:8px}
.table-wrap::-webkit-scrollbar-thumb:hover{background:#94a3b8}
.table-wrap::after{content:"";position:absolute;top:0;right:0;width:30px;height:calc(100% - 12px);pointer-events:none;background:linear-gradient(to left, rgba(255,255,255,0.9), transparent)}
</style>
</head>
<body>

<h1>GPO Audit Report</h1>

<div class="meta">
    <h2>Environment</h2>
    <div class="summary-grid">
        <div class="card" style="cursor:default">
            <div class="label">Domain</div>
            <div class="value" style="font-size:22px">$(New-SafeHtml $domainInfo.DNSRoot)</div>
        </div>
        <div class="card" style="cursor:default">
            <div class="label">Forest</div>
            <div class="value" style="font-size:22px">$(New-SafeHtml $forestInfo.Name)</div>
        </div>
        <div class="card" style="cursor:default">
            <div class="label">Generated</div>
            <div class="value" style="font-size:18px">$(New-SafeHtml ([string](Get-Date)))</div>
        </div>
        <div class="card" style="cursor:default">
            <div class="label">Old GPO Threshold</div>
            <div class="value" style="font-size:22px">$(New-SafeHtml "$OldGpoYears year(s)")</div>
        </div>
    </div>
    <div class="muted result-line"><strong>Excluded GPOs:</strong> $(New-SafeHtml $excludedText)</div>
</div>

<div class="summary">
    <h2>Top Findings</h2>
    <p class="muted">Klikkaa löytöä suodattaaksesi taulukon. Nollat jäävät staattisiksi, koska tyhjä nappi on yhtä hyödyllinen kuin rikkinäinen kahviautomaatti.</p>
    <div class="summary-grid">
        $topFindingsHtml
    </div>
</div>

<div class="summary">
    <h2>Summary</h2>
    <p class="muted">Klikkaa korttia suodattaaksesi taulukon.</p>
    <div class="summary-grid" id="summaryCards">
        <div class="card active" data-filter="all">
            <div class="label">All GPOs</div>
            <div class="value">$totalCount</div>
        </div>
        <div class="card" data-filter="cleanup">
            <div class="label">Cleanup Candidates</div>
            <div class="value">$cleanupCandidatesCount</div>
        </div>
        <div class="card" data-filter="highconfidence">
            <div class="label">High Confidence</div>
            <div class="value">$highConfidenceCount</div>
        </div>
        <div class="card" data-filter="linked">
            <div class="label">Linked</div>
            <div class="value">$linkedCount</div>
        </div>
        <div class="card" data-filter="unlinked">
            <div class="label">Unlinked</div>
            <div class="value">$unlinkedCount</div>
        </div>
        <div class="card" data-filter="disabled">
            <div class="label">Disabled</div>
            <div class="value">$disabledCount</div>
        </div>
        <div class="card" data-filter="old">
            <div class="label">Old</div>
            <div class="value">$oldCount</div>
        </div>
        <div class="card" data-filter="empty">
            <div class="label">Likely Empty</div>
            <div class="value">$likelyEmptyCount</div>
        </div>
        <div class="card" data-filter="wmi">
            <div class="label">WMI Filtered</div>
            <div class="value">$wmiFilteredCount</div>
        </div>
    </div>
</div>

<div class="section">
    <h2>Toolbar</h2>
    <div class="toolbar">
        <input type="search" id="searchBox" placeholder="Search GPO name, GUID, links, owner, comment, WMI filter...">

        <select id="quickFilter">
            <option value="all">All</option>
            <option value="cleanup">Cleanup Candidates</option>
            <option value="highconfidence">High Confidence</option>
            <option value="linked">Linked</option>
            <option value="unlinked">Unlinked</option>
            <option value="disabled">Disabled</option>
            <option value="old">Old</option>
            <option value="empty">Likely Empty</option>
            <option value="wmi">WMI Filtered</option>
        </select>

        <select id="rowsPerPage">
            <option value="10"$(if($RowsPerPage -eq 10){' selected'}else{''})>10</option>
            <option value="25"$(if($RowsPerPage -eq 25){' selected'}else{''})>25</option>
            <option value="50"$(if($RowsPerPage -eq 50){' selected'}else{''})>50</option>
            <option value="100"$(if($RowsPerPage -eq 100){' selected'}else{''})>100</option>
            <option value="999999">All</option>
        </select>

        <button type="button" onclick="resetAll()">Reset</button>
        <button type="button" onclick="copyVisibleNames()">Copy visible names</button>
        <button type="button" onclick="copyVisibleGuids()">Copy visible GUIDs</button>
        <button type="button" onclick="exportVisibleCsv()">Export visible rows CSV</button>
        <button type="button" onclick="openCleanupModal()">Cleanup modal</button>
    </div>

    <div class="muted result-line" id="resultInfo"></div>
    <div class="muted" id="pageInfo"></div>
</div>

<div class="notes">
    <h2>Interpretation Notes</h2>
    <ul>
        <li><strong>Excluded GPOs</strong> are not included in this report at all.</li>
        <li><strong>Unlinked</strong> is calculated from AD <code>gPLink</code> values on Domain, OU and Site objects.</li>
        <li><strong>Likely Empty</strong> is based on actual <code>ExtensionData</code> XML content.</li>
        <li><strong>Cleanup Candidates</strong> includes GPOs that are Unlinked, Disabled or Old.</li>
        <li><strong>High Confidence</strong> means Unlinked + Disabled + Old.</li>
        <li><strong>Visible rows tools</strong> now use only the current page.</li>
        <li><strong>Details</strong> opens per-GPO metadata plus copy-paste snippets for report, backup and backup+remove.</li>
    </ul>
</div>

<div class="section">
    <h2>Detailed Results</h2>
    <div class="table-wrap">
        <table id="gpoTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">#</th>
                    <th onclick="sortTable(1)">GPO Name</th>
                    <th onclick="sortTable(2)">GUID</th>
                    <th onclick="sortTable(3)">Status</th>
                    <th onclick="sortTable(4)">Links</th>
                    <th onclick="sortTable(5)">Link Targets</th>
                    <th onclick="sortTable(6)">Unlinked</th>
                    <th onclick="sortTable(7)">Disabled</th>
                    <th onclick="sortTable(8)">Old</th>
                    <th onclick="sortTable(9)">Likely Empty</th>
                    <th onclick="sortTable(10)">Security Filtering</th>
                    <th onclick="sortTable(11)">WMI Filter</th>
                    <th onclick="sortTable(12)">Owner</th>
                    <th onclick="sortTable(13)">Modified</th>
                    <th onclick="sortTable(14)">Comment</th>
                    <th onclick="sortTable(15)">Cleanup Hint</th>
                    <th class="no-sort">Actions</th>
                </tr>
            </thead>
            <tbody>
                $($rowBuilder.ToString())
            </tbody>
        </table>
    </div>
    <div class="bulk-toolbar">
        <div class="muted">Pagination</div>
        <div id="pagination" class="toolbar"></div>
    </div>
</div>

<div class="modal-backdrop" id="cleanupModalBackdrop">
    <div class="modal">
        <h2>Cleanup modal</h2>

        <div class="warn-box">
            Batch snippets for backup and delete candidates. Start with backup. Katastrofin jälkeinen “rollback-ajatus” ei ole menetelmä.
        </div>

        <div class="modal-grid">
            <div>
                <label for="cleanupNames">Candidate names</label>
                <textarea id="cleanupNames" readonly class="codebox">$(New-SafeHtml $cleanupNameText)</textarea>
            </div>

            <div>
                <label for="cleanupGuids">Candidate GUIDs</label>
                <textarea id="cleanupGuids" readonly class="codebox">$(New-SafeHtml $cleanupGuidText)</textarea>
            </div>

            <div>
                <label for="backupOnlyScript">Backup only script</label>
                <textarea id="backupOnlyScript" readonly class="codebox">$(New-SafeHtml $backupOnlyScript)</textarea>
            </div>

            <div>
                <label for="backupRemoveScript">Backup + Remove script</label>
                <textarea id="backupRemoveScript" readonly class="codebox">$(New-SafeHtml $backupRemoveScript)</textarea>
            </div>
        </div>

        <div class="modal-actions">
            <button type="button" onclick="copyFromTextarea('cleanupNames')">Copy names</button>
            <button type="button" onclick="copyFromTextarea('cleanupGuids')">Copy GUIDs</button>
            <button type="button" onclick="copyFromTextarea('backupOnlyScript')">Copy backup script</button>
            <button type="button" onclick="copyFromTextarea('backupRemoveScript')">Copy backup+remove script</button>
            <button type="button" onclick="closeCleanupModal()">Close</button>
        </div>
    </div>
</div>

<div class="modal-backdrop" id="detailModalBackdrop">
    <div class="modal">
        <h2 id="detailTitle">GPO details</h2>
        <div class="muted" id="detailSubTitle" style="margin-bottom:12px;">Review metadata and copy-paste snippets.</div>

        <div class="detail-grid" id="detailGrid"></div>

        <div class="helper-grid">
            <div>
                <label for="detailScriptReport">Review / export report script</label>
                <textarea id="detailScriptReport" readonly class="codebox"></textarea>
            </div>

            <div>
                <label for="detailScriptBackup">Single GPO backup script</label>
                <textarea id="detailScriptBackup" readonly class="codebox"></textarea>
            </div>
        </div>

        <div style="margin-top:12px;">
            <label for="detailScriptBackupRemove">Single GPO backup + remove script</label>
            <textarea id="detailScriptBackupRemove" readonly class="codebox"></textarea>
        </div>

        <div class="modal-actions">
            <button type="button" onclick="copyFromTextarea('detailScriptReport')">Copy report script</button>
            <button type="button" onclick="copyFromTextarea('detailScriptBackup')">Copy backup script</button>
            <button type="button" onclick="copyFromTextarea('detailScriptBackupRemove')">Copy backup+remove script</button>
            <button type="button" onclick="closeDetailModal()">Close</button>
        </div>
    </div>
</div>

<script>
$detailsJs

let currentFilter = "all";
let currentSortColumn = -1;
let currentSortAsc = true;
let currentPage = 1;

function getAllRows() {
    return Array.from(document.querySelectorAll("#gpoTable tbody tr"));
}

function getSearchText() {
    const el = document.getElementById("searchBox");
    return (el ? el.value : "").trim().toLowerCase();
}

function getRowsPerPage() {
    const el = document.getElementById("rowsPerPage");
    const value = el ? parseInt(el.value, 10) : 10;
    return Number.isFinite(value) ? value : 10;
}

function getFilterLabel(filterName) {
    const map = {
        all: "All GPOs",
        cleanup: "Cleanup Candidates",
        highconfidence: "High Confidence",
        linked: "Linked",
        unlinked: "Unlinked",
        disabled: "Disabled",
        old: "Old",
        empty: "Likely Empty",
        wmi: "WMI Filtered"
    };
    return map[filterName] || filterName;
}

function matchesFilter(row, filterName) {
    switch (filterName) {
        case "all": return true;
        case "cleanup": return row.dataset.cleanup === "true";
        case "highconfidence": return row.dataset.highrisk === "true";
        case "linked": return row.dataset.unlinked === "false";
        case "unlinked": return row.dataset.unlinked === "true";
        case "disabled": return row.dataset.disabled === "true";
        case "old": return row.dataset.old === "true";
        case "empty": return row.dataset.empty === "true";
        case "wmi": return row.dataset.wmi === "true";
        default: return true;
    }
}

function matchesSearch(row, searchText) {
    if (!searchText) return true;
    return row.textContent.toLowerCase().includes(searchText);
}

function getMatchedRows() {
    const rows = getAllRows();
    const searchText = getSearchText();
    return rows.filter(row => matchesFilter(row, currentFilter) && matchesSearch(row, searchText));
}

function getPagedRows(matchedRows) {
    const rowsPerPage = getRowsPerPage();
    if (rowsPerPage >= 999999) return matchedRows;

    const start = (currentPage - 1) * rowsPerPage;
    const end = start + rowsPerPage;
    return matchedRows.slice(start, end);
}

function getCurrentPageRows() {
    const matchedRows = getMatchedRows();
    return getPagedRows(matchedRows);
}

function updateActiveStates() {
    document.querySelectorAll("#summaryCards .card").forEach(card => {
        card.classList.toggle("active", card.dataset.filter === currentFilter);
    });

    document.querySelectorAll(".finding-link").forEach(link => {
        link.classList.toggle("active", link.dataset.filter === currentFilter);
    });

    const quickFilter = document.getElementById("quickFilter");
    if (quickFilter) {
        quickFilter.value = currentFilter;
    }
}

function renderTable() {
    const rows = getAllRows();
    const matchedRows = getMatchedRows();
    const rowsPerPage = getRowsPerPage();

    let totalPages = 1;
    if (rowsPerPage < 999999) {
        totalPages = Math.max(1, Math.ceil(matchedRows.length / rowsPerPage));
    }

    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;

    const pagedRows = getPagedRows(matchedRows);

    rows.forEach(row => row.classList.add("hidden-row"));
    pagedRows.forEach(row => row.classList.remove("hidden-row"));

    updateActiveStates();

    const resultInfo = document.getElementById("resultInfo");
    if (resultInfo) {
        resultInfo.textContent =
            "Showing " + pagedRows.length + " of " + matchedRows.length + " matching rows (" + rows.length + " total). Filter: " + getFilterLabel(currentFilter);
    }

    const pageInfo = document.getElementById("pageInfo");
    if (pageInfo) {
        pageInfo.textContent = "Page " + currentPage + " / " + totalPages;
    }

    renderPagination(totalPages);
}

function renderPagination(totalPages) {
    const container = document.getElementById("pagination");
    if (!container) return;

    container.innerHTML = "";

    function addBtn(label, page, disabled, active) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = label;
        btn.disabled = !!disabled;
        if (active) btn.classList.add("active");
        btn.addEventListener("click", function() {
            currentPage = page;
            renderTable();
        });
        container.appendChild(btn);
    }

    addBtn("Prev", Math.max(1, currentPage - 1), currentPage === 1, false);

    const maxButtons = 7;
    let start = Math.max(1, currentPage - 3);
    let end = Math.min(totalPages, start + maxButtons - 1);

    if ((end - start + 1) < maxButtons) {
        start = Math.max(1, end - maxButtons + 1);
    }

    for (let i = start; i <= end; i++) {
        addBtn(String(i), i, false, i === currentPage);
    }

    addBtn("Next", Math.min(totalPages, currentPage + 1), currentPage === totalPages, false);
}

function applyFilter(filterName) {
    currentFilter = filterName;
    currentPage = 1;
    renderTable();
}

function resetAll() {
    const searchBox = document.getElementById("searchBox");
    const rowsPerPage = document.getElementById("rowsPerPage");

    if (searchBox) searchBox.value = "";
    if (rowsPerPage) rowsPerPage.value = "$(New-SafeHtml ([string]$RowsPerPage))";

    currentFilter = "all";
    currentPage = 1;
    renderTable();
}

document.querySelectorAll("#summaryCards .card").forEach(card => {
    card.addEventListener("click", function() {
        applyFilter(this.dataset.filter);
    });
});

document.querySelectorAll(".finding-link").forEach(link => {
    link.addEventListener("click", function() {
        applyFilter(this.dataset.filter);
    });
});

const quickFilterEl = document.getElementById("quickFilter");
if (quickFilterEl) {
    quickFilterEl.addEventListener("change", function() {
        applyFilter(this.value);
    });
}

const searchBoxEl = document.getElementById("searchBox");
if (searchBoxEl) {
    searchBoxEl.addEventListener("input", function() {
        currentPage = 1;
        renderTable();
    });
}

const rowsPerPageEl = document.getElementById("rowsPerPage");
if (rowsPerPageEl) {
    rowsPerPageEl.addEventListener("change", function() {
        currentPage = 1;
        renderTable();
    });
}

function getCellValue(row, columnIndex) {
    const cell = row.children[columnIndex];
    if (!cell) return "";
    return (cell.getAttribute("data-sort") || cell.textContent || "").trim();
}

function parseSortableValue(value) {
    const lower = String(value).toLowerCase();

    if (lower === "yes" || lower === "true") return 1;
    if (lower === "no" || lower === "false") return 0;

    const numeric = Number(value);
    if (!isNaN(numeric) && value !== "") return numeric;

    const time = Date.parse(value);
    if (!isNaN(time)) return time;

    return lower;
}

function sortTable(columnIndex) {
    const th = document.querySelectorAll("#gpoTable thead th")[columnIndex];
    if (th && th.classList.contains("no-sort")) {
        return;
    }

    const tbody = document.querySelector("#gpoTable tbody");
    const rows = getAllRows();

    if (currentSortColumn === columnIndex) {
        currentSortAsc = !currentSortAsc;
    } else {
        currentSortColumn = columnIndex;
        currentSortAsc = true;
    }

    rows.sort((a, b) => {
        const aVal = parseSortableValue(getCellValue(a, columnIndex));
        const bVal = parseSortableValue(getCellValue(b, columnIndex));

        if (aVal < bVal) return currentSortAsc ? -1 : 1;
        if (aVal > bVal) return currentSortAsc ? 1 : -1;
        return 0;
    });

    rows.forEach(row => tbody.appendChild(row));
    currentPage = 1;
    renderTable();
}

function getFilteredExportRows() {
    return getCurrentPageRows();
}

function rowsToVisibleNames(rows) {
    return rows.map(row => row.dataset.gponame || "").filter(Boolean);
}

function rowsToVisibleGuids(rows) {
    return rows.map(row => row.dataset.gpoid || "").filter(Boolean);
}

function copyTextToClipboard(text) {
    const temp = document.createElement("textarea");
    temp.value = text;
    document.body.appendChild(temp);
    temp.focus();
    temp.select();
    temp.setSelectionRange(0, 999999);

    try {
        document.execCommand("copy");
    } catch (e) {}

    document.body.removeChild(temp);
}

function copyVisibleNames() {
    const rows = getFilteredExportRows();
    const names = rowsToVisibleNames(rows).join("\r\n");
    copyTextToClipboard(names);
}

function copyVisibleGuids() {
    const rows = getFilteredExportRows();
    const guids = rowsToVisibleGuids(rows).join("\r\n");
    copyTextToClipboard(guids);
}

function csvEscape(value) {
    const s = String(value ?? "");
    if (/[",\r\n]/.test(s)) {
        return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
}

function exportVisibleCsv() {
    const rows = getFilteredExportRows();

    const headers = [
        "#","GPO Name","GUID","Status","Links","Link Targets","Unlinked","Disabled","Old","Likely Empty",
        "Security Filtering","WMI Filter","Owner","Modified","Comment","Cleanup Hint"
    ];

    const lines = [];
    lines.push(headers.map(csvEscape).join(","));

    rows.forEach((row, idx) => {
        const values = [
            row.children[0]?.textContent.trim() || String(idx + 1),
            row.dataset.gponame || "",
            row.dataset.gpoid || "",
            row.dataset.status || "",
            row.dataset.linkcount || "",
            row.dataset.linktargets || "",
            row.dataset.unlinked || "",
            row.dataset.disabled || "",
            row.dataset.old || "",
            row.dataset.empty || "",
            row.dataset.securityfiltering || "",
            row.dataset.wmifiltername || "",
            row.dataset.owner || "",
            row.dataset.modified || "",
            row.dataset.comment || "",
            row.dataset.cleanuphint || ""
        ];
        lines.push(values.map(csvEscape).join(","));
    });

    const csvContent = "\uFEFF" + lines.join("\r\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);

    const now = new Date();
    const pad = n => String(n).padStart(2, "0");
    const stamp =
        now.getFullYear().toString() +
        pad(now.getMonth() + 1) +
        pad(now.getDate()) + "_" +
        pad(now.getHours()) +
        pad(now.getMinutes()) +
        pad(now.getSeconds());

    const filename = "GPO_Audit_VisibleRows_" + stamp + ".csv";

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function openCleanupModal() {
    document.getElementById("cleanupModalBackdrop").style.display = "flex";
}

function closeCleanupModal() {
    document.getElementById("cleanupModalBackdrop").style.display = "none";
}

function makeDetailItem(name, value) {
    const div = document.createElement("div");
    div.className = "detail-item";
    div.innerHTML =
        '<div class="name">' + escapeHtml(name) + '</div>' +
        '<div class="data">' + escapeHtml(value || "") + '</div>';
    return div;
}

function openDetailModal(gpoId) {
    const item = gpoDetails[gpoId];
    if (!item) return;

    document.getElementById("detailTitle").textContent = item.gpoName;
    document.getElementById("detailSubTitle").textContent = "GUID: " + item.gpoId;

    const grid = document.getElementById("detailGrid");
    grid.innerHTML = "";

    [
        ["Status", item.status],
        ["Owner", item.owner],
        ["Created", item.created],
        ["Modified", item.modified],
        ["Link Count", item.linkCount],
        ["Link Targets", item.linkTargets],
        ["Unlinked", item.isUnlinked],
        ["Disabled", item.isDisabled],
        ["Old", item.isOld],
        ["Likely Empty", item.isLikelyEmpty],
        ["Computer Enabled", item.computerEnabled],
        ["User Enabled", item.userEnabled],
        ["Security Filtering", item.securityFiltering],
        ["WMI Filter Name", item.wmiFilterName],
        ["WMI Filter Query", item.wmiFilterQuery],
        ["Comment", item.comment],
        ["Cleanup Hint", item.cleanupHint]
    ].forEach(pair => grid.appendChild(makeDetailItem(pair[0], pair[1])));

    document.getElementById("detailScriptReport").value = item.scriptReport || "";
    document.getElementById("detailScriptBackup").value = item.scriptBackup || "";
    document.getElementById("detailScriptBackupRemove").value = item.scriptBackupRemove || "";

    document.getElementById("detailModalBackdrop").style.display = "flex";
}

function closeDetailModal() {
    document.getElementById("detailModalBackdrop").style.display = "none";
}

function copyFromTextarea(id) {
    const el = document.getElementById(id);
    el.focus();
    el.select();
    el.setSelectionRange(0, 999999);

    try {
        document.execCommand("copy");
    } catch (e) {}
}

function escapeHtml(value) {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

document.getElementById("cleanupModalBackdrop").addEventListener("click", function(e) {
    if (e.target === this) closeCleanupModal();
});

document.getElementById("detailModalBackdrop").addEventListener("click", function(e) {
    if (e.target === this) closeDetailModal();
});

document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") {
        closeCleanupModal();
        closeDetailModal();
    }
});

renderTable();
</script>
</body>
</html>
"@

Set-Content -Path $htmlPath -Value $html -Encoding UTF8

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "HTML: $htmlPath"
Write-Host ""
Write-Host "Excluded GPOs:" -ForegroundColor Cyan
$ExcludedGpoNames | ForEach-Object { Write-Host (" - {0}" -f $_) }
Write-Host ""
Write-Host "This was a read-only audit. No changes were made." -ForegroundColor Yellow
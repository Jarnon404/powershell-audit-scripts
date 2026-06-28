<#
.SYNOPSIS
    Intune Windows Apps Assignment Audit.

.DESCRIPTION
    Auditoi Intunen Windows-sovellusten assignmentit, kohderyhmät, exclude-ryhmät ja assignment filterit.

.REQUIREMENTS
    - Microsoft Graph PowerShell -moduulit ja Intune-sovellustietojen lukuoikeudet

.OUTPUTS
    - CSV/HTML-raportti sovellusmäärityksistä

.EXAMPLE
    .\Get-IntuneWindowsAppAssignmentReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Get-IntuneWindowsAppAssignmentReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

<#
.SYNOPSIS
    Intune Windows Apps Assignment Audit

.DESCRIPTION
    READ-ONLY audit:
    - Hakee Intunen Windows-sovellukset
    - Hakee sovellusten assignmentit
    - Tunnistaa Group / Exclude Group / All Users / All Devices -kohdistukset
    - Tunnistaa assignment filterit
    - Hakee ryhmän nimen Entra ID:stä
    - Vie tulokset CSV:ksi
    - Ei muuta Intunea, Entra ID:tä eikä sovellusten kohdistuksia

.REQUIRED SCOPES
    DeviceManagementApps.Read.All
    Group.Read.All

.NOTES
    Safe / Read-only:
    Käyttää vain Get-* -komentoja ja Export-Csv:tä.
#>

$ErrorActionPreference = "Stop"

# -----------------------------
# Asetukset
# -----------------------------
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir = Join-Path $PSScriptRoot "output\intune-audit"
$OutFile = Join-Path $OutDir "Intune_WindowsApps_Assignments_$Timestamp.csv"

New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

# -----------------------------
# Otsikko
# -----------------------------
Write-Host ""
Write-Host "=== Intune Windows Apps Assignment Audit ===" -ForegroundColor Cyan
Write-Host "Mode: READ-ONLY" -ForegroundColor Green
Write-Host "Output: $OutFile" -ForegroundColor DarkGray

# -----------------------------
# Microsoft Graph -yhteys
# -----------------------------
try {
    Write-Host ""
    Write-Host "Yhdistetään Microsoft Graphiin..." -ForegroundColor Yellow

    Connect-MgGraph `
        -Scopes "DeviceManagementApps.Read.All", "Group.Read.All" `
        -NoWelcome

    $context = Get-MgContext

    Write-Host "Yhdistetty tenanttiin: $($context.TenantId)" -ForegroundColor DarkGray
    Write-Host "Account: $($context.Account)" -ForegroundColor DarkGray
}
catch {
    Write-Host "ERROR: Microsoft Graph -kirjautuminen epäonnistui." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

# -----------------------------
# Apufunktiot
# -----------------------------

function Get-ODataType {
    param(
        [Parameter(Mandatory = $false)]
        $Object
    )

    if (-not $Object) {
        return $null
    }

    if ($Object.PSObject.Properties.Name -contains "@odata.type") {
        return $Object.'@odata.type'
    }

    if ($Object.AdditionalProperties -and $Object.AdditionalProperties.ContainsKey("@odata.type")) {
        return $Object.AdditionalProperties["@odata.type"]
    }

    return $Object.GetType().Name
}

function Get-PropertyValueSafe {
    param(
        [Parameter(Mandatory = $false)]
        $Object,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $false)]
        [string]$AdditionalPropertyName
    )

    if (-not $Object) {
        return $null
    }

    if ($Object.PSObject.Properties.Name -contains $PropertyName) {
        $value = $Object.$PropertyName
        if ($null -ne $value -and $value -ne "") {
            return $value
        }
    }

    if (-not $AdditionalPropertyName) {
        $AdditionalPropertyName = $PropertyName
    }

    if ($Object.AdditionalProperties -and $Object.AdditionalProperties.ContainsKey($AdditionalPropertyName)) {
        return $Object.AdditionalProperties[$AdditionalPropertyName]
    }

    return $null
}

function Get-TargetGroupId {
    param(
        [Parameter(Mandatory = $false)]
        $Target
    )

    return Get-PropertyValueSafe `
        -Object $Target `
        -PropertyName "GroupId" `
        -AdditionalPropertyName "groupId"
}

function Get-AssignmentFilterInfo {
    param(
        [Parameter(Mandatory = $false)]
        $Target
    )

    $filterId = Get-PropertyValueSafe `
        -Object $Target `
        -PropertyName "DeviceAndAppManagementAssignmentFilterId" `
        -AdditionalPropertyName "deviceAndAppManagementAssignmentFilterId"

    $filterType = Get-PropertyValueSafe `
        -Object $Target `
        -PropertyName "DeviceAndAppManagementAssignmentFilterType" `
        -AdditionalPropertyName "deviceAndAppManagementAssignmentFilterType"

    if (-not $filterType) {
        $filterType = "none"
    }

    return @{
        FilterId   = $filterId
        FilterType = $filterType
    }
}

function Convert-AppType {
    param(
        [Parameter(Mandatory = $false)]
        [string]$ODataType
    )

    switch -Wildcard ($ODataType) {
        "*win32LobApp*"                  { return "Win32 app" }
        "*windowsMobileMSI*"             { return "Windows MSI / LOB" }
        "*windowsMicrosoftEdgeApp*"      { return "Microsoft Edge app" }
        "*windowsStoreApp*"              { return "Windows Store app" }
        "*microsoftStoreForBusinessApp*" { return "Microsoft Store for Business app" }
        "*officeSuiteApp*"               { return "Microsoft 365 Apps / Office suite" }
        "*webApp*"                       { return "Web app" }
        default {
            if ($ODataType) {
                return $ODataType
            }
            else {
                return "Unknown"
            }
        }
    }
}

function Test-IsWindowsApp {
    param(
        [Parameter(Mandatory = $false)]
        [string]$ODataType
    )

    if (-not $ODataType) {
        return $false
    }

    if (
        $ODataType -like "*windows*" -or
        $ODataType -like "*win32*" -or
        $ODataType -like "*officeSuiteApp*" -or
        $ODataType -like "*microsoftStore*"
    ) {
        return $true
    }

    return $false
}

function Convert-TargetType {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TargetODataType
    )

    # Tärkeää:
    # Exclusion pitää tarkistaa ennen groupAssignmentTargetia,
    # koska "exclusionGroupAssignmentTarget" sisältää myös tekstin "groupAssignmentTarget".
    switch -Wildcard ($TargetODataType) {
        "*exclusionGroupAssignmentTarget*" {
            return "Exclude group"
        }
        "*groupAssignmentTarget*" {
            return "Group"
        }
        "*allLicensedUsersAssignmentTarget*" {
            return "All users"
        }
        "*allDevicesAssignmentTarget*" {
            return "All devices"
        }
        "*configurationManagerCollectionAssignmentTarget*" {
            return "Configuration Manager collection"
        }
        default {
            if ($TargetODataType) {
                return $TargetODataType
            }
            else {
                return "Unknown"
            }
        }
    }
}

function Convert-AssignmentIntent {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Intent
    )

    switch ($Intent) {
        "required"            { return "Required" }
        "available"           { return "Available" }
        "uninstall"           { return "Uninstall" }
        "availableWithoutEnrollment" { return "Available without enrollment" }
        default {
            if ($Intent) {
                return $Intent
            }
            else {
                return "Unknown"
            }
        }
    }
}

# Ryhmäcache, ettei samaa ryhmää haeta Graphista turhaan uudelleen.
$GroupCache = @{}

function Get-CachedGroupName {
    param(
        [Parameter(Mandatory = $false)]
        [string]$GroupId
    )

    if (-not $GroupId) {
        return $null
    }

    if ($GroupCache.ContainsKey($GroupId)) {
        return $GroupCache[$GroupId]
    }

    try {
        $group = Get-MgGroup `
            -GroupId $GroupId `
            -Property "id,displayName" `
            -ErrorAction Stop

        $GroupCache[$GroupId] = $group.DisplayName
        return $group.DisplayName
    }
    catch {
        $GroupCache[$GroupId] = "[Group not found or no permission]"
        return $GroupCache[$GroupId]
    }
}

# -----------------------------
# Hae sovellukset
# -----------------------------
try {
    Write-Host ""
    Write-Host "Haetaan Intune-sovellukset..." -ForegroundColor Yellow

    $apps = Get-MgDeviceAppManagementMobileApp -All
}
catch {
    Write-Host "ERROR: Sovellusten haku epäonnistui." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

$windowsApps = foreach ($app in $apps) {
    $appODataType = Get-ODataType -Object $app

    if (Test-IsWindowsApp -ODataType $appODataType) {
        $app
    }
}

Write-Host "Sovelluksia yhteensä: $($apps.Count)" -ForegroundColor DarkGray
Write-Host "Windows-sovelluksia: $($windowsApps.Count)" -ForegroundColor DarkGray

# -----------------------------
# Hae assignmentit
# -----------------------------
$result = New-Object System.Collections.Generic.List[object]
$counter = 0

foreach ($app in $windowsApps) {
    $counter++

    $appODataType = Get-ODataType -Object $app
    $appTypeFriendly = Convert-AppType -ODataType $appODataType

    Write-Progress `
        -Activity "Haetaan Intune app assignmentit" `
        -Status "$counter / $($windowsApps.Count): $($app.DisplayName)" `
        -PercentComplete (($counter / [math]::Max($windowsApps.Count, 1)) * 100)

    try {
        $assignments = Get-MgDeviceAppManagementMobileAppAssignment `
            -MobileAppId $app.Id `
            -All `
            -ErrorAction Stop
    }
    catch {
        $result.Add([PSCustomObject]@{
            AppName      = $app.DisplayName
            AppId        = $app.Id
            AppType      = $appTypeFriendly
            AppODataType = $appODataType
            Assignment   = "[ERROR]"
            IntentRaw    = $null
            TargetType   = $null
            TargetRaw    = $null
            TargetName   = $null
            GroupName    = $null
            GroupId      = $null
            FilterType   = $null
            FilterId     = $null
            AssignmentId = $null
            IsReadOnly   = $true
            Error        = $_.Exception.Message
        })

        continue
    }

    if (-not $assignments -or $assignments.Count -eq 0) {
        $result.Add([PSCustomObject]@{
            AppName      = $app.DisplayName
            AppId        = $app.Id
            AppType      = $appTypeFriendly
            AppODataType = $appODataType
            Assignment   = "[Not assigned]"
            IntentRaw    = $null
            TargetType   = $null
            TargetRaw    = $null
            TargetName   = $null
            GroupName    = $null
            GroupId      = $null
            FilterType   = $null
            FilterId     = $null
            AssignmentId = $null
            IsReadOnly   = $true
            Error        = $null
        })

        continue
    }

    foreach ($a in $assignments) {
        $target = $a.Target

        $targetODataType = Get-ODataType -Object $target
        $targetType = Convert-TargetType -TargetODataType $targetODataType

        $groupId = Get-TargetGroupId -Target $target
        $groupName = Get-CachedGroupName -GroupId $groupId

        $filterInfo = Get-AssignmentFilterInfo -Target $target

        $targetName = switch ($targetType) {
            "Group" {
                $groupName
            }
            "Exclude group" {
                $groupName
            }
            "All users" {
                "All licensed users"
            }
            "All devices" {
                "All devices"
            }
            "Configuration Manager collection" {
                "Configuration Manager collection"
            }
            default {
                $targetType
            }
        }

        $result.Add([PSCustomObject]@{
            AppName      = $app.DisplayName
            AppId        = $app.Id
            AppType      = $appTypeFriendly
            AppODataType = $appODataType
            Assignment   = Convert-AssignmentIntent -Intent $a.Intent
            IntentRaw    = $a.Intent
            TargetType   = $targetType
            TargetRaw    = $targetODataType
            TargetName   = $targetName
            GroupName    = $groupName
            GroupId      = $groupId
            FilterType   = $filterInfo.FilterType
            FilterId     = $filterInfo.FilterId
            AssignmentId = $a.Id
            IsReadOnly   = $true
            Error        = $null
        })
    }
}

Write-Progress -Activity "Haetaan Intune app assignmentit" -Completed

# -----------------------------
# Export
# -----------------------------
try {
    $result |
        Sort-Object AppName, Assignment, TargetType, TargetName |
        Export-Csv $OutFile -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Host "ERROR: CSV-export epäonnistui." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

# -----------------------------
# Yhteenveto
# -----------------------------
Write-Host ""
Write-Host "Valmis." -ForegroundColor Green
Write-Host "CSV: $OutFile" -ForegroundColor Green

Write-Host ""
Write-Host "Yhteenveto assignment-tyypeistä:" -ForegroundColor Cyan

$result |
    Group-Object Assignment |
    Sort-Object Name |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Yhteenveto target-tyypeistä:" -ForegroundColor Cyan

$result |
    Group-Object TargetType |
    Sort-Object Name |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Sovellukset ilman assignmentia:" -ForegroundColor Cyan

$result |
    Where-Object { $_.Assignment -eq "[Not assigned]" } |
    Select-Object AppName, AppType |
    Sort-Object AppName |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Read-only tarkistus:" -ForegroundColor Cyan
Write-Host "Käytetyt tenanttiin kohdistuvat komennot: Connect-MgGraph, Get-MgContext, Get-MgDeviceAppManagementMobileApp, Get-MgDeviceAppManagementMobileAppAssignment, Get-MgGroup" -ForegroundColor DarkGray
Write-Host "Muutoksia tekeviä komentoja ei käytetty." -ForegroundColor Green
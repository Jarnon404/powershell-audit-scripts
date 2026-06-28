<#
.SYNOPSIS
    Intune Windows Update Policy Audit.

.DESCRIPTION
    Kerää Intunen Windows Update -ringit, feature/quality/driver update -profiilit, deploymentit ja assignmentit.

.REQUIREMENTS
    - Microsoft Graph PowerShell -moduulit ja Intune update policy -tietojen lukuoikeudet

.OUTPUTS
    - CSV/HTML-raportti Intune Windows Update -asetuksista

.EXAMPLE
    .\Invoke-IntuneWindowsUpdateAuditReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Invoke-IntuneWindowsUpdateAuditReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

<#
.SYNOPSIS
    Intune Windows Update -kokonaisauditointi.

.DESCRIPTION
    READ-ONLY-auditointi, joka hakee:

    - Windows Update Ringit
    - Feature Update -profiilit
    - Quality Update -profiilit
    - Driver Update -profiilit
    - Driver Update -inventaarion
    - Windows Update / Autopatch -deploymentit
    - Windows Update -catalog entries eli Releases
    - profiilien kohdistukset
    - Entra ID -ryhmien nimet
    - assignment filter -tiedot
    - täydet raakavastaukset JSON-tiedostoihin
    - tiivistelmät CSV-tiedostoihin
    - haettavan ja lajiteltavan HTML-raportin

    Skripti ei muuta Intunea, Entra ID:tä, laitteita tai päivityksiä.

.REQUIRED SCOPES
    DeviceManagementConfiguration.Read.All
    Group.Read.All
    WindowsUpdates.Read.All

.NOTES
    TENANTIN OSALTA READ-ONLY:

    - Käyttää Microsoft Graphiin vain HTTP GET -pyyntöjä
    - Ei käytä POST-, PATCH-, PUT- tai DELETE-pyyntöjä
    - Ei muuta Intunen asetuksia
    - Ei muuta Entra ID -ryhmiä
    - Ei käynnistä tai asenna Windows-päivityksiä

    Skripti kirjoittaa raporttitiedostoja paikalliselle levylle.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path $PSScriptRoot "output\intune-windowsupdate-audit"),

    [switch]$DoNotOpenReport
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Perusasetukset
# ------------------------------------------------------------

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir = Join-Path $OutputRoot $Timestamp

New-Item `
    -Path $OutputDir `
    -ItemType Directory `
    -Force |
    Out-Null

$Scopes = @(
    "DeviceManagementConfiguration.Read.All",
    "Group.Read.All",
    "WindowsUpdates.Read.All"
)

# Alustetaan muuttujat, jotta HTML-raportti voidaan muodostaa,
# vaikka jokin yksittäinen Graph-haku epäonnistuisi.

$UpdateRings = @()
$UpdateRingSummary = @()

$FeatureProfiles = @()
$FeatureSummary = @()

$QualityProfiles = @()
$QualitySummary = @()

$DriverProfiles = @()
$DriverSummary = @()
$AllDriverInventory = @()

$CatalogEntries = @()
$CatalogSummary = @()

$Deployments = @()
$DeploymentSummary = @()

$GroupCache = @{}

$AllAssignments =
    [System.Collections.Generic.List[object]]::new()

$Errors =
    [System.Collections.Generic.List[object]]::new()

$Findings =
    [System.Collections.Generic.List[object]]::new()

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Cyan

Write-Host " Intune Windows Update -kokonaisauditointi" `
    -ForegroundColor Cyan

Write-Host " READ-ONLY - tenanttiin ei tehdä muutoksia" `
    -ForegroundColor Green

Write-Host "============================================================" `
    -ForegroundColor Cyan

Write-Host ""
Write-Host "Tuloshakemisto: $OutputDir" `
    -ForegroundColor DarkGray

# ------------------------------------------------------------
# Moduulin tarkistus ja Graph-yhteys
# ------------------------------------------------------------

if (
    -not (
        Get-Module `
            -ListAvailable `
            -Name Microsoft.Graph.Authentication
    )
) {
    throw @"
Microsoft.Graph.Authentication-moduulia ei löytynyt.

Asenna se nykyiselle käyttäjälle:

Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
"@
}

Import-Module Microsoft.Graph.Authentication `
    -ErrorAction Stop

Connect-MgGraph `
    -Scopes $Scopes `
    -NoWelcome

$GraphContext = Get-MgContext

if (-not $GraphContext) {
    throw "Microsoft Graph -yhteyttä ei voitu muodostaa."
}

Write-Host ""
Write-Host "Tenant ID : $($GraphContext.TenantId)" `
    -ForegroundColor DarkGray

Write-Host "Account   : $($GraphContext.Account)" `
    -ForegroundColor DarkGray

Write-Host "Auth type : $($GraphContext.AuthType)" `
    -ForegroundColor DarkGray

# ------------------------------------------------------------
# Apufunktiot
# ------------------------------------------------------------

function Invoke-GraphGetAll {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [switch]$AllowFailure
    )

    $Results =
        [System.Collections.Generic.List[object]]::new()

    $NextUri = $Uri

    try {
        while ($NextUri) {
            $Response = Invoke-MgGraphRequest `
                -Method GET `
                -Uri $NextUri `
                -OutputType PSObject

            if ($null -ne $Response.value) {
                foreach ($Item in @($Response.value)) {
                    $Results.Add($Item)
                }

                $NextUri = $Response.'@odata.nextLink'
            }
            else {
                if ($null -ne $Response) {
                    $Results.Add($Response)
                }

                $NextUri = $null
            }
        }

        return @($Results)
    }
    catch {
        if ($AllowFailure) {
            Write-Warning "Graph-haku epäonnistui:"
            Write-Warning $Uri
            Write-Warning $_.Exception.Message

            return @()
        }

        throw
    }
}

function Export-JsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $Json = ConvertTo-Json `
        -InputObject @($InputObject) `
        -Depth 50

    $Json |
        Set-Content `
            -Path $Path `
            -Encoding UTF8
}

function Export-CsvSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $Rows = @($InputObject)

    if ($Rows.Count -gt 0) {
        $Rows |
            Export-Csv `
                -Path $Path `
                -NoTypeInformation `
                -Encoding UTF8
    }
    else {
        "" |
            Set-Content `
                -Path $Path `
                -Encoding UTF8
    }
}

function ConvertTo-CompactJson {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [int]$Depth = 15
    )

    if ($null -eq $InputObject) {
        return ""
    }

    return (
        ConvertTo-Json `
            -InputObject $InputObject `
            -Compress `
            -Depth $Depth
    )
}

function ConvertTo-HtmlSafe {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode(
        [string]$Value
    )
}

function New-HtmlTable {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Data,

        [Parameter(Mandatory)]
        [string[]]$Properties,

        [string]$EmptyMessage = "Ei tietoja.",

        [string]$TableClass = "audit-table"
    )

    $Rows = @($Data)

    if ($Rows.Count -eq 0) {
        $SafeMessage = ConvertTo-HtmlSafe $EmptyMessage

        return "<div class='empty'>$SafeMessage</div>"
    }

    $Fragment = (
        $Rows |
            Select-Object -Property $Properties |
            ConvertTo-Html `
                -Fragment |
            Out-String
    )

    return $Fragment.Replace(
        "<table>",
        "<table class='$TableClass'>"
    )
}

function Get-TargetInformation {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Target,

        [Parameter(Mandatory)]
        [hashtable]$GroupCache
    )

    if ($null -eq $Target) {
        return [pscustomobject]@{
            AssignmentType = "Unknown"
            GroupId         = $null
            GroupName       = $null
            FilterId        = $null
            FilterType      = $null
            TargetODataType = $null
        }
    }

    $TargetType = $Target.'@odata.type'
    $GroupId = $Target.groupId
    $GroupName = $null
    $AssignmentType = $TargetType

    switch ($TargetType) {
        "#microsoft.graph.groupAssignmentTarget" {
            $AssignmentType = "Include Group"
        }

        "#microsoft.graph.exclusionGroupAssignmentTarget" {
            $AssignmentType = "Exclude Group"
        }

        "#microsoft.graph.allDevicesAssignmentTarget" {
            $AssignmentType = "All Devices"
        }

        "#microsoft.graph.allLicensedUsersAssignmentTarget" {
            $AssignmentType = "All Users"
        }

        "#microsoft.graph.allUsersAssignmentTarget" {
            $AssignmentType = "All Users"
        }

        default {
            if ([string]::IsNullOrWhiteSpace($AssignmentType)) {
                $AssignmentType = "Unknown"
            }
        }
    }

    if ($GroupId) {
        if ($GroupCache.ContainsKey($GroupId)) {
            $GroupName = $GroupCache[$GroupId]
        }
        else {
            try {
                $EncodedGroupId =
                    [uri]::EscapeDataString($GroupId)

                $GroupUri =
                    "https://graph.microsoft.com/v1.0/groups/" +
                    "$EncodedGroupId" +
                    "?`$select=id,displayName"

                $Group = Invoke-MgGraphRequest `
                    -Method GET `
                    -Uri $GroupUri `
                    -OutputType PSObject

                $GroupName = $Group.displayName

                if (
                    [string]::IsNullOrWhiteSpace(
                        [string]$GroupName
                    )
                ) {
                    $GroupName = "[Ryhmällä ei ole nimeä]"
                }

                $GroupCache[$GroupId] = $GroupName
            }
            catch {
                $GroupName =
                    "[Ryhmän nimeä ei voitu lukea]"

                $GroupCache[$GroupId] = $GroupName
            }
        }
    }

    return [pscustomobject]@{
        AssignmentType = $AssignmentType
        GroupId         = $GroupId
        GroupName       = $GroupName
        FilterId        =
            $Target.deviceAndAppManagementAssignmentFilterId
        FilterType      =
            $Target.deviceAndAppManagementAssignmentFilterType
        TargetODataType = $TargetType
    }
}

function Get-ProfileAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AssignmentUri,

        [Parameter(Mandatory)]
        [string]$ProfileType,

        [Parameter(Mandatory)]
        [string]$ProfileName,

        [Parameter(Mandatory)]
        [string]$ProfileId,

        [Parameter(Mandatory)]
        [hashtable]$GroupCache
    )

    $Assignments = Invoke-GraphGetAll `
        -Uri $AssignmentUri `
        -AllowFailure

    if (@($Assignments).Count -eq 0) {
        return [pscustomobject]@{
            ProfileType     = $ProfileType
            ProfileName     = $ProfileName
            ProfileId       = $ProfileId
            AssignmentType  = "Ei kohdistuksia"
            GroupName       = $null
            GroupId         = $null
            FilterId        = $null
            FilterType      = $null
            TargetODataType = $null
        }
    }

    foreach ($Assignment in @($Assignments)) {
        $TargetInfo = Get-TargetInformation `
            -Target $Assignment.target `
            -GroupCache $GroupCache

        [pscustomobject]@{
            ProfileType     = $ProfileType
            ProfileName     = $ProfileName
            ProfileId       = $ProfileId
            AssignmentType  = $TargetInfo.AssignmentType
            GroupName       = $TargetInfo.GroupName
            GroupId         = $TargetInfo.GroupId
            FilterId        = $TargetInfo.FilterId
            FilterType      = $TargetInfo.FilterType
            TargetODataType = $TargetInfo.TargetODataType
        }
    }
}

function Add-AuditError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Section,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $Errors.Add(
        [pscustomobject]@{
            Section = $Section
            Error   = $Message
        }
    )
}

# ------------------------------------------------------------
# 1. Update Rings
# ------------------------------------------------------------

Write-Host ""
Write-Host "[1/6] Haetaan Update Ringit..." `
    -ForegroundColor Yellow

try {
    $UpdateRingUri =
        "https://graph.microsoft.com/v1.0/" +
        "deviceManagement/deviceConfigurations" +
        "?`$filter=isof(" +
        "'microsoft.graph.windowsUpdateForBusinessConfiguration'" +
        ")"

    $UpdateRings =
        @(Invoke-GraphGetAll -Uri $UpdateRingUri)

    Export-JsonFile `
        -InputObject $UpdateRings `
        -Path (
            Join-Path `
                $OutputDir `
                "01_UpdateRings_FULL.json"
        )

    $UpdateRingSummary = @(
        foreach ($Ring in $UpdateRings) {
            [pscustomobject]@{
                Name =
                    $Ring.displayName

                Description =
                    $Ring.description

                Id =
                    $Ring.id

                CreatedDateTime =
                    $Ring.createdDateTime

                LastModifiedDateTime =
                    $Ring.lastModifiedDateTime

                QualityUpdatesDeferralDays =
                    $Ring.qualityUpdatesDeferralPeriodInDays

                FeatureUpdatesDeferralDays =
                    $Ring.featureUpdatesDeferralPeriodInDays

                QualityUpdatesPauseStartDate =
                    $Ring.qualityUpdatesPauseStartDate

                FeatureUpdatesPauseStartDate =
                    $Ring.featureUpdatesPauseStartDate

                DriversExcluded =
                    $Ring.driversExcluded

                MicrosoftUpdateServiceAllowed =
                    $Ring.microsoftUpdateServiceAllowed

                AutomaticUpdateMode =
                    $Ring.automaticUpdateMode

                BusinessReadyUpdatesOnly =
                    $Ring.businessReadyUpdatesOnly

                ActiveHoursStart =
                    $Ring.activeHoursStart

                ActiveHoursEnd =
                    $Ring.activeHoursEnd

                UserPauseAccess =
                    $Ring.userPauseAccess

                UserWindowsUpdateScanAccess =
                    $Ring.userWindowsUpdateScanAccess

                UpdateNotificationLevel =
                    $Ring.updateNotificationLevel

                FeatureUpdatesRollbackWindowDays =
                    $Ring.featureUpdatesRollbackWindowInDays

                DeadlineForFeatureUpdatesDays =
                    $Ring.deadlineForFeatureUpdatesInDays

                DeadlineForQualityUpdatesDays =
                    $Ring.deadlineForQualityUpdatesInDays

                DeadlineGracePeriodDays =
                    $Ring.deadlineGracePeriodInDays

                DeadlineNoAutoReboot =
                    $Ring.deadlineNoAutoReboot

                AutoRestartNotificationDismissal =
                    $Ring.autoRestartNotificationDismissal

                ScheduleRestartWarningHours =
                    $Ring.scheduleRestartWarningInHours

                ScheduleImminentRestartWarningMinutes =
                    $Ring.scheduleImminentRestartWarningInMinutes

                EngagedRestartDeadlineDays =
                    $Ring.engagedRestartDeadlineInDays

                EngagedRestartSnoozeScheduleDays =
                    $Ring.engagedRestartSnoozeScheduleInDays

                EngagedRestartTransitionScheduleDays =
                    $Ring.engagedRestartTransitionScheduleInDays
            }

            $AssignmentUri =
                "https://graph.microsoft.com/v1.0/" +
                "deviceManagement/deviceConfigurations/" +
                "$($Ring.id)/assignments"

            $ProfileAssignments =
                Get-ProfileAssignments `
                    -AssignmentUri $AssignmentUri `
                    -ProfileType "Update Ring" `
                    -ProfileName $Ring.displayName `
                    -ProfileId $Ring.id `
                    -GroupCache $GroupCache

            foreach (
                $Assignment in @($ProfileAssignments)
            ) {
                $AllAssignments.Add($Assignment)
            }
        }
    )

    Export-CsvSafe `
        -InputObject $UpdateRingSummary `
        -Path (
            Join-Path `
                $OutputDir `
                "01_UpdateRings.csv"
        )

    Write-Host `
        "  Update Ringejä: $($UpdateRings.Count)" `
        -ForegroundColor Green
}
catch {
    Add-AuditError `
        -Section "Update Rings" `
        -Message $_.Exception.Message

    Write-Warning (
        "Update Ringien haku epäonnistui: " +
        $_.Exception.Message
    )
}

# ------------------------------------------------------------
# 2. Feature Update -profiilit
# ------------------------------------------------------------

Write-Host ""
Write-Host "[2/6] Haetaan Feature Update -profiilit..." `
    -ForegroundColor Yellow

try {
    $FeatureProfiles = @(
        Invoke-GraphGetAll `
            -Uri (
                "https://graph.microsoft.com/beta/" +
                "deviceManagement/windowsFeatureUpdateProfiles"
            )
    )

    Export-JsonFile `
        -InputObject $FeatureProfiles `
        -Path (
            Join-Path `
                $OutputDir `
                "02_FeatureUpdates_FULL.json"
        )

    $FeatureSummary = @(
        foreach ($Profile in $FeatureProfiles) {
            [pscustomobject]@{
                Name =
                    $Profile.displayName

                Description =
                    $Profile.description

                Id =
                    $Profile.id

                FeatureUpdateVersion =
                    $Profile.featureUpdateVersion

                InstallLatestWindows10OnWindows11IneligibleDevice =
                    $Profile.installLatestWindows10OnWindows11IneligibleDevice

                InstallFeatureUpdatesOptional =
                    $Profile.installFeatureUpdatesOptional

                RolloutSettings =
                    ConvertTo-CompactJson `
                        -InputObject $Profile.rolloutSettings

                CreatedDateTime =
                    $Profile.createdDateTime

                LastModifiedDateTime =
                    $Profile.lastModifiedDateTime
            }

            $AssignmentUri =
                "https://graph.microsoft.com/beta/" +
                "deviceManagement/windowsFeatureUpdateProfiles/" +
                "$($Profile.id)/assignments"

            $ProfileAssignments =
                Get-ProfileAssignments `
                    -AssignmentUri $AssignmentUri `
                    -ProfileType "Feature Update" `
                    -ProfileName $Profile.displayName `
                    -ProfileId $Profile.id `
                    -GroupCache $GroupCache

            foreach (
                $Assignment in @($ProfileAssignments)
            ) {
                $AllAssignments.Add($Assignment)
            }
        }
    )

    Export-CsvSafe `
        -InputObject $FeatureSummary `
        -Path (
            Join-Path `
                $OutputDir `
                "02_FeatureUpdates.csv"
        )

    Write-Host (
        "  Feature Update -profiileja: " +
        $FeatureProfiles.Count
    ) -ForegroundColor Green
}
catch {
    Add-AuditError `
        -Section "Feature Updates" `
        -Message $_.Exception.Message

    Write-Warning (
        "Feature Update -profiilien haku epäonnistui: " +
        $_.Exception.Message
    )
}

# ------------------------------------------------------------
# 3. Quality Update -profiilit
# ------------------------------------------------------------

Write-Host ""
Write-Host "[3/6] Haetaan Quality Update -profiilit..." `
    -ForegroundColor Yellow

try {
    $QualityProfiles = @(
        Invoke-GraphGetAll `
            -Uri (
                "https://graph.microsoft.com/beta/" +
                "deviceManagement/windowsQualityUpdateProfiles"
            )
    )

    Export-JsonFile `
        -InputObject $QualityProfiles `
        -Path (
            Join-Path `
                $OutputDir `
                "03_QualityUpdates_FULL.json"
        )

    $QualitySummary = @(
        foreach ($Profile in $QualityProfiles) {
            [pscustomobject]@{
                Name =
                    $Profile.displayName

                Description =
                    $Profile.description

                Id =
                    $Profile.id

                ExpeditedUpdateSettings =
                    ConvertTo-CompactJson `
                        -InputObject `
                            $Profile.expeditedUpdateSettings

                CreatedDateTime =
                    $Profile.createdDateTime

                LastModifiedDateTime =
                    $Profile.lastModifiedDateTime
            }

            $AssignmentUri =
                "https://graph.microsoft.com/beta/" +
                "deviceManagement/windowsQualityUpdateProfiles/" +
                "$($Profile.id)/assignments"

            $ProfileAssignments =
                Get-ProfileAssignments `
                    -AssignmentUri $AssignmentUri `
                    -ProfileType "Quality Update" `
                    -ProfileName $Profile.displayName `
                    -ProfileId $Profile.id `
                    -GroupCache $GroupCache

            foreach (
                $Assignment in @($ProfileAssignments)
            ) {
                $AllAssignments.Add($Assignment)
            }
        }
    )

    Export-CsvSafe `
        -InputObject $QualitySummary `
        -Path (
            Join-Path `
                $OutputDir `
                "03_QualityUpdates.csv"
        )

    Write-Host (
        "  Quality Update -profiileja: " +
        $QualityProfiles.Count
    ) -ForegroundColor Green
}
catch {
    Add-AuditError `
        -Section "Quality Updates" `
        -Message $_.Exception.Message

    Write-Warning (
        "Quality Update -profiilien haku epäonnistui: " +
        $_.Exception.Message
    )
}

# ------------------------------------------------------------
# 4. Driver Update -profiilit
# ------------------------------------------------------------

Write-Host ""
Write-Host "[4/6] Haetaan Driver Update -profiilit..." `
    -ForegroundColor Yellow

try {
    $DriverProfiles = @(
        Invoke-GraphGetAll `
            -Uri (
                "https://graph.microsoft.com/beta/" +
                "deviceManagement/windowsDriverUpdateProfiles"
            )
    )

    Export-JsonFile `
        -InputObject $DriverProfiles `
        -Path (
            Join-Path `
                $OutputDir `
                "04_DriverUpdates_FULL.json"
        )

    $DriverSummary = @(
        foreach ($Profile in $DriverProfiles) {
            [pscustomobject]@{
                Name =
                    $Profile.displayName

                Description =
                    $Profile.description

                Id =
                    $Profile.id

                ApprovalType =
                    $Profile.approvalType

                DeviceReporting =
                    $Profile.deviceReporting

                InventorySyncStatus =
                    ConvertTo-CompactJson `
                        -InputObject `
                            $Profile.inventorySyncStatus

                DeploymentDeferralInDays =
                    $Profile.deploymentDeferralInDays

                CreatedDateTime =
                    $Profile.createdDateTime

                LastModifiedDateTime =
                    $Profile.lastModifiedDateTime
            }

            $AssignmentUri =
                "https://graph.microsoft.com/beta/" +
                "deviceManagement/windowsDriverUpdateProfiles/" +
                "$($Profile.id)/assignments"

            $ProfileAssignments =
                Get-ProfileAssignments `
                    -AssignmentUri $AssignmentUri `
                    -ProfileType "Driver Update" `
                    -ProfileName $Profile.displayName `
                    -ProfileId $Profile.id `
                    -GroupCache $GroupCache

            foreach (
                $Assignment in @($ProfileAssignments)
            ) {
                $AllAssignments.Add($Assignment)
            }

            try {
                $InventoryUri =
                    "https://graph.microsoft.com/beta/" +
                    "deviceManagement/windowsDriverUpdateProfiles/" +
                    "$($Profile.id)/driverInventories"

                $DriverInventory = @(
                    Invoke-GraphGetAll `
                        -Uri $InventoryUri `
                        -AllowFailure
                )

                if ($DriverInventory.Count -gt 0) {
                    Export-JsonFile `
                        -InputObject $DriverInventory `
                        -Path (
                            Join-Path `
                                $OutputDir `
                                (
                                    "04_DriverInventory_{0}.json" `
                                        -f $Profile.id
                                )
                        )

                    $DriverInventorySummary = @(
                        foreach (
                            $Driver in $DriverInventory
                        ) {
                            [pscustomobject]@{
                                ProfileName =
                                    $Profile.displayName

                                ProfileId =
                                    $Profile.id

                                DriverId =
                                    $Driver.id

                                Name =
                                    $Driver.name

                                Version =
                                    $Driver.version

                                Manufacturer =
                                    $Driver.manufacturer

                                ReleaseDateTime =
                                    $Driver.releaseDateTime

                                DriverClass =
                                    $Driver.driverClass

                                ApplicableDeviceCount =
                                    $Driver.applicableDeviceCount

                                ApprovalStatus =
                                    $Driver.approvalStatus

                                Category =
                                    $Driver.category

                                DeployDateTime =
                                    $Driver.deployDateTime
                            }
                        }
                    )

                    $AllDriverInventory +=
                        $DriverInventorySummary

                    Export-CsvSafe `
                        -InputObject `
                            $DriverInventorySummary `
                        -Path (
                            Join-Path `
                                $OutputDir `
                                (
                                    "04_DriverInventory_{0}.csv" `
                                        -f $Profile.id
                                )
                        )
                }
            }
            catch {
                Add-AuditError `
                    -Section (
                        "Driver Inventory: " +
                        $Profile.displayName
                    ) `
                    -Message $_.Exception.Message
            }
        }
    )

    Export-CsvSafe `
        -InputObject $DriverSummary `
        -Path (
            Join-Path `
                $OutputDir `
                "04_DriverUpdates.csv"
        )

    Export-CsvSafe `
        -InputObject $AllDriverInventory `
        -Path (
            Join-Path `
                $OutputDir `
                "04_AllDriverInventory.csv"
        )

    Write-Host (
        "  Driver Update -profiileja: " +
        $DriverProfiles.Count
    ) -ForegroundColor Green

    Write-Host (
        "  Ajuri-inventaarion rivejä: " +
        @($AllDriverInventory).Count
    ) -ForegroundColor Green
}
catch {
    Add-AuditError `
        -Section "Driver Updates" `
        -Message $_.Exception.Message

    Write-Warning (
        "Driver Update -profiilien haku epäonnistui: " +
        $_.Exception.Message
    )
}

# ------------------------------------------------------------
# 5. Releases / Windows Update -catalog
# ------------------------------------------------------------

Write-Host ""
Write-Host "[5/6] Haetaan Releases / Windows Update -catalog..." `
    -ForegroundColor Yellow

try {
    $CatalogEntries = @(
        Invoke-GraphGetAll `
            -Uri (
                "https://graph.microsoft.com/beta/" +
                "admin/windows/updates/catalog/entries"
            ) `
            -AllowFailure
    )

    Export-JsonFile `
        -InputObject $CatalogEntries `
        -Path (
            Join-Path `
                $OutputDir `
                "05_Releases_Catalog_FULL.json"
        )

    $CatalogSummary = @(
        foreach ($Entry in $CatalogEntries) {
            [pscustomobject]@{
                Id =
                    $Entry.id

                DisplayName =
                    $Entry.displayName

                ODataType =
                    $Entry.'@odata.type'

                ReleaseDateTime =
                    $Entry.releaseDateTime

                DeployableUntilDateTime =
                    $Entry.deployableUntilDateTime

                CatalogName =
                    $Entry.catalogName

                Version =
                    $Entry.version

                BuildNumber =
                    $Entry.buildNumber

                QualityUpdateClassification =
                    $Entry.qualityUpdateClassification

                IsExpeditable =
                    $Entry.isExpeditable
            }
        }
    )

    Export-CsvSafe `
        -InputObject $CatalogSummary `
        -Path (
            Join-Path `
                $OutputDir `
                "05_Releases_Catalog.csv"
        )

    Write-Host (
        "  Catalog entries: " +
        $CatalogEntries.Count
    ) -ForegroundColor Green
}
catch {
    Add-AuditError `
        -Section "Releases / Catalog" `
        -Message $_.Exception.Message

    Write-Warning (
        "Releases/catalog-haku epäonnistui: " +
        $_.Exception.Message
    )
}

# ------------------------------------------------------------
# 6. Windows Update / Autopatch -deploymentit
# ------------------------------------------------------------

Write-Host ""
Write-Host "[6/6] Haetaan Windows Update -deploymentit..." `
    -ForegroundColor Yellow

try {
    $Deployments = @(
        Invoke-GraphGetAll `
            -Uri (
                "https://graph.microsoft.com/beta/" +
                "admin/windows/updates/deployments"
            ) `
            -AllowFailure
    )

    Export-JsonFile `
        -InputObject $Deployments `
        -Path (
            Join-Path `
                $OutputDir `
                "06_Deployments_FULL.json"
        )

    $DeploymentSummary = @(
        foreach ($Deployment in $Deployments) {
            [pscustomobject]@{
                Id =
                    $Deployment.id

                CreatedDateTime =
                    $Deployment.createdDateTime

                LastModifiedDateTime =
                    $Deployment.lastModifiedDateTime

                State =
                    $Deployment.state

                Content =
                    ConvertTo-CompactJson `
                        -InputObject $Deployment.content

                Settings =
                    ConvertTo-CompactJson `
                        -InputObject $Deployment.settings

                Audience =
                    ConvertTo-CompactJson `
                        -InputObject $Deployment.audience
            }
        }
    )

    Export-CsvSafe `
        -InputObject $DeploymentSummary `
        -Path (
            Join-Path `
                $OutputDir `
                "06_Deployments.csv"
        )

    Write-Host (
        "  Deploymentteja: " +
        $Deployments.Count
    ) -ForegroundColor Green
}
catch {
    Add-AuditError `
        -Section "Windows Update Deployments" `
        -Message $_.Exception.Message

    Write-Warning (
        "Deployment-haku epäonnistui: " +
        $_.Exception.Message
    )
}

# ------------------------------------------------------------
# Kohdistusten vienti
# ------------------------------------------------------------

$SortedAssignments = @(
    $AllAssignments |
        Sort-Object `
            ProfileType,
            ProfileName,
            AssignmentType,
            GroupName
)

Export-CsvSafe `
    -InputObject $SortedAssignments `
    -Path (
        Join-Path `
            $OutputDir `
            "00_AllAssignments.csv"
    )

Export-JsonFile `
    -InputObject $SortedAssignments `
    -Path (
        Join-Path `
            $OutputDir `
            "00_AllAssignments_FULL.json"
    )

# ------------------------------------------------------------
# Automaattiset havainnot
# ------------------------------------------------------------

foreach ($Ring in @($UpdateRingSummary)) {
    if (
        $null -ne $Ring.FeatureUpdatesDeferralDays -and
        [int]$Ring.FeatureUpdatesDeferralDays -gt 0
    ) {
        $Findings.Add(
            [pscustomobject]@{
                Severity = "Warning"
                Category = "Update Ring"
                Profile  = $Ring.Name

                Finding =
                    "Feature Update -viive on " +
                    "$($Ring.FeatureUpdatesDeferralDays) päivää."

                Recommendation =
                    "Jos käytössä on erillinen Feature Update " +
                    "-profiili, tarkista pitäisikö viiveen olla " +
                    "0 päivää."
            }
        )
    }

    if (
        $null -ne $Ring.QualityUpdatesDeferralDays -and
        [int]$Ring.QualityUpdatesDeferralDays -gt 14
    ) {
        $Findings.Add(
            [pscustomobject]@{
                Severity = "Info"
                Category = "Update Ring"
                Profile  = $Ring.Name

                Finding =
                    "Quality Update -viive on " +
                    "$($Ring.QualityUpdatesDeferralDays) päivää."

                Recommendation =
                    "Tarkista, vastaako viive organisaation " +
                    "tietoturva- ja päivityskäytäntöä."
            }
        )
    }

    if (
        $null -eq $Ring.DeadlineForFeatureUpdatesDays
    ) {
        $Findings.Add(
            [pscustomobject]@{
                Severity = "Info"
                Category = "Update Ring"
                Profile  = $Ring.Name

                Finding =
                    "Feature Update -deadlinea ei havaittu."

                Recommendation =
                    "Tarkista, onko deadline tarkoituksella " +
                    "määrittämättä."
            }
        )
    }

    if (
        $null -eq $Ring.DeadlineForQualityUpdatesDays
    ) {
        $Findings.Add(
            [pscustomobject]@{
                Severity = "Info"
                Category = "Update Ring"
                Profile  = $Ring.Name

                Finding =
                    "Quality Update -deadlinea ei havaittu."

                Recommendation =
                    "Tarkista, onko deadline tarkoituksella " +
                    "määrittämättä."
            }
        )
    }
}

foreach ($Profile in @($FeatureSummary)) {
    if (
        $Profile.InstallFeatureUpdatesOptional -eq $true
    ) {
        $Findings.Add(
            [pscustomobject]@{
                Severity = "Warning"
                Category = "Feature Update"
                Profile  = $Profile.Name

                Finding =
                    "Feature Update on määritetty " +
                    "vapaaehtoiseksi."

                Recommendation =
                    "Käyttäjän täytyy itse aloittaa päivitys. " +
                    "Tarkista, pitäisikö jakelun olla Required."
            }
        )
    }
}

$ProfilesWithoutAssignments = @(
    $AllAssignments |
        Where-Object {
            $_.AssignmentType -eq "Ei kohdistuksia"
        }
)

foreach (
    $Assignment in $ProfilesWithoutAssignments
) {
    $Findings.Add(
        [pscustomobject]@{
            Severity = "Info"
            Category = $Assignment.ProfileType
            Profile  = $Assignment.ProfileName

            Finding =
                "Profiililla ei ole kohdistuksia."

            Recommendation =
                "Tarkista, onko profiili vanha, keskeneräinen " +
                "tai tarkoituksella ilman kohdistusta."
        }
    )
}

# Samalle ryhmälle tai All Devices / All Users -kohteelle
# kohdistuvat useat Update Ringit.

$DuplicateRingTargets = @(
    $AllAssignments |
        Where-Object {
            $_.ProfileType -eq "Update Ring" -and
            $_.AssignmentType -in @(
                "Include Group",
                "All Devices",
                "All Users"
            )
        } |
        Group-Object `
            GroupId,
            GroupName,
            AssignmentType |
        Where-Object {
            $_.Count -gt 1
        }
)

foreach ($Target in $DuplicateRingTargets) {
    $ProfileNames = @(
        $Target.Group |
            Select-Object `
                -ExpandProperty ProfileName `
                -Unique
    )

    $TargetName =
        if ($Target.Group[0].GroupName) {
            $Target.Group[0].GroupName
        }
        else {
            $Target.Group[0].AssignmentType
        }

    $Findings.Add(
        [pscustomobject]@{
            Severity = "Warning"
            Category = "Assignments"
            Profile  = ($ProfileNames -join ", ")

            Finding =
                "Samaan kohteeseen '$TargetName' kohdistuu " +
                "useita Update Ringejä."

            Recommendation =
                "Vertaa asetuksia ja varmista, etteivät samat " +
                "asetukset saa ristiriitaisia arvoja."
        }
    )
}

foreach ($AuditError in @($Errors)) {
    $Findings.Add(
        [pscustomobject]@{
            Severity = "Error"
            Category = $AuditError.Section
            Profile  = ""
            Finding  = $AuditError.Error

            Recommendation =
                "Tarkista Graph-oikeudet, endpoint ja virheen " +
                "tarkemmat tiedot."
        }
    )
}

if ($Findings.Count -eq 0) {
    $Findings.Add(
        [pscustomobject]@{
            Severity = "OK"
            Category = "Audit"
            Profile  = ""

            Finding =
                "Automaattinen tarkistus ei havainnut " +
                "huomautettavaa."

            Recommendation =
                "Tarkista silti kohdistukset ja organisaation " +
                "omat vaatimukset."
        }
    )
}

$SortedFindings = @(
    $Findings |
        Sort-Object `
            @{ Expression = {
                switch ($_.Severity) {
                    "Error"   { 1 }
                    "Warning" { 2 }
                    "Info"    { 3 }
                    "OK"      { 4 }
                    default   { 5 }
                }
            }},
            Category,
            Profile
)

Export-CsvSafe `
    -InputObject $SortedFindings `
    -Path (
        Join-Path `
            $OutputDir `
            "00_Findings.csv"
    )

Export-JsonFile `
    -InputObject $SortedFindings `
    -Path (
        Join-Path `
            $OutputDir `
            "00_Findings_FULL.json"
    )

# ------------------------------------------------------------
# Mahdolliset virheet
# ------------------------------------------------------------

Export-CsvSafe `
    -InputObject @($Errors) `
    -Path (
        Join-Path `
            $OutputDir `
            "99_Errors.csv"
    )

Export-JsonFile `
    -InputObject @($Errors) `
    -Path (
        Join-Path `
            $OutputDir `
            "99_Errors_FULL.json"
    )

# ------------------------------------------------------------
# HTML-taulukot
# ------------------------------------------------------------

Write-Host ""
Write-Host "Luodaan HTML-raportti..." `
    -ForegroundColor Yellow

$HtmlReportPath =
    Join-Path `
        $OutputDir `
        "Intune_Windows_Update_Audit.html"

$FindingsTable = New-HtmlTable `
    -Data $SortedFindings `
    -Properties @(
        "Severity",
        "Category",
        "Profile",
        "Finding",
        "Recommendation"
    )

$UpdateRingsTable = New-HtmlTable `
    -Data $UpdateRingSummary `
    -Properties @(
        "Name",
        "Description",
        "QualityUpdatesDeferralDays",
        "FeatureUpdatesDeferralDays",
        "QualityUpdatesPauseStartDate",
        "FeatureUpdatesPauseStartDate",
        "DriversExcluded",
        "MicrosoftUpdateServiceAllowed",
        "AutomaticUpdateMode",
        "BusinessReadyUpdatesOnly",
        "ActiveHoursStart",
        "ActiveHoursEnd",
        "UserPauseAccess",
        "UserWindowsUpdateScanAccess",
        "UpdateNotificationLevel",
        "FeatureUpdatesRollbackWindowDays",
        "DeadlineForQualityUpdatesDays",
        "DeadlineForFeatureUpdatesDays",
        "DeadlineGracePeriodDays",
        "DeadlineNoAutoReboot",
        "AutoRestartNotificationDismissal",
        "ScheduleRestartWarningHours",
        "ScheduleImminentRestartWarningMinutes",
        "EngagedRestartDeadlineDays",
        "EngagedRestartSnoozeScheduleDays",
        "EngagedRestartTransitionScheduleDays",
        "CreatedDateTime",
        "LastModifiedDateTime",
        "Id"
    )

$FeatureUpdatesTable = New-HtmlTable `
    -Data $FeatureSummary `
    -Properties @(
        "Name",
        "Description",
        "FeatureUpdateVersion",
        "InstallFeatureUpdatesOptional",
        "InstallLatestWindows10OnWindows11IneligibleDevice",
        "RolloutSettings",
        "CreatedDateTime",
        "LastModifiedDateTime",
        "Id"
    )

$QualityUpdatesTable = New-HtmlTable `
    -Data $QualitySummary `
    -Properties @(
        "Name",
        "Description",
        "ExpeditedUpdateSettings",
        "CreatedDateTime",
        "LastModifiedDateTime",
        "Id"
    )

$DriverUpdatesTable = New-HtmlTable `
    -Data $DriverSummary `
    -Properties @(
        "Name",
        "Description",
        "ApprovalType",
        "DeploymentDeferralInDays",
        "DeviceReporting",
        "InventorySyncStatus",
        "CreatedDateTime",
        "LastModifiedDateTime",
        "Id"
    )

$DriverInventoryTable = New-HtmlTable `
    -Data $AllDriverInventory `
    -Properties @(
        "ProfileName",
        "Name",
        "Version",
        "Manufacturer",
        "ReleaseDateTime",
        "DriverClass",
        "ApplicableDeviceCount",
        "ApprovalStatus",
        "Category",
        "DeployDateTime",
        "DriverId",
        "ProfileId"
    ) `
    -EmptyMessage "Ajuri-inventaariota ei löytynyt."

$AssignmentsTable = New-HtmlTable `
    -Data $SortedAssignments `
    -Properties @(
        "ProfileType",
        "ProfileName",
        "AssignmentType",
        "GroupName",
        "GroupId",
        "FilterType",
        "FilterId",
        "TargetODataType",
        "ProfileId"
    )

$ReleasesTable = New-HtmlTable `
    -Data $CatalogSummary `
    -Properties @(
        "DisplayName",
        "Version",
        "BuildNumber",
        "ReleaseDateTime",
        "DeployableUntilDateTime",
        "QualityUpdateClassification",
        "IsExpeditable",
        "CatalogName",
        "ODataType",
        "Id"
    )

$DeploymentsTable = New-HtmlTable `
    -Data $DeploymentSummary `
    -Properties @(
        "Id",
        "State",
        "CreatedDateTime",
        "LastModifiedDateTime",
        "Content",
        "Settings",
        "Audience"
    )

$ErrorsTable = New-HtmlTable `
    -Data @($Errors) `
    -Properties @(
        "Section",
        "Error"
    ) `
    -EmptyMessage (
        "Auditoinnissa ei havaittu Graph-hakuvirheitä."
    )

# ------------------------------------------------------------
# Raportin metadata
# ------------------------------------------------------------

$GeneratedAt =
    Get-Date -Format "dd.MM.yyyy HH:mm:ss"

$TenantId =
    ConvertTo-HtmlSafe $GraphContext.TenantId

$Account =
    ConvertTo-HtmlSafe $GraphContext.Account

$OutputDirectoryHtml =
    ConvertTo-HtmlSafe $OutputDir

$ReportTitle =
    "Intune Windows Update -auditointi"

$Html = @"
<!DOCTYPE html>
<html lang="fi">
<head>
    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1">

    <title>$ReportTitle</title>

    <style>
        :root {
            --bg: #0b1020;
            --panel: #131a2c;
            --panel-alt: #182238;
            --border: #2a3653;
            --text: #edf2ff;
            --muted: #aab6d3;
            --accent: #6da8ff;
            --ok: #4fd18b;
            --warning: #f4c75b;
            --error: #ff7272;
        }

        * {
            box-sizing: border-box;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            margin: 0;

            background:
                radial-gradient(
                    circle at top right,
                    #1a3157 0,
                    transparent 32rem
                ),
                var(--bg);

            color: var(--text);

            font-family:
                "Segoe UI",
                Arial,
                sans-serif;
        }

        header {
            padding: 32px;

            border-bottom:
                1px solid var(--border);

            background:
                rgba(11, 16, 32, 0.92);
        }

        header h1 {
            margin: 0 0 8px;
            font-size: 30px;
        }

        header p {
            margin: 4px 0;
            color: var(--muted);
        }

        main {
            max-width: 1900px;
            margin: 0 auto;
            padding: 24px;
        }

        .toolbar {
            position: sticky;
            top: 0;
            z-index: 50;

            display: flex;
            gap: 12px;
            flex-wrap: wrap;

            padding: 14px;
            margin-bottom: 20px;

            border:
                1px solid var(--border);

            border-radius: 12px;

            background:
                rgba(19, 26, 44, 0.97);

            backdrop-filter:
                blur(10px);
        }

        .toolbar input {
            min-width: 320px;
            flex: 1;

            padding: 11px 13px;

            border:
                1px solid var(--border);

            border-radius: 8px;

            background: #0d1425;
            color: var(--text);
        }

        .toolbar button,
        .toolbar a {
            padding: 10px 14px;

            border:
                1px solid var(--border);

            border-radius: 8px;

            background: var(--panel-alt);
            color: var(--text);

            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
        }

        .toolbar button:hover,
        .toolbar a:hover {
            border-color: var(--accent);
        }

        .cards {
            display: grid;

            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(180px, 1fr)
                );

            gap: 14px;
            margin-bottom: 24px;
        }

        .card {
            padding: 18px;

            border:
                1px solid var(--border);

            border-radius: 12px;

            background:
                linear-gradient(
                    145deg,
                    var(--panel-alt),
                    var(--panel)
                );
        }

        .card .value {
            display: block;

            margin-bottom: 6px;

            font-size: 30px;
            font-weight: 700;
            color: var(--accent);
        }

        .card .label {
            color: var(--muted);
        }

        nav {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;

            margin-bottom: 24px;
        }

        nav a {
            padding: 9px 12px;

            border:
                1px solid var(--border);

            border-radius: 8px;

            background: var(--panel);
            color: var(--accent);

            text-decoration: none;
        }

        nav a:hover {
            border-color: var(--accent);
        }

        section {
            margin-bottom: 24px;
            padding: 20px;

            border:
                1px solid var(--border);

            border-radius: 12px;

            background:
                rgba(19, 26, 44, 0.96);

            scroll-margin-top: 90px;
        }

        section h2 {
            margin: 0 0 16px;
            font-size: 21px;
        }

        .table-wrap {
            overflow-x: auto;

            border:
                1px solid var(--border);

            border-radius: 9px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        th {
            position: sticky;
            top: 0;

            padding: 11px;

            text-align: left;
            white-space: nowrap;

            background: #1c2943;
            color: #ffffff;

            cursor: pointer;
        }

        th::after {
            content: " ↕";
            opacity: 0.45;
            font-size: 11px;
        }

        th[data-direction="asc"]::after {
            content: " ↑";
            opacity: 1;
        }

        th[data-direction="desc"]::after {
            content: " ↓";
            opacity: 1;
        }

        td {
            padding: 10px 11px;

            border-top:
                1px solid var(--border);

            vertical-align: top;
            word-break: break-word;
        }

        tr:nth-child(even) td {
            background:
                rgba(255, 255, 255, 0.025);
        }

        tr:hover td {
            background:
                rgba(109, 168, 255, 0.08);
        }

        .empty {
            padding: 18px;
            color: var(--muted);
        }

        .links {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .links a {
            display: inline-block;

            padding: 9px 12px;

            border:
                1px solid var(--border);

            border-radius: 8px;

            color: var(--accent);
            text-decoration: none;

            background: var(--panel-alt);
        }

        .links a:hover {
            border-color: var(--accent);
        }

        .hidden {
            display: none !important;
        }

        footer {
            padding: 20px 24px 40px;
            color: var(--muted);
            text-align: center;
        }

        @media print {
            body {
                background: white;
                color: black;
            }

            .toolbar,
            nav,
            .links {
                display: none;
            }

            section,
            .card {
                break-inside: avoid;
                background: white;
                border-color: #cccccc;
            }

            th {
                position: static;
                background: #eeeeee;
                color: black;
            }

            td {
                border-color: #dddddd;
            }
        }
    </style>
</head>

<body>

<header>
    <h1>Intune Windows Update -auditointi</h1>

    <p>
        READ-ONLY-raportti.
        Tenanttiin ei tehty muutoksia.
    </p>

    <p>
        Luotu: $GeneratedAt
        |
        Tenant: $TenantId
        |
        Käyttäjä: $Account
    </p>

    <p>
        Tuloshakemisto:
        $OutputDirectoryHtml
    </p>
</header>

<main>

    <div class="toolbar">
        <input
            id="globalSearch"
            type="search"
            placeholder="Hae kaikista taulukoista...">

        <button
            type="button"
            onclick="clearSearch()">
            Tyhjennä haku
        </button>

        <button
            type="button"
            onclick="window.print()">
            Tulosta / PDF
        </button>

        <a href="#findings">
            Havainnot
        </a>

        <a href="#assignments">
            Kohdistukset
        </a>
    </div>

    <div class="cards">

        <div class="card">
            <span class="value">
                $(@($UpdateRings).Count)
            </span>

            <span class="label">
                Update Ringit
            </span>
        </div>

        <div class="card">
            <span class="value">
                $(@($FeatureProfiles).Count)
            </span>

            <span class="label">
                Feature Update -profiilit
            </span>
        </div>

        <div class="card">
            <span class="value">
                $(@($QualityProfiles).Count)
            </span>

            <span class="label">
                Quality Update -profiilit
            </span>
        </div>

        <div class="card">
            <span class="value">
                $(@($DriverProfiles).Count)
            </span>

            <span class="label">
                Driver Update -profiilit
            </span>
        </div>

        <div class="card">
            <span class="value">
                $(@($CatalogEntries).Count)
            </span>

            <span class="label">
                Release-catalog entries
            </span>
        </div>

        <div class="card">
            <span class="value">
                $(@($Deployments).Count)
            </span>

            <span class="label">
                Deploymentit
            </span>
        </div>

        <div class="card">
            <span class="value">
                $(@($AllAssignments).Count)
            </span>

            <span class="label">
                Kohdistukset
            </span>
        </div>

        <div class="card">
            <span class="value">
                $(@($AllDriverInventory).Count)
            </span>

            <span class="label">
                Ajuri-inventaarion rivit
            </span>
        </div>

        <div class="card">
            <span class="value">
                $(@($Findings).Count)
            </span>

            <span class="label">
                Havainnot
            </span>
        </div>

        <div class="card">
            <span class="value">
                $(@($Errors).Count)
            </span>

            <span class="label">
                Hakuvirheet
            </span>
        </div>

    </div>

    <nav>
        <a href="#findings">
            Havainnot
        </a>

        <a href="#rings">
            Update Ringit
        </a>

        <a href="#feature">
            Feature Updates
        </a>

        <a href="#quality">
            Quality Updates
        </a>

        <a href="#drivers">
            Driver Updates
        </a>

        <a href="#driver-inventory">
            Ajuri-inventaario
        </a>

        <a href="#assignments">
            Kohdistukset
        </a>

        <a href="#releases">
            Releases
        </a>

        <a href="#deployments">
            Deploymentit
        </a>

        <a href="#errors">
            Virheet
        </a>

        <a href="#files">
            Tiedostot
        </a>
    </nav>

    <section id="findings">
        <h2>Automaattiset havainnot</h2>

        <div class="table-wrap">
            $FindingsTable
        </div>
    </section>

    <section id="rings">
        <h2>Update Ringit</h2>

        <div class="table-wrap">
            $UpdateRingsTable
        </div>
    </section>

    <section id="feature">
        <h2>Feature Update -profiilit</h2>

        <div class="table-wrap">
            $FeatureUpdatesTable
        </div>
    </section>

    <section id="quality">
        <h2>Quality Update -profiilit</h2>

        <div class="table-wrap">
            $QualityUpdatesTable
        </div>
    </section>

    <section id="drivers">
        <h2>Driver Update -profiilit</h2>

        <div class="table-wrap">
            $DriverUpdatesTable
        </div>
    </section>

    <section id="driver-inventory">
        <h2>Driver Update -inventaario</h2>

        <div class="table-wrap">
            $DriverInventoryTable
        </div>
    </section>

    <section id="assignments">
        <h2>Kaikki kohdistukset</h2>

        <div class="table-wrap">
            $AssignmentsTable
        </div>
    </section>

    <section id="releases">
        <h2>Windows Update Releases / catalog</h2>

        <div class="table-wrap">
            $ReleasesTable
        </div>
    </section>

    <section id="deployments">
        <h2>Windows Update -deploymentit</h2>

        <div class="table-wrap">
            $DeploymentsTable
        </div>
    </section>

    <section id="errors">
        <h2>Auditoinnin virheet</h2>

        <div class="table-wrap">
            $ErrorsTable
        </div>
    </section>

    <section id="files">
        <h2>Raakadata ja CSV-tiedostot</h2>

        <div class="links">
            <a href="00_Findings.csv">
                Havainnot CSV
            </a>

            <a href="00_AllAssignments.csv">
                Kaikki kohdistukset CSV
            </a>

            <a href="01_UpdateRings.csv">
                Update Ringit CSV
            </a>

            <a href="01_UpdateRings_FULL.json">
                Update Ringit JSON
            </a>

            <a href="02_FeatureUpdates.csv">
                Feature Updates CSV
            </a>

            <a href="02_FeatureUpdates_FULL.json">
                Feature Updates JSON
            </a>

            <a href="03_QualityUpdates.csv">
                Quality Updates CSV
            </a>

            <a href="03_QualityUpdates_FULL.json">
                Quality Updates JSON
            </a>

            <a href="04_DriverUpdates.csv">
                Driver Updates CSV
            </a>

            <a href="04_DriverUpdates_FULL.json">
                Driver Updates JSON
            </a>

            <a href="04_AllDriverInventory.csv">
                Ajuri-inventaario CSV
            </a>

            <a href="05_Releases_Catalog.csv">
                Releases CSV
            </a>

            <a href="05_Releases_Catalog_FULL.json">
                Releases JSON
            </a>

            <a href="06_Deployments.csv">
                Deploymentit CSV
            </a>

            <a href="06_Deployments_FULL.json">
                Deploymentit JSON
            </a>

            <a href="99_Errors.csv">
                Virheet CSV
            </a>
        </div>
    </section>

</main>

<footer>
    Intune Windows Update -auditointi
    |
    READ-ONLY
    |
    $GeneratedAt
</footer>

<script>
    const searchInput =
        document.getElementById("globalSearch");

    searchInput.addEventListener(
        "input",
        function () {
            const query =
                this.value
                    .toLowerCase()
                    .trim();

            document
                .querySelectorAll(
                    "table tbody tr"
                )
                .forEach(
                    function (row) {
                        const text =
                            row.innerText
                                .toLowerCase();

                        row.classList.toggle(
                            "hidden",
                            query.length > 0 &&
                            !text.includes(query)
                        );
                    }
                );
        }
    );

    function clearSearch() {
        searchInput.value = "";

        document
            .querySelectorAll(
                "table tbody tr"
            )
            .forEach(
                function (row) {
                    row.classList.remove(
                        "hidden"
                    );
                }
            );

        searchInput.focus();
    }

    document
        .querySelectorAll("table")
        .forEach(
            function (table) {
                const headers =
                    table.querySelectorAll("th");

                headers.forEach(
                    function (header, index) {
                        header.addEventListener(
                            "click",
                            function () {
                                const body =
                                    table.querySelector(
                                        "tbody"
                                    );

                                if (!body) {
                                    return;
                                }

                                const rows =
                                    Array.from(
                                        body.querySelectorAll(
                                            "tr"
                                        )
                                    );

                                const currentDirection =
                                    header.dataset.direction ||
                                    "desc";

                                const nextDirection =
                                    currentDirection === "asc"
                                        ? "desc"
                                        : "asc";

                                headers.forEach(
                                    function (item) {
                                        delete item.dataset
                                            .direction;
                                    }
                                );

                                header.dataset.direction =
                                    nextDirection;

                                rows.sort(
                                    function (a, b) {
                                        const aCell =
                                            a.children[index];

                                        const bCell =
                                            b.children[index];

                                        const aValue =
                                            aCell
                                                ? aCell.innerText
                                                    .trim()
                                                : "";

                                        const bValue =
                                            bCell
                                                ? bCell.innerText
                                                    .trim()
                                                : "";

                                        const aNumber =
                                            Number(aValue);

                                        const bNumber =
                                            Number(bValue);

                                        let result;

                                        if (
                                            !Number.isNaN(
                                                aNumber
                                            ) &&
                                            !Number.isNaN(
                                                bNumber
                                            ) &&
                                            aValue !== "" &&
                                            bValue !== ""
                                        ) {
                                            result =
                                                aNumber -
                                                bNumber;
                                        }
                                        else {
                                            result =
                                                aValue
                                                    .localeCompare(
                                                        bValue,
                                                        "fi",
                                                        {
                                                            numeric:
                                                                true,

                                                            sensitivity:
                                                                "base"
                                                        }
                                                    );
                                        }

                                        return (
                                            nextDirection ===
                                            "asc"
                                        )
                                            ? result
                                            : -result;
                                    }
                                );

                                rows.forEach(
                                    function (row) {
                                        body.appendChild(row);
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );
</script>

</body>
</html>
"@

$Html |
    Set-Content `
        -Path $HtmlReportPath `
        -Encoding UTF8

Write-Host `
    "  HTML-raportti: $HtmlReportPath" `
    -ForegroundColor Green

# ------------------------------------------------------------
# Konsoliyhteenveto
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Cyan

Write-Host " AUDITOINNIN YHTEENVETO" `
    -ForegroundColor Cyan

Write-Host "============================================================" `
    -ForegroundColor Cyan

[pscustomobject]@{
    UpdateRings =
        @($UpdateRings).Count

    FeatureUpdates =
        @($FeatureProfiles).Count

    QualityUpdates =
        @($QualityProfiles).Count

    DriverUpdates =
        @($DriverProfiles).Count

    DriverInventoryRows =
        @($AllDriverInventory).Count

    ReleaseCatalogItems =
        @($CatalogEntries).Count

    Deployments =
        @($Deployments).Count

    Assignments =
        @($AllAssignments).Count

    Findings =
        @($Findings).Count

    Errors =
        @($Errors).Count

    OutputDirectory =
        $OutputDir

    HtmlReport =
        $HtmlReportPath
} | Format-List

Write-Host "Kohdistukset:" `
    -ForegroundColor Cyan

if (@($SortedAssignments).Count -gt 0) {
    $SortedAssignments |
        Format-Table `
            ProfileType,
            ProfileName,
            AssignmentType,
            GroupName,
            FilterType `
            -AutoSize
}
else {
    Write-Host "Ei kohdistuksia." `
        -ForegroundColor DarkGray
}

Write-Host ""
Write-Host (
    "Auditointi valmis. " +
    "Mitään tenantin asetuksia ei muutettu."
) -ForegroundColor Green

Write-Host "Tulokset: $OutputDir" `
    -ForegroundColor Green

Write-Host ""

if (-not $DoNotOpenReport) {
    if (Test-Path $HtmlReportPath) {
        Start-Process `
            -FilePath $HtmlReportPath
    }
    else {
        Write-Warning (
            "HTML-raporttia ei löytynyt: " +
            $HtmlReportPath
        )
    }
}
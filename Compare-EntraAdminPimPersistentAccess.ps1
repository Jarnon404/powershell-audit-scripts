<#
.SYNOPSIS
    Entra Admins PIM vs Persistent Access Audit.

.DESCRIPTION
    Vertaa Entra ID -adminroolien aktiivisia oikeuksia PIM eligibility/active schedule -tietoihin ja tunnistaa pysyviä admin-oikeuksia.

.REQUIREMENTS
    - Microsoft Graph PowerShell -moduulit ja roolihallinnan lukuoikeudet

.OUTPUTS
    - CSV/HTML-raportti PIM- ja persistent-oikeuksista

.EXAMPLE
    .\Compare-EntraAdminPimPersistentAccess.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Compare-EntraAdminPimPersistentAccess.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

<#
.SYNOPSIS
    Entra Admins - PIM vs Persistent Active Assignments Audit

.DESCRIPTION
    Read-only report for Entra ID directory roles.

    Collects:
    - Directory role definitions
    - Active role assignments
    - PIM eligible schedule instances
    - PIM active assignment schedule instances
    - Compares active admin assignments against PIM datasets
    - Identifies likely Persistent / non-PIM active admin assignments

.NOTES
    Avoids importing the full Microsoft.Graph meta-module because Windows PowerShell
    can hit "function capacity 4096 has been exceeded".

    Uses only:
    - Microsoft.Graph.Authentication
    - Connect-MgGraph
    - Invoke-MgGraphRequest

.REQUIRED GRAPH SCOPES
    RoleManagement.Read.Directory
    Directory.Read.All
    RoleEligibilitySchedule.Read.Directory
    RoleAssignmentSchedule.Read.Directory

.READONLY
    Yes. Only GET/POST read endpoints are used.
    POST is used only for directoryObjects/getByIds lookup, not modification.
#>

$ErrorActionPreference = "Stop"

# =========================================================
# BASIC SETTINGS
# =========================================================

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$BaseDir   = Join-Path -Path (Get-Location) -ChildPath "Entra-PIM-vs-Persistent-$Timestamp"

New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null

$OutAll        = Join-Path $BaseDir "Entra-ActiveAdmins-Compared-$Timestamp.csv"
$OutPersistent = Join-Path $BaseDir "Entra-PersistentAdmins-$Timestamp.csv"
$OutEligible   = Join-Path $BaseDir "Entra-PIM-Eligible-$Timestamp.csv"
$OutSummary    = Join-Path $BaseDir "Entra-Summary-$Timestamp.csv"

# =========================================================
# CLEAN CURRENT POWERSHELL TAB / SESSION ONLY
# =========================================================

Write-Host "Cleaning current Microsoft Graph session in this PowerShell tab only..." -ForegroundColor DarkGray

try {
    if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
catch {
    Write-Warning "Disconnect-MgGraph cleanup warning: $($_.Exception.Message)"
}

try {
    Get-Module Microsoft.Graph* | Remove-Module -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Microsoft.Graph module cleanup warning: $($_.Exception.Message)"
}

# =========================================================
# MODULE LOAD - ONLY AUTHENTICATION MODULE
# =========================================================

Write-Host "Loading Microsoft.Graph.Authentication only..." -ForegroundColor Cyan

try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
}
catch {
    Write-Host "Microsoft.Graph.Authentication module missing or failed to load." -ForegroundColor Yellow
    Write-Host "Try reinstalling it with:" -ForegroundColor Yellow
    Write-Host "Uninstall-Module Microsoft.Graph.Authentication -AllVersions -Force" -ForegroundColor Green
    Write-Host "Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber" -ForegroundColor Green
    throw
}

# =========================================================
# CONNECT
# =========================================================

$Scopes = @(
    "RoleManagement.Read.Directory",
    "Directory.Read.All",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleAssignmentSchedule.Read.Directory"
)

Write-Host "Connecting to Microsoft Graph with script-required read scopes only..." -ForegroundColor Cyan

Connect-MgGraph `
    -Scopes $Scopes `
    -NoWelcome `
    -UseDeviceAuthentication `
    -ContextScope Process | Out-Null

$Context = Get-MgContext

Write-Host ""
Write-Host "Connected as: $($Context.Account)" -ForegroundColor Green
Write-Host "TenantId    : $($Context.TenantId)" -ForegroundColor Green
Write-Host "ClientId    : $($Context.ClientId)" -ForegroundColor Green
Write-Host "AuthType    : $($Context.AuthType)" -ForegroundColor Green
Write-Host "Scope mode  : $($Context.ContextScope)" -ForegroundColor Green
Write-Host ""

# =========================================================
# GRAPH SCOPE CHECK
# =========================================================

$ExpectedScopes = @(
    "RoleManagement.Read.Directory",
    "Directory.Read.All",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleAssignmentSchedule.Read.Directory"
)

$ActualScopes = @($Context.Scopes | Sort-Object -Unique)

$UnexpectedScopes = @(
    $ActualScopes | Where-Object {
        $_ -notin $ExpectedScopes -and
        $_ -notin @("openid", "profile", "email", "offline_access", "User.Read")
    }
)

$MissingScopes = @(
    $ExpectedScopes | Where-Object {
        $_ -notin $ActualScopes
    }
)

Write-Host "=== Graph scope check ===" -ForegroundColor Cyan
Write-Host "Expected script scopes:" -ForegroundColor DarkGray
$ExpectedScopes | ForEach-Object { Write-Host " - $_" -ForegroundColor DarkGray }

Write-Host ""
Write-Host "Actual token scopes:" -ForegroundColor DarkGray
$ActualScopes | ForEach-Object { Write-Host " - $_" -ForegroundColor DarkGray }

if ($MissingScopes.Count -gt 0) {
    Write-Host ""
    Write-Host "WARNING: Missing required scope(s):" -ForegroundColor Yellow
    $MissingScopes | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }
    throw "Missing required Microsoft Graph scope(s). Cannot continue safely."
}

if ($UnexpectedScopes.Count -gt 0) {
    Write-Host ""
    Write-Host "WARNING: Token contains extra scope(s) not required by this script:" -ForegroundColor Yellow
    $UnexpectedScopes | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }

    Write-Host ""
    Write-Host "The script itself is still read-only, but this PowerShell Graph token has broader delegated permissions than needed." -ForegroundColor Yellow
    Write-Host "Because apparently even permissions need to arrive with extra luggage." -ForegroundColor DarkYellow
}
else {
    Write-Host ""
    Write-Host "Scope check OK. No unexpected Graph scopes detected." -ForegroundColor Green
}

Write-Host ""

# =========================================================
# HELPERS
# =========================================================

function Get-GraphAllPages {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$Activity = "Graph query"
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $page = 0

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $page++

        Write-Progress `
            -Activity $Activity `
            -Status "Loading page $page..." `
            -PercentComplete -1

        $response = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop

        if ($response.value) {
            foreach ($item in @($response.value)) {
                $items.Add($item) | Out-Null
            }
        }

        $next = $null

        if ($response -is [hashtable]) {
            if ($response.ContainsKey("@odata.nextLink")) {
                $next = $response["@odata.nextLink"]
            }
        }
        elseif ($response.PSObject.Properties.Name -contains "@odata.nextLink") {
            $next = $response.'@odata.nextLink'
        }
    }

    Write-Progress -Activity $Activity -Completed

    return $items
}

function New-Key {
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId,
        [string]$AppScopeId
    )

    $ds = if ([string]::IsNullOrWhiteSpace($DirectoryScopeId)) { "" } else { $DirectoryScopeId }
    $as = if ([string]::IsNullOrWhiteSpace($AppScopeId)) { "" } else { $AppScopeId }

    return "$PrincipalId|$RoleDefinitionId|$ds|$as"
}

function Get-PropValue {
    param(
        [Parameter(Mandatory)]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object.PSObject.Properties.Name -contains $Name) {
        return $Object.$Name
    }

    if ($Object -is [hashtable] -and $Object.ContainsKey($Name)) {
        return $Object[$Name]
    }

    return $null
}

function Get-PrincipalTypeFromOData {
    param([string]$ODataType)

    if ([string]::IsNullOrWhiteSpace($ODataType)) {
        return "Unknown"
    }

    return ($ODataType -replace "#microsoft.graph.", "")
}

function Split-Array {
    param(
        [object[]]$InputArray,

        [int]$ChunkSize = 1000
    )

    if ($null -eq $InputArray -or $InputArray.Count -eq 0) {
        return @()
    }

    for ($i = 0; $i -lt $InputArray.Count; $i += $ChunkSize) {
        $end = [Math]::Min($i + $ChunkSize - 1, $InputArray.Count - 1)
        ,$InputArray[$i..$end]
    }
}

# =========================================================
# PHASE 1 - ROLE DEFINITIONS
# =========================================================

Write-Host "Loading role definitions..." -ForegroundColor Cyan

$RoleDefinitionsUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,description"
$RoleDefs = Get-GraphAllPages -Uri $RoleDefinitionsUri -Activity "Loading role definitions"

$RoleDefMap = @{}

foreach ($rd in $RoleDefs) {
    $id = Get-PropValue -Object $rd -Name "id"
    $displayName = Get-PropValue -Object $rd -Name "displayName"

    if ($id) {
        $RoleDefMap[$id] = $displayName
    }
}

Write-Host "Role definitions loaded: $($RoleDefs.Count)" -ForegroundColor Green

# =========================================================
# PHASE 2 - ACTIVE ROLE ASSIGNMENTS
# =========================================================

Write-Host "Loading ACTIVE role assignments..." -ForegroundColor Cyan

# NOTE:
# Do not include appScopeId here.
# In this endpoint/type Graph may reject it with:
# "Could not find a property named 'appScopeId' on type 'Microsoft.DirectoryServices.RoleAssignment'."
$ActiveAssignmentsUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$select=id,principalId,roleDefinitionId,directoryScopeId"
$ActiveAssignments = Get-GraphAllPages -Uri $ActiveAssignmentsUri -Activity "Loading active role assignments"

Write-Host "Active role assignments loaded: $($ActiveAssignments.Count)" -ForegroundColor Green

# =========================================================
# PHASE 3 - PIM ELIGIBLE SCHEDULE INSTANCES
# =========================================================

Write-Host "Loading PIM ELIGIBLE schedule instances..." -ForegroundColor Cyan

$EligibleUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$select=id,principalId,roleDefinitionId,directoryScopeId,appScopeId,memberType,startDateTime,endDateTime"
$EligibleInstances = Get-GraphAllPages -Uri $EligibleUri -Activity "Loading PIM eligible schedule instances"

Write-Host "PIM eligible instances loaded: $($EligibleInstances.Count)" -ForegroundColor Green

# =========================================================
# PHASE 4 - PIM ACTIVE ASSIGNMENT SCHEDULE INSTANCES
# =========================================================

Write-Host "Loading PIM ACTIVE assignment schedule instances..." -ForegroundColor Cyan

$ActiveScheduleUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$select=id,principalId,roleDefinitionId,directoryScopeId,appScopeId,memberType,assignmentType,startDateTime,endDateTime"
$ActiveScheduleInstances = Get-GraphAllPages -Uri $ActiveScheduleUri -Activity "Loading PIM active assignment schedule instances"

Write-Host "PIM active schedule instances loaded: $($ActiveScheduleInstances.Count)" -ForegroundColor Green

# =========================================================
# PHASE 5 - BUILD PIM INDEXES
# =========================================================

Write-Host "Indexing PIM datasets..." -ForegroundColor Cyan

$PimEligibleKeys = [System.Collections.Generic.HashSet[string]]::new()
$PimActiveKeys   = [System.Collections.Generic.HashSet[string]]::new()
$PimActiveMeta   = @{}
$PimEligibleMeta = @{}

foreach ($e in $EligibleInstances) {
    $principalId      = Get-PropValue -Object $e -Name "principalId"
    $roleDefinitionId = Get-PropValue -Object $e -Name "roleDefinitionId"
    $directoryScopeId = Get-PropValue -Object $e -Name "directoryScopeId"
    $appScopeId       = Get-PropValue -Object $e -Name "appScopeId"

$key = New-Key `
    -PrincipalId $principalId `
    -RoleDefinitionId $roleDefinitionId `
    -DirectoryScopeId $directoryScopeId `
    -AppScopeId $appScopeId

$keyWithoutAppScope = New-Key `
    -PrincipalId $principalId `
    -RoleDefinitionId $roleDefinitionId `
    -DirectoryScopeId $directoryScopeId `
    -AppScopeId ""

    $PimEligibleKeys.Add($key) | Out-Null
    $PimEligibleMeta[$key] = $e
}

foreach ($s in $ActiveScheduleInstances) {
    $principalId      = Get-PropValue -Object $s -Name "principalId"
    $roleDefinitionId = Get-PropValue -Object $s -Name "roleDefinitionId"
    $directoryScopeId = Get-PropValue -Object $s -Name "directoryScopeId"
    $appScopeId       = Get-PropValue -Object $s -Name "appScopeId"

    $key = New-Key `
        -PrincipalId $principalId `
        -RoleDefinitionId $roleDefinitionId `
        -DirectoryScopeId $directoryScopeId `
        -AppScopeId $appScopeId

    $PimActiveKeys.Add($key) | Out-Null
    $PimActiveMeta[$key] = $s
}

# =========================================================
# PHASE 6 - COLLECT UNIQUE PRINCIPAL IDS
# =========================================================

Write-Host "Collecting unique principal IDs..." -ForegroundColor Cyan

$PrincipalIds = New-Object System.Collections.Generic.HashSet[string]

foreach ($a in $ActiveAssignments) {
    $id = Get-PropValue -Object $a -Name "principalId"
    if ($id) { $PrincipalIds.Add($id) | Out-Null }
}

foreach ($e in $EligibleInstances) {
    $id = Get-PropValue -Object $e -Name "principalId"
    if ($id) { $PrincipalIds.Add($id) | Out-Null }
}

foreach ($s in $ActiveScheduleInstances) {
    $id = Get-PropValue -Object $s -Name "principalId"
    if ($id) { $PrincipalIds.Add($id) | Out-Null }
}

$PrincipalIdArray = @($PrincipalIds)

Write-Host "Unique principals found: $($PrincipalIdArray.Count)" -ForegroundColor Green

# =========================================================
# PHASE 7 - RESOLVE PRINCIPALS WITH getByIds
# =========================================================

Write-Host "Resolving principals..." -ForegroundColor Cyan

$PrincipalMap = @{}
$Chunks = @(Split-Array -InputArray $PrincipalIdArray -ChunkSize 1000)

$chunkIndex = 0
foreach ($chunk in $Chunks) {
    $chunkIndex++

    Write-Progress `
        -Activity "Resolving principals" `
        -Status "Chunk $chunkIndex / $($Chunks.Count)" `
        -PercentComplete (($chunkIndex / [Math]::Max($Chunks.Count, 1)) * 100)

    $body = @{
        ids = @($chunk)
        types = @(
            "user",
            "group",
            "servicePrincipal"
        )
    } | ConvertTo-Json -Depth 5

    try {
        $response = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/directoryObjects/getByIds" `
            -Body $body `
            -ContentType "application/json"

        foreach ($obj in $response.value) {
            $id = Get-PropValue -Object $obj -Name "id"

            if (-not $id) {
                continue
            }

            $odataType = Get-PropValue -Object $obj -Name "@odata.type"
            $type = Get-PrincipalTypeFromOData -ODataType $odataType

            $displayName = Get-PropValue -Object $obj -Name "displayName"
            $upn         = Get-PropValue -Object $obj -Name "userPrincipalName"
            $mail        = Get-PropValue -Object $obj -Name "mail"
            $appId       = Get-PropValue -Object $obj -Name "appId"

            $PrincipalMap[$id] = [pscustomobject]@{
                PrincipalId       = $id
                PrincipalType     = $type
                DisplayName       = $displayName
                UserPrincipalName = $upn
                Mail              = $mail
                AppId             = $appId
            }
        }
    }
    catch {
        Write-Warning "Failed to resolve principal chunk $chunkIndex. Error: $($_.Exception.Message)"
    }
}

Write-Progress -Activity "Resolving principals" -Completed

# Add unresolved placeholders
foreach ($id in $PrincipalIdArray) {
    if (-not $PrincipalMap.ContainsKey($id)) {
        $PrincipalMap[$id] = [pscustomobject]@{
            PrincipalId       = $id
            PrincipalType     = "Unknown"
            DisplayName       = $null
            UserPrincipalName = $null
            Mail              = $null
            AppId             = $null
        }
    }
}

Write-Host "Principals resolved: $($PrincipalMap.Count)" -ForegroundColor Green

# =========================================================
# PHASE 8 - COMPARE ACTIVE ASSIGNMENTS AGAINST PIM
# =========================================================

Write-Host "Comparing active assignments against PIM datasets..." -ForegroundColor Cyan

$Result = New-Object System.Collections.Generic.List[object]
$total = $ActiveAssignments.Count
$i = 0

foreach ($a in $ActiveAssignments) {
    $i++

    Write-Progress `
        -Activity "Comparing active assignments" `
        -Status "$i / $total" `
        -PercentComplete (($i / [Math]::Max($total, 1)) * 100)

    $principalId      = Get-PropValue -Object $a -Name "principalId"
    $roleDefinitionId = Get-PropValue -Object $a -Name "roleDefinitionId"
    $directoryScopeId = Get-PropValue -Object $a -Name "directoryScopeId"
    $appScopeId       = Get-PropValue -Object $a -Name "appScopeId"
    $assignmentId     = Get-PropValue -Object $a -Name "id"

    $key = New-Key `
        -PrincipalId $principalId `
        -RoleDefinitionId $roleDefinitionId `
        -DirectoryScopeId $directoryScopeId `
        -AppScopeId $appScopeId

    $source = "Persistent (non-PIM) ACTIVE"
    $pimMemberType = $null
    $pimAssignmentType = $null
    $pimStartDateTime = $null
    $pimEndDateTime = $null

if ($PimActiveKeys.Contains($key)) {
    $source = "PIM Active (assignment schedule instance)"

    $meta = $PimActiveMeta[$key]
    $pimMemberType     = Get-PropValue -Object $meta -Name "memberType"
    $pimAssignmentType = Get-PropValue -Object $meta -Name "assignmentType"
    $pimStartDateTime  = Get-PropValue -Object $meta -Name "startDateTime"
    $pimEndDateTime    = Get-PropValue -Object $meta -Name "endDateTime"
}
elseif ($PimActiveKeys.Contains($keyWithoutAppScope)) {
    $source = "PIM Active (assignment schedule instance)"

    $meta = $PimActiveMeta[$keyWithoutAppScope]
    $pimMemberType     = Get-PropValue -Object $meta -Name "memberType"
    $pimAssignmentType = Get-PropValue -Object $meta -Name "assignmentType"
    $pimStartDateTime  = Get-PropValue -Object $meta -Name "startDateTime"
    $pimEndDateTime    = Get-PropValue -Object $meta -Name "endDateTime"
}
elseif ($PimEligibleKeys.Contains($key)) {
    $source = "PIM Eligible (also active)"

    $meta = $PimEligibleMeta[$key]
    $pimMemberType     = Get-PropValue -Object $meta -Name "memberType"
    $pimAssignmentType = "Eligible"
    $pimStartDateTime  = Get-PropValue -Object $meta -Name "startDateTime"
    $pimEndDateTime    = Get-PropValue -Object $meta -Name "endDateTime"
}
elseif ($PimEligibleKeys.Contains($keyWithoutAppScope)) {
    $source = "PIM Eligible (also active)"

    $meta = $PimEligibleMeta[$keyWithoutAppScope]
    $pimMemberType     = Get-PropValue -Object $meta -Name "memberType"
    $pimAssignmentType = "Eligible"
    $pimStartDateTime  = Get-PropValue -Object $meta -Name "startDateTime"
    $pimEndDateTime    = Get-PropValue -Object $meta -Name "endDateTime"
}

    $principal = $PrincipalMap[$principalId]

    $roleName = if ($RoleDefMap.ContainsKey($roleDefinitionId)) {
        $RoleDefMap[$roleDefinitionId]
    }
    else {
        $roleDefinitionId
    }

    $Result.Add([pscustomobject]@{
        RoleName            = $roleName
        RoleDefinitionId    = $roleDefinitionId
        PrincipalType       = $principal.PrincipalType
        DisplayName         = $principal.DisplayName
        UserPrincipalName   = $principal.UserPrincipalName
        Mail                = $principal.Mail
        AppId               = $principal.AppId
        PrincipalId         = $principalId
        DirectoryScopeId    = $directoryScopeId
        AppScopeId          = $appScopeId
        Source              = $source
        PimMemberType       = $pimMemberType
        PimAssignmentType   = $pimAssignmentType
        PimStartDateTimeUtc = $pimStartDateTime
        PimEndDateTimeUtc   = $pimEndDateTime
        AssignmentId        = $assignmentId
    }) | Out-Null
}

Write-Progress -Activity "Comparing active assignments" -Completed

# =========================================================
# PHASE 9 - ELIGIBLE REPORT
# =========================================================

Write-Host "Building PIM eligible report..." -ForegroundColor Cyan

$EligibleReport = foreach ($e in $EligibleInstances) {
    $principalId      = Get-PropValue -Object $e -Name "principalId"
    $roleDefinitionId = Get-PropValue -Object $e -Name "roleDefinitionId"
    $directoryScopeId = Get-PropValue -Object $e -Name "directoryScopeId"
    $appScopeId       = Get-PropValue -Object $e -Name "appScopeId"
    $eligibilityId    = Get-PropValue -Object $e -Name "id"
    $memberType       = Get-PropValue -Object $e -Name "memberType"
    $startDateTime    = Get-PropValue -Object $e -Name "startDateTime"
    $endDateTime      = Get-PropValue -Object $e -Name "endDateTime"

    $principal = $PrincipalMap[$principalId]

    $roleName = if ($RoleDefMap.ContainsKey($roleDefinitionId)) {
        $RoleDefMap[$roleDefinitionId]
    }
    else {
        $roleDefinitionId
    }

    [pscustomobject]@{
        RoleName            = $roleName
        RoleDefinitionId    = $roleDefinitionId
        PrincipalType       = $principal.PrincipalType
        DisplayName         = $principal.DisplayName
        UserPrincipalName   = $principal.UserPrincipalName
        Mail                = $principal.Mail
        AppId               = $principal.AppId
        PrincipalId         = $principalId
        DirectoryScopeId    = $directoryScopeId
        AppScopeId          = $appScopeId
        MemberType          = $memberType
        StartDateTimeUtc    = $startDateTime
        EndDateTimeUtc      = $endDateTime
        EligibilityId       = $eligibilityId
    }
}

# =========================================================
# PHASE 10 - SUMMARY + EXPORT
# =========================================================

$Persistent = $Result |
    Where-Object { $_.Source -eq "Persistent (non-PIM) ACTIVE" } |
    Sort-Object RoleName, DisplayName, UserPrincipalName

$Summary = $Result |
    Group-Object Source |
    Sort-Object Name |
    Select-Object Name, Count

Write-Host ""
Write-Host "=== Summary: Active assignments by source ===" -ForegroundColor Cyan
$Summary | Format-Table -AutoSize

Write-Host ""
Write-Host "=== Persistent (non-PIM) ACTIVE admins ===" -ForegroundColor Yellow

if (@($Persistent).Count -eq 0) {
    Write-Host "None found ✅" -ForegroundColor Green
}
else {
    $Persistent |
        Select-Object RoleName, PrincipalType, DisplayName, UserPrincipalName, Source |
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "Exporting CSV files..." -ForegroundColor Cyan

$Result |
    Sort-Object RoleName, DisplayName, UserPrincipalName |
    Export-Csv -Path $OutAll -NoTypeInformation -Encoding UTF8

$Persistent |
    Export-Csv -Path $OutPersistent -NoTypeInformation -Encoding UTF8

$EligibleReport |
    Sort-Object RoleName, DisplayName, UserPrincipalName |
    Export-Csv -Path $OutEligible -NoTypeInformation -Encoding UTF8

$Summary |
    Export-Csv -Path $OutSummary -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "CSV written:" -ForegroundColor Cyan
Write-Host " - $OutAll"
Write-Host " - $OutPersistent"
Write-Host " - $OutEligible"
Write-Host " - $OutSummary"

Write-Host ""
Write-Host "Done." -ForegroundColor Green
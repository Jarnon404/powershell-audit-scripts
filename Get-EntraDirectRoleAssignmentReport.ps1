<#
.SYNOPSIS
    Entra ID Direct Role Assignments Audit.

.DESCRIPTION
    Listaa Entra ID:n suorat roolimääritykset ja auttaa erottamaan suorat assignmentit PIM-pohjaisista oikeuksista.

.REQUIREMENTS
    - Microsoft Graph PowerShell -moduulit ja roolimääritysten lukuoikeudet

.OUTPUTS
    - CSV/HTML-raportti suorista roolimäärityksistä

.EXAMPLE
    .\Get-EntraDirectRoleAssignmentReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Get-EntraDirectRoleAssignmentReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

# =========================================
# Entra ID - Direct role assignments
# Read-only / Audit safe
# =========================================

Connect-MgGraph -Scopes RoleManagement.Read.Directory,Directory.Read.All

Write-Host "Loading role definitions..."
$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All

Write-Host "Loading role assignments..."
$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All

$result = @()
$total = $assignments.Count
$i = 0

foreach ($a in $assignments) {
    $i++

    Write-Progress `
        -Activity "Processing role assignments" `
        -Status "$i / $total processed" `
        -PercentComplete (($i / $total) * 100)

    # Skip PIM (eligible / active via schedule)
    if ($a.ScheduleInfo -ne $null) { continue }

    # Resolve role name
    $roleDef = $roleDefinitions | Where-Object Id -eq $a.RoleDefinitionId
    if (-not $roleDef) { continue }

    # Resolve principal
    try {
        $principal = Get-MgDirectoryObjectById -DirectoryObjectId $a.PrincipalId
    }
    catch {
        continue
    }

    $result += [pscustomobject]@{
        RoleName      = $roleDef.DisplayName
        PrincipalType = ($principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '')
        DisplayName   = $principal.AdditionalProperties.displayName
        Assignment    = "Direct"
    }
}

Write-Progress -Activity "Processing role assignments" -Completed

$result |
    Sort-Object RoleName, DisplayName |
    Format-Table -AutoSize
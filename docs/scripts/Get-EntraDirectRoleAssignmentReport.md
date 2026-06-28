# Entra ID Direct Role Assignments Audit

**Script file:** `Get-EntraDirectRoleAssignmentReport.ps1`

## GitHub description

Lists direct Entra ID role assignments and helps distinguish direct assignments from PIM-based privileged access.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Direct Entra role assignments
- Role definitions
- Assigned principals
- Basic privileged access indicators

## Requirements

- Microsoft Graph PowerShell module
- Read permissions for role management data
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- HTML report

## Example

```powershell
.\Get-EntraDirectRoleAssignmentReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

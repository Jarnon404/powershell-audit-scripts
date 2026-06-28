# Intune Windows Apps Assignment Audit

**Script file:** `Get-IntuneWindowsAppAssignmentReport.ps1`

## GitHub description

Audits Intune Windows application assignments, target groups, exclusion groups and assignment filters.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Intune Windows applications
- Application assignments
- Target groups
- Exclusion groups
- Assignment filters

## Requirements

- Microsoft Graph PowerShell module
- Intune application read permissions
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- HTML report

## Example

```powershell
.\Get-IntuneWindowsAppAssignmentReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

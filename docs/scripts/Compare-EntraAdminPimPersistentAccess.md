# Entra Admins PIM vs Persistent Access Audit

**Script file:** `Compare-EntraAdminPimPersistentAccess.ps1`

## GitHub description

Compares active Entra ID admin role assignments with PIM eligibility or active schedule data to identify persistent admin access.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Entra ID admin role assignments
- PIM eligibility data when available
- PIM active schedules when available
- Persistent access indicators

## Requirements

- Microsoft Graph PowerShell module
- Read permissions for role management data
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- HTML report

## Example

```powershell
.\Compare-EntraAdminPimPersistentAccess.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

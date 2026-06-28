# M365 / Entra Privileged Access Audit

**Script file:** `Invoke-EntraPrivilegedAccessAudit.ps1`

## GitHub description

Reports high-privilege Entra ID and Microsoft 365 roles, administrative users and PIM or persistent assignment findings.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Privileged Entra roles
- Administrative users
- Role assignments
- PIM-related data when available
- Persistent privileged access indicators

## Requirements

- Microsoft Graph PowerShell module
- Read permissions for directory roles and role assignments
- Windows PowerShell 5.1 or newer

## Outputs

- HTML report
- CSV report

## Example

```powershell
.\Invoke-EntraPrivilegedAccessAudit.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

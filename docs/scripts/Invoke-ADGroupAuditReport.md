# Active Directory Group Audit Dashboard

**Script file:** `Invoke-ADGroupAuditReport.ps1`

## GitHub description

Audits Active Directory groups, memberships, empty groups, risk categories and group management findings in an HTML dashboard.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Active Directory groups
- Group membership
- Empty groups
- Nested or high-impact group patterns
- Basic group risk indicators

## Requirements

- Windows PowerShell 5.1 or newer
- ActiveDirectory PowerShell module
- Read access to Active Directory groups and memberships

## Outputs

- HTML dashboard
- CSV report

## Example

```powershell
.\Invoke-ADGroupAuditReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

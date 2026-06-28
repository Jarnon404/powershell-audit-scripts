# Exchange Online Mail Groups Audit Dashboard

**Script file:** `Invoke-ExchangeOnlineGroupAuditReport.ps1`

## GitHub description

Audits Exchange Online and Microsoft 365 mail-enabled groups, distribution groups, membership and visibility-related settings.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Exchange Online groups
- Microsoft 365 groups
- Distribution groups
- Group membership
- Basic visibility and mail settings

## Requirements

- ExchangeOnlineManagement PowerShell module
- Exchange Online read permissions
- Windows PowerShell 5.1 or newer

## Outputs

- Offline HTML dashboard
- CSV report

## Example

```powershell
.\Invoke-ExchangeOnlineGroupAuditReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

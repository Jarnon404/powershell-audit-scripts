# Exchange Online Mailbox Quota and Capacity Report

**Script file:** `Get-ExchangeOnlineMailboxQuotaReport.ps1`

## GitHub description

Reports Exchange Online mailbox sizes, quotas, utilization, archive information and capacity risk indicators.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Mailbox size
- Mailbox quotas
- Utilization percentage
- Archive mailbox data
- Capacity risk indicators

## Requirements

- ExchangeOnlineManagement PowerShell module
- Exchange Online read permissions
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- HTML report

## Example

```powershell
.\Get-ExchangeOnlineMailboxQuotaReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

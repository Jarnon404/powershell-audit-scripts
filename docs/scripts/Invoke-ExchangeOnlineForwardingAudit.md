# Exchange Online Mailbox Forwarding Audit

**Script file:** `Invoke-ExchangeOnlineForwardingAudit.ps1`

## GitHub description

Checks Exchange Online mailbox forwarding settings and Inbox rule based forwarding or redirect rules.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Mailbox forwarding settings
- Inbox rules
- Forward and redirect actions
- External forwarding indicators

## Requirements

- ExchangeOnlineManagement PowerShell module
- Exchange Online read permissions
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- HTML report

## Example

```powershell
.\Invoke-ExchangeOnlineForwardingAudit.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

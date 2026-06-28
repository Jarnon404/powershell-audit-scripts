# Intune + Exchange Online Read-Only Audit

**Script file:** `Invoke-IntuneExchangeReadOnlyAudit.ps1`

## GitHub description

Performs a read-only audit of selected Intune Apple token and certificate-related items plus Exchange Online connector TLS settings.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Apple MDM Push Certificate
- Apple ADE or DEP tokens
- Apple VPP tokens
- Intune certificate-related profiles
- Exchange Online inbound and outbound connector TLS settings

## Requirements

- Microsoft Graph PowerShell module
- ExchangeOnlineManagement PowerShell module
- Intune read permissions
- Exchange Online read permissions
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- HTML report with filters and details modal

## Example

```powershell
.\Invoke-IntuneExchangeReadOnlyAudit.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

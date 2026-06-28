# M365 / Entra Credential Expiry Audit

**Script file:** `Invoke-M365EntraCredentialExpiryAudit.ps1`

## GitHub description

Audits Microsoft 365 and Entra ID App Registration and Enterprise Application credentials, including certificate credentials and client secrets.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- App Registration certificate credentials
- App Registration client secrets
- Enterprise Application certificate credentials
- Enterprise Application client secrets
- Credential expiry dates

## Requirements

- Microsoft Graph PowerShell module
- Application.Read.All delegated permission
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- HTML report with filters and details modal

## Example

```powershell
.\Invoke-M365EntraCredentialExpiryAudit.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

# Windows Certificate and Service Account Audit

**Script file:** `Invoke-WindowsCertificateServiceAccountAudit.ps1`

## GitHub description

Audits Windows LocalMachine certificate stores and Windows services running under named service accounts.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- LocalMachine certificate stores
- Certificate expiry dates
- Certificate metadata
- Windows services running under named service accounts
- Built-in service account exclusions

## Requirements

- Windows PowerShell 5.1 or newer
- Sufficient read permissions on target machines
- PowerShell Remoting / WinRM for remote targets

## Outputs

- Combined CSV report
- Combined HTML report
- Per-computer CSV reports
- Per-computer HTML reports

## Example

```powershell
.\Invoke-WindowsCertificateServiceAccountAudit.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

# Windows Server License Status Audit

**Script file:** `Invoke-WindowsServerLicenseAudit.ps1`

## GitHub description

Audits Windows Server activation and licensing status and generates CSV and HTML reports for operational review.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Windows Server activation state
- License status information
- Server inventory details available to the script

## Requirements

- Windows PowerShell 5.1 or newer
- Administrative or sufficient read permissions on target servers
- PowerShell Remoting / WinRM if remote collection is used

## Outputs

- CSV report
- HTML report

## Example

```powershell
.\Invoke-WindowsServerLicenseAudit.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

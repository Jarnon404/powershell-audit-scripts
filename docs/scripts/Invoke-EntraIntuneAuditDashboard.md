# Entra ID and Intune Audit Dashboard

**Script file:** `Invoke-EntraIntuneAuditDashboard.ps1`

## GitHub description

Collects Entra ID users, Entra devices and optionally Intune device data into CSV, JSON and HTML audit views.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Entra ID users
- Entra ID devices
- Optional Intune devices
- Basic identity and device inventory data

## Requirements

- Microsoft Graph PowerShell module
- Required read permissions for Entra ID and Intune data
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- JSON data
- HTML dashboard

## Example

```powershell
.\Invoke-EntraIntuneAuditDashboard.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

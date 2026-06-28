# Intune Windows Device Inventory and Apps Report

**Script file:** `Export-IntuneWindowsInventoryReport.ps1`

## GitHub description

Exports Intune Windows device inventory, storage data and detected application summaries to CSV and HTML reports.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Intune Windows devices
- Device inventory data
- Storage information
- Detected applications when available

## Requirements

- Microsoft Graph PowerShell module
- Intune device read permissions
- Windows PowerShell 5.1 or newer

## Outputs

- CSV reports
- Interactive HTML report

## Example

```powershell
.\Export-IntuneWindowsInventoryReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

# Intune Device Storage Report

**Script file:** `Export-IntuneDeviceStorageReport.ps1`

## GitHub description

Reports total storage, free storage and storage utilization for Intune-managed devices for capacity review.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Intune device storage data
- Total storage
- Free storage
- Storage utilization percentage

## Requirements

- Microsoft Graph PowerShell module
- Intune device read permissions
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- HTML report

## Example

```powershell
.\Export-IntuneDeviceStorageReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

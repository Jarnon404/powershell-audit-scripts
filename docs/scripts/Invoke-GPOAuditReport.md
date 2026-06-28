# Group Policy Object Audit Dashboard

**Script file:** `Invoke-GPOAuditReport.ps1`

## GitHub description

Collects Group Policy Object metadata, links, inheritance information and findings related to stale or unmanaged GPOs.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Group Policy Objects
- GPO links
- GPO inheritance
- Modification dates
- Basic GPO hygiene indicators

## Requirements

- Windows PowerShell 5.1 or newer
- GroupPolicy PowerShell module
- Read access to Group Policy data

## Outputs

- HTML report
- CSV report

## Example

```powershell
.\Invoke-GPOAuditReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

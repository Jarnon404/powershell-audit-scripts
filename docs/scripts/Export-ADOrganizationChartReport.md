# Active Directory Organization Chart Report

**Script file:** `Export-ADOrganizationChartReport.ps1`

## GitHub description

Creates an HTML organization chart from Active Directory manager and direct-report relationships without environment-specific hardcoding.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Active Directory users
- Manager attributes
- Direct report relationships
- Basic organizational hierarchy data

## Requirements

- Windows PowerShell 5.1 or newer
- ActiveDirectory PowerShell module
- Read access to Active Directory user attributes

## Outputs

- HTML organization chart report
- CSV data export when supported by the script

## Example

```powershell
.\Export-ADOrganizationChartReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

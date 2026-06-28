# Intune Windows Update Policy Audit

**Script file:** `Invoke-IntuneWindowsUpdateAuditReport.ps1`

## GitHub description

Collects Intune Windows Update rings, feature update profiles, quality update profiles, driver update profiles, deployments and assignments.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Windows Update rings
- Feature update profiles
- Quality update profiles
- Driver update profiles
- Assignments and deployment data

## Requirements

- Microsoft Graph PowerShell module
- Intune configuration read permissions
- Windows PowerShell 5.1 or newer

## Outputs

- CSV report
- HTML report

## Example

```powershell
.\Invoke-IntuneWindowsUpdateAuditReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

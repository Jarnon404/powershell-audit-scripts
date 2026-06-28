# Local Windows Update Policy Audit

**Script file:** `Get-LocalWindowsUpdatePolicyAudit.ps1`

## GitHub description

Audits local Windows Update policy and registry-based configuration on a Windows device.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- Local Windows Update policy
- Registry-based update settings
- Device update configuration indicators

## Requirements

- Windows PowerShell 5.1 or newer
- Local Windows device
- Permission to read relevant registry and policy settings

## Outputs

- Console output
- CSV or HTML report when supported by the script

## Example

```powershell
.\Get-LocalWindowsUpdatePolicyAudit.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

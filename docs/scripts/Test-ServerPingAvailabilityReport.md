# Server Ping Availability Report

**Script file:** `Test-ServerPingAvailabilityReport.ps1`

## GitHub description

Tests ICMP availability for explicitly provided server names and creates a simple availability report without a hardcoded default host list.

## Purpose

This script is intended for audit, inventory, reporting and operational visibility. The collection logic is intended to be read-only unless the script documentation or inline help explicitly states otherwise.

## What it checks

- ICMP reachability
- Server response status
- Basic availability state

## Requirements

- Windows PowerShell 5.1 or newer
- Network access to target hosts
- ICMP allowed between the audit host and targets

## Outputs

- HTML report
- CSV report

## Example

```powershell
.\Test-ServerPingAvailabilityReport.ps1
```

## Notes

Review the script before running it in production. Test first in a lab, sandbox, pilot group, test tenant or other non-production environment.

Generated reports may contain environment-specific information such as tenant IDs, server names, application IDs, object IDs, connector names, account names or certificate metadata. Review and sanitize reports before sharing them outside your organization.

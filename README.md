![PSScriptAnalyzer](https://github.com/Jarnon404/powershell-audit-scripts/actions/workflows/psscriptanalyzer.yml/badge.svg)
![Secret Scan](https://github.com/Jarnon404/powershell-audit-scripts/actions/workflows/gitleaks.yml/badge.svg)
![License](https://img.shields.io/github/license/Jarnon404/powershell-audit-scripts)
![Release](https://img.shields.io/github/v/release/Jarnon404/powershell-audit-scripts)
![Repo Size](https://img.shields.io/github/repo-size/Jarnon404/powershell-audit-scripts)
# PowerShell Audit Scripts

PowerShell audit and reporting scripts for Windows Server, Active Directory, Group Policy, Microsoft 365, Exchange Online, Entra ID and Intune environments.

The scripts are intended for inventory, audit, reporting and operational visibility. Review each script before use and test in a non-production environment before running in production.

## Important disclaimer

Some parts of this repository may have been developed with assistance from ChatGPT/OpenAI and then reviewed, modified and maintained by the repository author.

Use these scripts at your own risk. They are provided as-is, without warranty. Always test in a lab, sandbox, pilot group, test tenant or other non-production environment before running in production.

Read the full disclaimer here: [DISCLAIMER.md](DISCLAIMER.md)

## Scripts

| Script | Name | Description |
|---|---|---|
| [`Compare-EntraAdminPimPersistentAccess.ps1`](docs/scripts/Compare-EntraAdminPimPersistentAccess.md) | Entra Admins PIM vs Persistent Access Audit | Compares active Entra ID admin role assignments with PIM eligibility or active schedule data to identify persistent admin access. |
| [`Export-ADOrganizationChartReport.ps1`](docs/scripts/Export-ADOrganizationChartReport.md) | Active Directory Organization Chart Report | Creates an HTML organization chart from Active Directory manager and direct-report relationships without environment-specific hardcoding. |
| [`Export-IntuneDeviceStorageReport.ps1`](docs/scripts/Export-IntuneDeviceStorageReport.md) | Intune Device Storage Report | Reports total storage, free storage and storage utilization for Intune-managed devices for capacity review. |
| [`Export-IntuneWindowsInventoryReport.ps1`](docs/scripts/Export-IntuneWindowsInventoryReport.md) | Intune Windows Device Inventory and Apps Report | Exports Intune Windows device inventory, storage data and detected application summaries to CSV and HTML reports. |
| [`Get-EntraDirectRoleAssignmentReport.ps1`](docs/scripts/Get-EntraDirectRoleAssignmentReport.md) | Entra ID Direct Role Assignments Audit | Lists direct Entra ID role assignments and helps distinguish direct assignments from PIM-based privileged access. |
| [`Get-ExchangeOnlineMailboxQuotaReport.ps1`](docs/scripts/Get-ExchangeOnlineMailboxQuotaReport.md) | Exchange Online Mailbox Quota and Capacity Report | Reports Exchange Online mailbox sizes, quotas, utilization, archive information and capacity risk indicators. |
| [`Get-IntuneWindowsAppAssignmentReport.ps1`](docs/scripts/Get-IntuneWindowsAppAssignmentReport.md) | Intune Windows Apps Assignment Audit | Audits Intune Windows application assignments, target groups, exclusion groups and assignment filters. |
| [`Get-LocalWindowsUpdatePolicyAudit.ps1`](docs/scripts/Get-LocalWindowsUpdatePolicyAudit.md) | Local Windows Update Policy Audit | Audits local Windows Update policy and registry-based configuration on a Windows device. |
| [`Invoke-ADGroupAuditReport.ps1`](docs/scripts/Invoke-ADGroupAuditReport.md) | Active Directory Group Audit Dashboard | Audits Active Directory groups, memberships, empty groups, risk categories and group management findings in an HTML dashboard. |
| [`Invoke-ADUserComputerAuditReport.ps1`](docs/scripts/Invoke-ADUserComputerAuditReport.md) | Active Directory Users and Computers Audit Dashboard | Audits Active Directory users and computers, including stale logons, disabled objects, lockout-related details and basic risk findings. |
| [`Invoke-EntraIntuneAuditDashboard.ps1`](docs/scripts/Invoke-EntraIntuneAuditDashboard.md) | Entra ID and Intune Audit Dashboard | Collects Entra ID users, Entra devices and optionally Intune device data into CSV, JSON and HTML audit views. |
| [`Invoke-EntraPrivilegedAccessAudit.ps1`](docs/scripts/Invoke-EntraPrivilegedAccessAudit.md) | M365 / Entra Privileged Access Audit | Reports high-privilege Entra ID and Microsoft 365 roles, administrative users and PIM or persistent assignment findings. |
| [`Invoke-ExchangeOnlineForwardingAudit.ps1`](docs/scripts/Invoke-ExchangeOnlineForwardingAudit.md) | Exchange Online Mailbox Forwarding Audit | Checks Exchange Online mailbox forwarding settings and Inbox rule based forwarding or redirect rules. |
| [`Invoke-ExchangeOnlineGroupAuditReport.ps1`](docs/scripts/Invoke-ExchangeOnlineGroupAuditReport.md) | Exchange Online Mail Groups Audit Dashboard | Audits Exchange Online and Microsoft 365 mail-enabled groups, distribution groups, membership and visibility-related settings. |
| [`Invoke-GPOAuditReport.ps1`](docs/scripts/Invoke-GPOAuditReport.md) | Group Policy Object Audit Dashboard | Collects Group Policy Object metadata, links, inheritance information and findings related to stale or unmanaged GPOs. |
| [`Invoke-IntuneExchangeReadOnlyAudit.ps1`](docs/scripts/Invoke-IntuneExchangeReadOnlyAudit.md) | Intune + Exchange Online Read-Only Audit | Performs a read-only audit of selected Intune Apple token and certificate-related items plus Exchange Online connector TLS settings. |
| [`Invoke-IntuneWindowsUpdateAuditReport.ps1`](docs/scripts/Invoke-IntuneWindowsUpdateAuditReport.md) | Intune Windows Update Policy Audit | Collects Intune Windows Update rings, feature update profiles, quality update profiles, driver update profiles, deployments and assignments. |
| [`Invoke-M365EntraCredentialExpiryAudit.ps1`](docs/scripts/Invoke-M365EntraCredentialExpiryAudit.md) | M365 / Entra Credential Expiry Audit | Audits Microsoft 365 and Entra ID App Registration and Enterprise Application credentials, including certificate credentials and client secrets. |
| [`Invoke-WindowsCertificateServiceAccountAudit.ps1`](docs/scripts/Invoke-WindowsCertificateServiceAccountAudit.md) | Windows Certificate and Service Account Audit | Audits Windows LocalMachine certificate stores and Windows services running under named service accounts. |
| [`Invoke-WindowsServerLicenseAudit.ps1`](docs/scripts/Invoke-WindowsServerLicenseAudit.md) | Windows Server License Status Audit | Audits Windows Server activation and licensing status and generates CSV and HTML reports for operational review. |
| [`Test-ServerPingAvailabilityReport.ps1`](docs/scripts/Test-ServerPingAvailabilityReport.md) | Server Ping Availability Report | Tests ICMP availability for explicitly provided server names and creates a simple availability report without a hardcoded default host list. |

## Documentation

Each script has a dedicated Markdown description under:

```text
docs/scripts/
```

Repository-level documents:

- [DISCLAIMER.md](DISCLAIMER.md)
- [SECURITY.md](SECURITY.md)

## Repository layout

```text
.
|-- *.ps1
|-- README.md
|-- DISCLAIMER.md
|-- SECURITY.md
`-- docs/
    `-- scripts/
        `-- <script-specific documentation>.md
```

## General usage

Run scripts from an elevated or appropriately permissioned PowerShell session when required.

```powershell
.\ScriptName.ps1
```

Many scripts create HTML and CSV reports in a local output folder. Review output files before sharing them outside your organization.

## Security note

Generated reports can contain sensitive operational information. Do not commit generated reports to a public repository unless they have been reviewed and sanitized.

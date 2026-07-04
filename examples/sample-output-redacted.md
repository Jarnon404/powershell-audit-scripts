# Sample output - redacted

This file shows the type of output this repository is intended to produce.

The data below is synthetic and does not represent a real customer, tenant, domain, device or user.

## Example: Active Directory group audit

| GroupName | Scope | Category | MemberCount | Notes |
|---|---|---|---:|---|
| Example-Admins | Global | Security | 3 | Review privileged membership |
| Example-Helpdesk | Global | Security | 8 | Operational support group |
| Example-ReadOnly-Audit | Global | Security | 2 | Read-only audit access |

## Example: Intune Windows inventory

| DeviceName | OS | Ownership | Compliance | LastCheckIn |
|---|---|---|---|---|
| EXAMPLE-WIN-001 | Windows 11 Enterprise | Corporate | Compliant | 2026-07-03 |
| EXAMPLE-WIN-002 | Windows 11 Pro | Corporate | NonCompliant | 2026-07-02 |

## Example: Exchange Online mailbox quota

| DisplayName | MailboxType | UsedGB | QuotaGB | PercentUsed |
|---|---|---:|---:|---:|
| Example User 1 | UserMailbox | 12.5 | 50 | 25 |
| Example Shared Mailbox | SharedMailbox | 34.2 | 50 | 68 |

## Safety note

Do not commit real generated reports to this repository.

Generated files such as CSV, HTML, JSON, XLSX, ZIP and log files should be reviewed, sanitized and stored outside the public repository unless they are fully synthetic examples.

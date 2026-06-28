# Security Policy

## Supported use

This repository contains PowerShell audit and reporting scripts intended for defensive administration, inventory, visibility and reporting.

The scripts are intended to be run by authorized administrators in environments where they have permission to perform the relevant checks.

## Reporting security issues

If you find a security issue in these scripts, avoid publishing exploit details publicly before the issue can be reviewed.

Suggested responsible disclosure process:

1. Open a private security advisory if the repository has that feature enabled.
2. Otherwise, contact the repository owner directly.
3. Include a clear description, affected script, potential impact and reproduction steps.

## Sensitive data

Generated reports can contain environment-specific information, including but not limited to:

- Tenant IDs
- Application IDs
- Object IDs
- Certificate metadata
- Connector names
- Server names
- Service account names
- User names
- Group names
- Device names
- Configuration profile names

Do not commit generated reports to a public repository unless you have reviewed and sanitized them.

## Permissions

Use the least privilege model where possible.

Read-oriented permissions can still expose sensitive configuration data. Treat report output accordingly.

## Safe handling

Recommended practices:

- Store reports in a restricted local folder.
- Avoid sending raw CSV, JSON or HTML reports over unsecured channels.
- Remove customer, tenant, server and identity data before sharing examples publicly.
- Rotate or remove any exposed secrets if accidental disclosure occurs.

## Scope

This project is not a penetration testing toolkit, exploit framework or offensive security toolset. It is intended for defensive audit, inventory and reporting use.

# Quality and safety model

This repository is designed as a public-safe PowerShell audit and reporting toolkit.

The goal is to keep the scripts useful for operational review while reducing the risk of accidentally publishing sensitive customer or environment-specific information.

## Quality checks

The repository uses GitHub Actions for automated quality checks.

| Check | Purpose |
|---|---|
| PSScriptAnalyzer | Runs static analysis for PowerShell scripts |
| Secret Scan / Gitleaks | Detects accidentally committed secrets |
| Pester Tests | Runs repository smoke tests and script validation |
| Public Safety Check | Detects generated output files and unsafe public markers |

## Branch protection

The `main` branch is protected and requires status checks before merge.

Required checks include:

- PSScriptAnalyzer
- Secret Scan / Gitleaks
- Pester Tests
- Public Safety Check

## Public-safe publishing model

The repository should not contain:

- Customer names
- Tenant IDs
- Client IDs
- Secrets
- Internal hostnames
- Private IP addresses
- Generated customer reports
- Unsanitized CSV, HTML, JSON, XLSX, ZIP or log output

## Generated reports

Generated reports may contain sensitive operational information.

Do not commit generated reports unless they are fully synthetic examples or have been reviewed and sanitized for public sharing.

## Review model

Before publishing changes:

1. Review the script or documentation change.
2. Confirm that no customer-specific data is included.
3. Confirm that no generated output files are included.
4. Run or review GitHub Actions checks.
5. Merge only after required checks are successful.

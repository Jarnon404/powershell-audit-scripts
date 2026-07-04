# Testing

This repository uses GitHub Actions for basic quality and public-safety checks.

## Current checks

| Check | Purpose |
|---|---|
| PSScriptAnalyzer | PowerShell static analysis |
| Gitleaks | Secret scanning |
| Pester Tests | Repository smoke tests |
| Public Safety Check | Detects unsafe public repository markers |

## Local Pester test

```powershell
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck
Invoke-Pester -Path .\tests -CI
```

## Local PSScriptAnalyzer test

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning,Error
```

## Safety reminder

Do not commit generated reports, customer data, tenant IDs, client IDs, internal server names, private IP addresses or secrets.

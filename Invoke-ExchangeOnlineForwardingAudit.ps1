<#
.SYNOPSIS
    Exchange Online Mailbox Forwarding Audit.

.DESCRIPTION
    Tarkistaa Exchange Online -postilaatikoiden forwardaukset sekä Inbox rule -pohjaiset forward/redirect-säännöt.

.REQUIREMENTS
    - ExchangeOnlineManagement-moduuli ja postilaatikoiden asetusten lukuoikeudet

.OUTPUTS
    - CSV/HTML-raportti forwardauslöydöksistä

.EXAMPLE
    .\Invoke-ExchangeOnlineForwardingAudit.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Invoke-ExchangeOnlineForwardingAudit.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

# =========================================================
# Exchange / M365 Forwarding Audit - READ ONLY
# =========================================================
# Version: 1.2
#
# Checks:
# - Mailbox-level forwarding
# - Inbox rule forwarding / redirecting
#
# Scope:
# - UserMailbox
# - SharedMailbox
#
# Output:
# - Console summary
# - Main CSV report
# - Error CSV report
#
# Progress:
# - Write-Progress
# - Console status every 10 mailboxes
# - Total duration
#
# READ ONLY:
# - Uses only Get-Mailbox and Get-InboxRule
# - Does NOT change, remove, disable or create anything
# =========================================================

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------
# Output path
# ---------------------------------------------------------

$OutputFolder = Join-Path $PSScriptRoot "output\mailbox-forwarding-audit"
$CsvFile      = Join-Path $OutputFolder "Mailbox_Forwarding_Audit.csv"
$ErrorCsvFile = Join-Path $OutputFolder "Mailbox_Forwarding_Audit_Errors.csv"

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

# ---------------------------------------------------------
# Timestamp
# ---------------------------------------------------------

$RunTime = Get-Date

# ---------------------------------------------------------
# Result arrays
# ---------------------------------------------------------

$Results = New-Object System.Collections.Generic.List[object]
$Errors  = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------
# Validate Exchange cmdlets
# ---------------------------------------------------------

Write-Host ""
Write-Host "=== Exchange / M365 Forwarding Audit - READ ONLY ===" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command Get-Mailbox -ErrorAction SilentlyContinue)) {
    throw "Get-Mailbox-komentoa ei löydy. Yhdistä ensin Exchange Onlineen komennolla: Connect-ExchangeOnline"
}

if (-not (Get-Command Get-InboxRule -ErrorAction SilentlyContinue)) {
    throw "Get-InboxRule-komentoa ei löydy. Yhdistä ensin Exchange Onlineen komennolla: Connect-ExchangeOnline"
}

# ---------------------------------------------------------
# Get target mailboxes
# ---------------------------------------------------------

Write-Host "Haetaan audit-kohteet: UserMailbox + SharedMailbox..." -ForegroundColor Cyan

$Mailboxes = Get-Mailbox -RecipientTypeDetails UserMailbox,SharedMailbox -ResultSize Unlimited

$Total = @($Mailboxes).Count
$Index = 0

Write-Host "Audit-kohteita yhteensä: $Total" -ForegroundColor Green
Write-Host ""

Write-Host "Mailbox-jakauma:" -ForegroundColor Cyan

$Mailboxes |
    Group-Object RecipientTypeDetails |
    Sort-Object Count -Descending |
    Select-Object Name, Count |
    Format-Table -AutoSize

# ---------------------------------------------------------
# Audit each mailbox
# ---------------------------------------------------------

$AuditStart = Get-Date

foreach ($mb in $Mailboxes) {

    $Index++

    $MailboxId = if ($mb.UserPrincipalName) {
        $mb.UserPrincipalName
    }
    else {
        $mb.PrimarySmtpAddress.ToString()
    }

    $PrimarySmtpAddress = if ($mb.PrimarySmtpAddress) {
        $mb.PrimarySmtpAddress.ToString()
    }
    else {
        $null
    }

    $Percent = [math]::Round((($Index / [math]::Max($Total,1)) * 100), 1)

    Write-Progress `
        -Activity "Exchange / M365 Forwarding Audit - READ ONLY" `
        -Status "$Index / $Total ($Percent %) - $MailboxId" `
        -CurrentOperation "Tarkistetaan mailbox forwardit ja inbox-säännöt" `
        -PercentComplete $Percent

    if (
        $Index -eq 1 -or
        $Index -eq $Total -or
        ($Index % 10 -eq 0)
    ) {
        Write-Host ("[{0}/{1}] {2}% - {3}" -f $Index, $Total, $Percent, $MailboxId) -ForegroundColor DarkCyan
    }

    # -----------------------------------------------------
    # 1) Mailbox-level forwarding
    # -----------------------------------------------------
    # These properties come from Get-Mailbox result.
    # This is read-only.
    # -----------------------------------------------------

    try {
        if (
            $mb.ForwardingAddress -or
            $mb.ForwardingSmtpAddress -or
            $mb.DeliverToMailboxAndForward
        ) {
            $Results.Add([PSCustomObject]@{
                RunTime                    = $RunTime
                Mailbox                    = $MailboxId
                PrimarySmtpAddress         = $PrimarySmtpAddress
                RecipientTypeDetails       = $mb.RecipientTypeDetails
                FindingType                = "Mailbox-level forwarding"
                RuleName                   = $null
                Enabled                    = $true
                ForwardTo                  = $null
                RedirectTo                 = $null
                ForwardAsAttachmentTo      = $null
                ForwardingAddress          = if ($mb.ForwardingAddress) { $mb.ForwardingAddress.ToString() } else { $null }
                ForwardingSmtpAddress      = if ($mb.ForwardingSmtpAddress) { $mb.ForwardingSmtpAddress.ToString() } else { $null }
                DeliverToMailboxAndForward = $mb.DeliverToMailboxAndForward
                SuspiciousHint             = if ($mb.ForwardingSmtpAddress) { "Check external SMTP forwarding" } else { "Check mailbox forwarding target" }
                Error                      = $null
            })
        }
    }
    catch {
        $Errors.Add([PSCustomObject]@{
            RunTime              = $RunTime
            Mailbox              = $MailboxId
            PrimarySmtpAddress   = $PrimarySmtpAddress
            RecipientTypeDetails = $mb.RecipientTypeDetails
            Stage                = "Mailbox-level forwarding check"
            Error                = $_.Exception.Message
        })
    }

    # -----------------------------------------------------
    # 2) Inbox rule forwarding
    # -----------------------------------------------------
    # Checks:
    # - ForwardTo
    # - RedirectTo
    # - ForwardAsAttachmentTo
    #
    # This is read-only.
    # -----------------------------------------------------

    try {
        $Rules = Get-InboxRule -Mailbox $MailboxId -ErrorAction Stop

        foreach ($rule in $Rules) {

            if (
                $rule.ForwardTo -or
                $rule.RedirectTo -or
                $rule.ForwardAsAttachmentTo
            ) {
                $Results.Add([PSCustomObject]@{
                    RunTime                    = $RunTime
                    Mailbox                    = $MailboxId
                    PrimarySmtpAddress         = $PrimarySmtpAddress
                    RecipientTypeDetails       = $mb.RecipientTypeDetails
                    FindingType                = "Inbox rule forwarding"
                    RuleName                   = $rule.Name
                    Enabled                    = $rule.Enabled
                    ForwardTo                  = if ($rule.ForwardTo) { ($rule.ForwardTo -join "; ") } else { $null }
                    RedirectTo                 = if ($rule.RedirectTo) { ($rule.RedirectTo -join "; ") } else { $null }
                    ForwardAsAttachmentTo      = if ($rule.ForwardAsAttachmentTo) { ($rule.ForwardAsAttachmentTo -join "; ") } else { $null }
                    ForwardingAddress          = $null
                    ForwardingSmtpAddress      = $null
                    DeliverToMailboxAndForward = $null
                    SuspiciousHint             = "Check inbox rule forwarding / redirect target"
                    Error                      = $null
                })
            }
        }
    }
    catch {
        $Errors.Add([PSCustomObject]@{
            RunTime              = $RunTime
            Mailbox              = $MailboxId
            PrimarySmtpAddress   = $PrimarySmtpAddress
            RecipientTypeDetails = $mb.RecipientTypeDetails
            Stage                = "Get-InboxRule"
            Error                = $_.Exception.Message
        })
    }
}

Write-Progress `
    -Activity "Exchange / M365 Forwarding Audit - READ ONLY" `
    -Completed

$AuditEnd = Get-Date
$Duration = New-TimeSpan -Start $AuditStart -End $AuditEnd

# ---------------------------------------------------------
# Export results
# ---------------------------------------------------------

$Results |
    Sort-Object Mailbox, FindingType, RuleName |
    Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8 -Delimiter ";"

$Errors |
    Sort-Object Mailbox, Stage |
    Export-Csv -Path $ErrorCsvFile -NoTypeInformation -Encoding UTF8 -Delimiter ";"

# ---------------------------------------------------------
# Console summary
# ---------------------------------------------------------

Write-Host ""
Write-Host "=== Yhteenveto ===" -ForegroundColor Cyan
Write-Host "Tarkistetut mailboxit: $Total" -ForegroundColor White
Write-Host "Löydöksiä:            $($Results.Count)" -ForegroundColor Yellow
Write-Host "Virheitä:             $($Errors.Count)" -ForegroundColor Yellow
Write-Host "Auditin kesto:        $($Duration.ToString())" -ForegroundColor Cyan
Write-Host ""
Write-Host "Raportti:      $CsvFile" -ForegroundColor Green
Write-Host "Virheraportti: $ErrorCsvFile" -ForegroundColor Green
Write-Host ""

if ($Results.Count -gt 0) {
    Write-Host "=== Löydökset ===" -ForegroundColor Cyan

    $Results |
        Sort-Object Mailbox, FindingType, RuleName |
        Format-Table `
            Mailbox,
            RecipientTypeDetails,
            FindingType,
            RuleName,
            Enabled,
            ForwardTo,
            RedirectTo,
            ForwardAsAttachmentTo,
            ForwardingAddress,
            ForwardingSmtpAddress,
            DeliverToMailboxAndForward `
            -AutoSize
}
else {
    Write-Host "Ei forwarding-löydöksiä UserMailbox / SharedMailbox -kohteista." -ForegroundColor Green
}

if ($Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "=== Virheet / tarkistamatta jääneet ===" -ForegroundColor Yellow

    $Errors |
        Sort-Object Mailbox, Stage |
        Format-Table `
            Mailbox,
            RecipientTypeDetails,
            Stage,
            Error `
            -AutoSize
}

Write-Host ""
Write-Host "Valmis. Skripti oli read-only: käytössä vain Get-Mailbox ja Get-InboxRule." -ForegroundColor Cyan
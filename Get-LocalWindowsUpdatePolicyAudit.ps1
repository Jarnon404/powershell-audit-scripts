<#
.SYNOPSIS
    Local Windows Update Policy Audit.

.DESCRIPTION
    Lukee paikallisen Windows-laitteen Windows Update-, MDM-, GPO-, WSUS- ja reboot-tilan ilman muutoksia.

.REQUIREMENTS
    - Paikallinen Windows-laite ja oikeudet lukea rekisteri-/policy-tietoja

.OUTPUTS
    - HTML/CSV/tekstiraportti paikallisesta Windows Update -policy-tilasta

.EXAMPLE
    .\Get-LocalWindowsUpdatePolicyAudit.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Get-LocalWindowsUpdatePolicyAudit.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

<#
.SYNOPSIS
    Windows Update / Intune effective policy audit

.DESCRIPTION
    Read-only auditointi:
    - Lukee Windows-version ja buildin
    - Lukee Intune/MDM Update Policy CSP -asetukset
    - Lukee mahdolliset GPO/WSUS-rekisteriasetukset
    - Näyttää WinningProvider-tunnukset
    - Tarkistaa Windows Update -palvelut
    - Tarkistaa uudelleenkäynnistyksen tarpeen
    - Tarkistaa Windows Update for Business -rekisteröinnit
    - Ei muuta mitään asetuksia

.NOTES
    READ-ONLY
#>

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Windows Update / Intune Effective Policy Audit" -ForegroundColor Cyan
Write-Host " READ-ONLY - asetuksia ei muuteta" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# ---------------------------------------------------------
# 1. Perustiedot
# ---------------------------------------------------------

Write-Host "`n[1/8] Windows ja laitetiedot" -ForegroundColor Yellow

$OS = Get-CimInstance Win32_OperatingSystem
$ComputerSystem = Get-CimInstance Win32_ComputerSystem

$WindowsInfo = [pscustomobject]@{
    ComputerName       = $env:COMPUTERNAME
    Manufacturer       = $ComputerSystem.Manufacturer
    Model              = $ComputerSystem.Model
    WindowsCaption     = $OS.Caption
    WindowsVersion     = $OS.Version
    BuildNumber        = $OS.BuildNumber
    LastBootUpTime     = $OS.LastBootUpTime
    CurrentUser        = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

$WindowsInfo | Format-List

# ---------------------------------------------------------
# 2. Windows release -tiedot
# ---------------------------------------------------------

Write-Host "`n[2/8] Windows release -tiedot" -ForegroundColor Yellow

$CurrentVersionPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

if (Test-Path $CurrentVersionPath) {
    $CurrentVersion = Get-ItemProperty $CurrentVersionPath

    [pscustomobject]@{
        ProductName        = $CurrentVersion.ProductName
        DisplayVersion     = $CurrentVersion.DisplayVersion
        ReleaseId          = $CurrentVersion.ReleaseId
        CurrentBuild       = $CurrentVersion.CurrentBuild
        CurrentBuildNumber = $CurrentVersion.CurrentBuildNumber
        UBR                = $CurrentVersion.UBR
        BuildLabEx         = $CurrentVersion.BuildLabEx
        EditionID          = $CurrentVersion.EditionID
    } | Format-List
}

# ---------------------------------------------------------
# 3. Intune / MDM effective Update CSP
# ---------------------------------------------------------

Write-Host "`n[3/8] Intune / MDM Update Policy CSP" -ForegroundColor Yellow

$PolicyManagerPath =
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update"

if (Test-Path $PolicyManagerPath) {

    $WU = Get-ItemProperty $PolicyManagerPath

    $EffectiveSettings = [ordered]@{
        AllowAutoUpdate =
            $WU.AllowAutoUpdate

        AllowMUUpdateService =
            $WU.AllowMUUpdateService

        ExcludeWUDriversInQualityUpdate =
            $WU.ExcludeWUDriversInQualityUpdate

        DeferQualityUpdatesPeriodInDays =
            $WU.DeferQualityUpdatesPeriodInDays

        DeferFeatureUpdatesPeriodInDays =
            $WU.DeferFeatureUpdatesPeriodInDays

        PauseQualityUpdates =
            $WU.PauseQualityUpdates

        PauseFeatureUpdates =
            $WU.PauseFeatureUpdates

        ActiveHoursStart =
            $WU.ActiveHoursStart

        ActiveHoursEnd =
            $WU.ActiveHoursEnd

        ConfigureDeadlineForQualityUpdates =
            $WU.ConfigureDeadlineForQualityUpdates

        ConfigureDeadlineForFeatureUpdates =
            $WU.ConfigureDeadlineForFeatureUpdates

        ConfigureDeadlineGracePeriod =
            $WU.ConfigureDeadlineGracePeriod

        ConfigureDeadlineNoAutoReboot =
            $WU.ConfigureDeadlineNoAutoReboot

        ConfigureFeatureUpdateUninstallPeriod =
            $WU.ConfigureFeatureUpdateUninstallPeriod

        UpdateNotificationLevel =
            $WU.UpdateNotificationLevel

        SetDisablePauseUXAccess =
            $WU.SetDisablePauseUXAccess

        SetDisableUXWUAccess =
            $WU.SetDisableUXWUAccess

        AllowRebootlessUpdates =
            $WU.AllowRebootlessUpdates

        FeatureUpdateEnrolled =
            $WU.FeatureUpdateEnrolled

        QualityUpdateEnrolled =
            $WU.QualityUpdateEnrolled

        DriverUpdateEnrolled =
            $WU.DriverUpdateEnrolled

        QuickMachineRecoveryEnrolled =
            $WU.QuickMachineRecoveryEnrolled
    }

    [pscustomobject]$EffectiveSettings | Format-List
}
else {
    Write-Host "Update Policy CSP -avainta ei löytynyt." -ForegroundColor DarkYellow
}

# ---------------------------------------------------------
# 4. Winning Provider -tunnukset
# ---------------------------------------------------------

Write-Host "`n[4/8] Asetusten Winning Provider -tunnukset" -ForegroundColor Yellow

if (Test-Path $PolicyManagerPath) {

    $ProviderProperties =
        (Get-ItemProperty $PolicyManagerPath).PSObject.Properties |
        Where-Object {
            $_.Name -like "*_WinningProvider"
        } |
        Sort-Object Name |
        Select-Object `
            @{Name="Setting"; Expression={
                $_.Name -replace "_WinningProvider$", ""
            }},
            @{Name="WinningProvider"; Expression={
                $_.Value
            }}

    if ($ProviderProperties) {
        $ProviderProperties | Format-Table -AutoSize
    }
    else {
        Write-Host "WinningProvider-tietoja ei löytynyt." -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------
# 5. GPO / WSUS / Target Release Version
# ---------------------------------------------------------

Write-Host "`n[5/8] GPO-, WSUS- ja Target Release -asetukset" -ForegroundColor Yellow

$WindowsUpdatePolicyPath =
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

$WindowsUpdateAUPath =
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

if (Test-Path $WindowsUpdatePolicyPath) {

    Write-Host "`nWindowsUpdate policy:" -ForegroundColor Cyan

    Get-ItemProperty $WindowsUpdatePolicyPath |
        Select-Object `
            TargetReleaseVersion,
            TargetReleaseVersionInfo,
            ProductVersion,
            WUServer,
            WUStatusServer,
            UpdateServiceUrlAlternate,
            DisableWindowsUpdateAccess,
            DoNotConnectToWindowsUpdateInternetLocations,
            SetPolicyDrivenUpdateSourceForFeatureUpdates,
            SetPolicyDrivenUpdateSourceForQualityUpdates,
            SetPolicyDrivenUpdateSourceForDriverUpdates,
            SetPolicyDrivenUpdateSourceForOtherUpdates |
        Format-List
}
else {
    Write-Host "WindowsUpdate GPO -avainta ei löytynyt." -ForegroundColor Green
}

if (Test-Path $WindowsUpdateAUPath) {

    Write-Host "`nWindowsUpdate AU policy:" -ForegroundColor Cyan

    Get-ItemProperty $WindowsUpdateAUPath |
        Select-Object `
            AUOptions,
            NoAutoUpdate,
            UseWUServer,
            ScheduledInstallDay,
            ScheduledInstallTime,
            DetectionFrequency,
            DetectionFrequencyEnabled,
            NoAutoRebootWithLoggedOnUsers |
        Format-List
}
else {
    Write-Host "WindowsUpdate AU GPO -avainta ei löytynyt." -ForegroundColor Green
}

# ---------------------------------------------------------
# 6. Windows Update -palvelut
# ---------------------------------------------------------

Write-Host "`n[6/8] Windows Update -palvelut" -ForegroundColor Yellow

$ServiceNames = @(
    "wuauserv",
    "UsoSvc",
    "WaaSMedicSvc",
    "BITS",
    "DoSvc",
    "CryptSvc"
)

$Services = foreach ($ServiceName in $ServiceNames) {

    $Service = Get-CimInstance Win32_Service `
        -Filter "Name='$ServiceName'" `
        -ErrorAction SilentlyContinue

    if ($Service) {
        [pscustomobject]@{
            Name      = $Service.Name
            DisplayName = $Service.DisplayName
            State     = $Service.State
            StartMode = $Service.StartMode
            StartName = $Service.StartName
        }
    }
}

$Services | Format-Table -AutoSize

# ---------------------------------------------------------
# 7. Pending reboot
# ---------------------------------------------------------

Write-Host "`n[7/8] Uudelleenkäynnistyksen tarve" -ForegroundColor Yellow

$PendingReboot = [pscustomobject]@{
    CBSRebootPending =
        Test-Path `
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"

    WindowsUpdateRebootRequired =
        Test-Path `
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

    PendingFileRenameOperations =
        [bool](
            Get-ItemProperty `
                "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
                -Name PendingFileRenameOperations `
                -ErrorAction SilentlyContinue
        )

    UpdateExeVolatile =
        [bool](
            Get-ItemProperty `
                "HKLM:\SOFTWARE\Microsoft\Updates" `
                -Name UpdateExeVolatile `
                -ErrorAction SilentlyContinue
        )
}

$PendingReboot | Format-List

$RestartRequired =
    $PendingReboot.CBSRebootPending -or
    $PendingReboot.WindowsUpdateRebootRequired -or
    $PendingReboot.PendingFileRenameOperations -or
    $PendingReboot.UpdateExeVolatile

Write-Host "Restart required: $RestartRequired" -ForegroundColor $(

    if ($RestartRequired) {
        "Yellow"
    }
    else {
        "Green"
    }
)

# ---------------------------------------------------------
# 8. Tulkinta
# ---------------------------------------------------------

Write-Host "`n[8/8] Tulkinta" -ForegroundColor Yellow

if (Test-Path $PolicyManagerPath) {

    $WU = Get-ItemProperty $PolicyManagerPath

    if ($WU.FeatureUpdateEnrolled -eq 1) {
        Write-Host `
            "[OK] Laite on rekisteröity Feature Update -hallintaan." `
            -ForegroundColor Green
    }
    else {
        Write-Host `
            "[INFO] Laite ei näytä olevan Feature Update -hallinnassa." `
            -ForegroundColor DarkYellow
    }

    if ($WU.DeferFeatureUpdatesPeriodInDays -gt 0) {
        Write-Host `
            "[HUOMIO] Feature update -viive on $($WU.DeferFeatureUpdatesPeriodInDays) päivää." `
            -ForegroundColor Yellow
    }
    else {
        Write-Host `
            "[OK] Feature update -viive on 0 päivää." `
            -ForegroundColor Green
    }

    if ($WU.PauseFeatureUpdates -eq 1) {
        Write-Host `
            "[VAROITUS] Feature updates on pausella." `
            -ForegroundColor Red
    }
    else {
        Write-Host `
            "[OK] Feature updates ei ole pausella." `
            -ForegroundColor Green
    }

    if ($WU.PauseQualityUpdates -eq 1) {
        Write-Host `
            "[VAROITUS] Quality updates on pausella." `
            -ForegroundColor Red
    }
    else {
        Write-Host `
            "[OK] Quality updates ei ole pausella." `
            -ForegroundColor Green
    }

    if ($WU.ExcludeWUDriversInQualityUpdate -eq 1) {
        Write-Host `
            "[INFO] Ajurit on suljettu pois tavallisista quality-päivityksistä." `
            -ForegroundColor Cyan
    }

    if ($WU.ConfigureDeadlineNoAutoReboot -eq 0) {
        Write-Host `
            "[INFO] Automaattinen uudelleenkäynnistys deadlinen yhteydessä on sallittu." `
            -ForegroundColor Cyan
    }
    elseif ($WU.ConfigureDeadlineNoAutoReboot -eq 1) {
        Write-Host `
            "[INFO] Automaattinen uudelleenkäynnistys ennen deadlinea on estetty." `
            -ForegroundColor Cyan
    }
}

if (Test-Path $WindowsUpdatePolicyPath) {

    $GPOWU = Get-ItemProperty $WindowsUpdatePolicyPath

    if ($GPOWU.WUServer) {
        Write-Host `
            "[HUOMIO] Koneelle on määritetty WSUS-palvelin: $($GPOWU.WUServer)" `
            -ForegroundColor Yellow
    }

    if ($GPOWU.TargetReleaseVersionInfo) {
        Write-Host `
            "[HUOMIO] TargetReleaseVersionInfo: $($GPOWU.TargetReleaseVersionInfo)" `
            -ForegroundColor Yellow
    }
}
else {
    Write-Host `
        "[OK] Vanhaa Windows Update GPO/WSUS -rekisteriavainta ei löytynyt." `
        -ForegroundColor Green
}

Write-Host ""
Write-Host "Auditointi valmis. Mitään asetuksia ei muutettu." -ForegroundColor Green
Write-Host ""
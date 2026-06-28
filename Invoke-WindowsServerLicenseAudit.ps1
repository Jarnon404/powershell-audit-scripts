<#
.SYNOPSIS
    Windows Server License Status Audit.

.DESCRIPTION
    Auditoi Windows Server -palvelimien aktivointi- ja lisenssitilatiedot sekä tuottaa selkeän CSV/HTML-raportin ylläpitoa ja tarkistuksia varten.

.REQUIREMENTS
    - Windows Server, CIM/WMI-yhteydet palvelimille, tarvittavat lukuoikeudet palvelimiin

.OUTPUTS
    - CSV- ja HTML-raportti palvelimien lisenssi-/aktivointitilasta

.EXAMPLE
    .\Invoke-WindowsServerLicenseAudit.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Invoke-WindowsServerLicenseAudit.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

param(
    [string]$OutputFolder = (Join-Path $PSScriptRoot "output\windows-activation"),
    [string[]]$Servers = @(
    )
)

$ErrorActionPreference = "Stop"

function New-SafeHtml {
    param([object]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-LicenseStatusText {
    param([object]$Status)

    if ($null -eq $Status -or $Status -eq "") { return "Unknown" }

    switch ([int]$Status) {
        0 { "Unlicensed" }
        1 { "Licensed" }
        2 { "OOB Grace" }
        3 { "Out of Tolerance" }
        4 { "Non-Genuine" }
        5 { "Notification" }
        6 { "Extended Grace" }
        default { "Unknown" }
    }
}

function Get-StatusClass {
    param([string]$Status)

    switch -Wildcard ($Status) {
        "Licensed" { "ok"; break }
        "Notification" { "warn"; break }
        "OOB Grace" { "warn"; break }
        "Extended Grace" { "warn"; break }
        "Out of Tolerance" { "warn"; break }
        "No Windows licensing row found" { "warn"; break }
        "Unknown" { "warn"; break }
        "Unlicensed" { "err"; break }
        "Non-Genuine" { "err"; break }
        "ERROR:*" { "err"; break }
        default { "warn"; break }
    }
}

function Get-IsProblem {
    param([string]$Status)

    if ($Status -eq "Licensed") { return $false }
    return $true
}

function Get-SummaryCategory {
    param([string]$Status)

    switch -Wildcard ($Status) {
        "Licensed" { "licensed"; break }
        "Notification" { "warnings"; break }
        "OOB Grace" { "warnings"; break }
        "Extended Grace" { "warnings"; break }
        "Out of Tolerance" { "warnings"; break }
        "No Windows licensing row found" { "warnings"; break }
        "Unknown" { "warnings"; break }
        "Unlicensed" { "errors"; break }
        "Non-Genuine" { "errors"; break }
        "ERROR:*" { "errors"; break }
        default { "warnings"; break }
    }
}

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath   = Join-Path $OutputFolder ("WindowsActivation_{0}.csv" -f $timestamp)
$htmlPath  = Join-Path $OutputFolder ("WindowsActivation_{0}.html" -f $timestamp)

$results = foreach ($s in ($Servers | Sort-Object -Unique)) {
    try {
        $lic = Get-CimInstance -ComputerName $s -ClassName SoftwareLicensingProduct -ErrorAction Stop |
            Where-Object {
                $_.PartialProductKey -and
                $_.Name -match "Windows"
            } |
            Sort-Object Name |
            Select-Object -First 1

        if ($null -eq $lic) {
            $statusText = "No Windows licensing row found"

            [PSCustomObject]@{
                Server          = $s
                Status          = $statusText
                LicenseStatus   = ""
                Product         = ""
                PartialKey      = ""
                Description     = ""
                ErrorMessage    = ""
                IsProblem       = $true
                SummaryCategory = (Get-SummaryCategory -Status $statusText)
            }
            continue
        }

        $statusText = Get-LicenseStatusText -Status $lic.LicenseStatus

        [PSCustomObject]@{
            Server          = $s
            Status          = $statusText
            LicenseStatus   = [int]$lic.LicenseStatus
            Product         = [string]$lic.Name
            PartialKey      = [string]$lic.PartialProductKey
            Description     = [string]$lic.Description
            ErrorMessage    = ""
            IsProblem       = (Get-IsProblem -Status $statusText)
            SummaryCategory = (Get-SummaryCategory -Status $statusText)
        }
    }
    catch {
        $statusText = "ERROR: $($_.Exception.Message)"

        [PSCustomObject]@{
            Server          = $s
            Status          = $statusText
            LicenseStatus   = ""
            Product         = ""
            PartialKey      = ""
            Description     = ""
            ErrorMessage    = $_.Exception.Message
            IsProblem       = $true
            SummaryCategory = (Get-SummaryCategory -Status $statusText)
        }
    }
}

$results = $results | Sort-Object Server

$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$totalCount    = $results.Count
$licensedCount = ($results | Where-Object { $_.SummaryCategory -eq "licensed" }).Count
$warningCount  = ($results | Where-Object { $_.SummaryCategory -eq "warnings" }).Count
$errorCount    = ($results | Where-Object { $_.SummaryCategory -eq "errors" }).Count
$problemCount  = ($results | Where-Object { $_.IsProblem -eq $true }).Count
$generatedAt   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$rowsHtml = foreach ($r in $results) {
    $statusClass = Get-StatusClass -Status $r.Status
    $problemText = if ($r.IsProblem) { "true" } else { "false" }

@"
<tr data-problem="$problemText" data-summary-category="$(New-SafeHtml $r.SummaryCategory)">
    <td>$(New-SafeHtml $r.Server)</td>
    <td data-sort-value="$(New-SafeHtml $r.Status)"><span class="badge $statusClass">$(New-SafeHtml $r.Status)</span></td>
    <td data-sort-value="$(New-SafeHtml $r.LicenseStatus)">$(New-SafeHtml $r.LicenseStatus)</td>
    <td>$(New-SafeHtml $r.Product)</td>
    <td>$(New-SafeHtml $r.PartialKey)</td>
    <td>$(New-SafeHtml $r.Description)</td>
    <td>$(New-SafeHtml $r.ErrorMessage)</td>
</tr>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="fi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Windows Activation Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:#f7f9fc;color:#1f2937}
h1,h2,h3{margin:0 0 10px 0}
.meta,.summary,.section,.toolbar,.notes{background:#fff;border:1px solid #dbe2ea;border-radius:10px;padding:16px;margin-bottom:18px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.summary h2,.section h2{font-size:20px;margin-bottom:8px}
.summary-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px}
@media (max-width:1400px){.summary-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:1000px){.summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:640px){.summary-grid{grid-template-columns:repeat(1,minmax(0,1fr))}}

.card{
    background:#f8fafc;border:1px solid #e6edf5;border-radius:10px;padding:14px;
    box-shadow:0 1px 2px rgba(0,0,0,.03)
}
.card .label{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px}
.card .value{font-size:28px;font-weight:700;line-height:1.1}
.card .subvalue{margin-top:8px;font-size:12px;color:#64748b}
.card.total{border-left:5px solid #64748b}
.card.ok{border-left:5px solid #16a34a}
.card.warn{border-left:5px solid #d97706}
.card.err{border-left:5px solid #dc2626}
.card.problem{border-left:5px solid #7c3aed}

.summary-btn{
    appearance:none;
    -webkit-appearance:none;
    width:100%;
    text-align:left;
    cursor:pointer;
    transition:transform .08s ease, box-shadow .12s ease, border-color .12s ease, background .12s ease, outline-color .12s ease;
}
.summary-btn:hover{
    transform:translateY(-1px);
    box-shadow:0 4px 10px rgba(0,0,0,.06);
    background:#fbfdff;
}
.summary-btn:active{
    transform:translateY(0);
}
.summary-btn.active{
    outline:2px solid #0f172a;
    outline-offset:1px;
    background:#eef4ff;
}
.summary-btn.active.total{background:#eef2f7}
.summary-btn.active.ok{background:#ecfdf5}
.summary-btn.active.warn{background:#fffbeb}
.summary-btn.active.err{background:#fef2f2}
.summary-btn.active.problem{background:#f5f3ff}

.toolbar-grid{display:grid;grid-template-columns:2fr 220px 220px auto;gap:12px;align-items:end}
@media (max-width:1100px){.toolbar-grid{grid-template-columns:1fr 1fr}}
@media (max-width:700px){.toolbar-grid{grid-template-columns:1fr}}
.field label{display:block;font-size:12px;color:#64748b;margin-bottom:6px;font-weight:600}
.field input,.field select{
    width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #cfd8e3;border-radius:8px;
    background:#fff;color:#1f2937;font-size:14px
}
.checkbox-row{display:flex;gap:10px;align-items:center;padding-top:28px;flex-wrap:wrap}
.btn{
    display:inline-flex;align-items:center;justify-content:center;gap:8px;
    border:1px solid #cfd8e3;background:#fff;border-radius:8px;padding:10px 14px;
    font-size:14px;cursor:pointer;color:#1f2937
}
.btn:hover{background:#f8fafc}

.table-wrap{overflow:auto;border:1px solid #dbe2ea;border-radius:10px}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{padding:10px 12px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}
th{
    position:sticky;top:0;background:#eef3f8;color:#0f172a;z-index:2;
    user-select:none;cursor:pointer;white-space:nowrap
}
th:hover{background:#e5edf6}
tr:hover td{background:#f8fafc}
th .sort-ind{font-size:11px;color:#64748b;margin-left:6px}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;border:1px solid transparent;white-space:nowrap}
.badge.ok{background:#dcfce7;color:#166534;border-color:#bbf7d0}
.badge.warn{background:#fef3c7;color:#92400e;border-color:#fde68a}
.badge.err{background:#fee2e2;color:#991b1b;border-color:#fecaca}
.small{font-size:12px;color:#64748b}
.meta-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
@media (max-width:900px){.meta-grid{grid-template-columns:repeat(1,minmax(0,1fr))}}
.kv{font-size:14px}
.kv .k{display:block;color:#64748b;font-size:12px;text-transform:uppercase;margin-bottom:4px}
.count-pill{
    display:inline-block;padding:3px 8px;border-radius:999px;background:#eef2ff;color:#3730a3;
    font-size:12px;font-weight:700;border:1px solid #c7d2fe
}
.hidden-row{display:none}
.muted{color:#64748b}
</style>
</head>
<body>

<div class="meta">
    <h1>Windows Activation Report</h1>
    <div class="meta-grid">
        <div class="kv"><span class="k">Generated</span>$generatedAt</div>
    </div>
</div>

<div class="summary">
    <h2>Summary</h2>
    <div class="summary-grid">
        <button type="button" class="card total summary-btn active" data-summary-filter="all">
            <div class="label">Total servers</div>
            <div class="value" data-kpi="total">$totalCount</div>
            <div class="subvalue">Visible / all</div>
        </button>

        <button type="button" class="card ok summary-btn" data-summary-filter="licensed">
            <div class="label">Licensed</div>
            <div class="value" data-kpi="licensed">$licensedCount</div>
            <div class="subvalue">Currently visible matching rows</div>
        </button>

        <button type="button" class="card warn summary-btn" data-summary-filter="warnings">
            <div class="label">Warnings</div>
            <div class="value" data-kpi="warnings">$warningCount</div>
            <div class="subvalue">Notification / grace / unknown</div>
        </button>

        <button type="button" class="card err summary-btn" data-summary-filter="errors">
            <div class="label">Errors / bad status</div>
            <div class="value" data-kpi="errors">$errorCount</div>
            <div class="subvalue">Query errors / invalid license states</div>
        </button>

        <button type="button" class="card problem summary-btn" data-summary-filter="problems">
            <div class="label">All problems</div>
            <div class="value" data-kpi="problems">$problemCount</div>
            <div class="subvalue">Everything except Licensed</div>
        </button>
    </div>
</div>

<div class="toolbar">
    <h2>Filters</h2>
    <div class="toolbar-grid">
        <div class="field">
            <label for="quickFilter">Quick filter</label>
            <input type="text" id="quickFilter" placeholder="Filter by server, status, product, description, error...">
        </div>

        <div class="field">
            <label for="statusFilter">Status filter</label>
            <select id="statusFilter">
                <option value="">All statuses</option>
                <option value="Licensed">Licensed</option>
                <option value="Notification">Notification</option>
                <option value="OOB Grace">OOB Grace</option>
                <option value="Extended Grace">Extended Grace</option>
                <option value="Out of Tolerance">Out of Tolerance</option>
                <option value="Unlicensed">Unlicensed</option>
                <option value="Non-Genuine">Non-Genuine</option>
                <option value="No Windows licensing row found">No Windows licensing row found</option>
                <option value="ERROR:">ERROR</option>
                <option value="Unknown">Unknown</option>
            </select>
        </div>

        <div class="field">
            <label for="problemFilter">Preset view</label>
            <select id="problemFilter">
                <option value="all">Show all</option>
                <option value="problems">Show only problems</option>
                <option value="licensed">Show only licensed</option>
            </select>
        </div>

        <div class="checkbox-row">
            <button type="button" class="btn" id="resetFiltersBtn">Reset filters</button>
            <span class="count-pill">Visible rows: <span id="visibleCount">$totalCount</span></span>
        </div>
    </div>
</div>

<div class="section">
    <h2>Results</h2>
    <div class="small" style="margin-bottom:10px;">
        Click a column header to sort. Koska taulukko ei tietenkään voi vain pysyä paikallaan ja käyttäytyä.
    </div>
    <div class="table-wrap">
        <table id="resultsTable">
            <thead>
                <tr>
                    <th data-col="0" data-type="text">Server <span class="sort-ind">⇅</span></th>
                    <th data-col="1" data-type="text">Status <span class="sort-ind">⇅</span></th>
                    <th data-col="2" data-type="number">LicenseStatus <span class="sort-ind">⇅</span></th>
                    <th data-col="3" data-type="text">Product <span class="sort-ind">⇅</span></th>
                    <th data-col="4" data-type="text">Partial Key <span class="sort-ind">⇅</span></th>
                    <th data-col="5" data-type="text">Description <span class="sort-ind">⇅</span></th>
                    <th data-col="6" data-type="text">Error <span class="sort-ind">⇅</span></th>
                </tr>
            </thead>
            <tbody>
$($rowsHtml -join "`r`n")
            </tbody>
        </table>
    </div>
</div>

<div class="notes">
    <h2>Status guide</h2>
    <div><strong>Licensed</strong> = activated normally</div>
    <div><strong>Notification</strong> = activation problem or grace expired, Windows is in reminder / notification mode</div>
    <div><strong>Unlicensed / Non-Genuine</strong> = license not valid</div>
    <div><strong>ERROR</strong> = query failed, commonly connectivity, permissions, RPC, firewall, WMI/CIM or DNS related</div>
</div>

<script>
(function () {
    const quickFilter = document.getElementById('quickFilter');
    const statusFilter = document.getElementById('statusFilter');
    const problemFilter = document.getElementById('problemFilter');
    const resetFiltersBtn = document.getElementById('resetFiltersBtn');
    const visibleCountEl = document.getElementById('visibleCount');
    const table = document.getElementById('resultsTable');
    const tbody = table.querySelector('tbody');
    const headers = table.querySelectorAll('thead th');
    const summaryButtons = document.querySelectorAll('.summary-btn');

    const kpiTotal = document.querySelector('[data-kpi="total"]');
    const kpiLicensed = document.querySelector('[data-kpi="licensed"]');
    const kpiWarnings = document.querySelector('[data-kpi="warnings"]');
    const kpiErrors = document.querySelector('[data-kpi="errors"]');
    const kpiProblems = document.querySelector('[data-kpi="problems"]');

    let summaryFilter = 'all';

    function normalize(text) {
        return (text || '').toString().toLowerCase().trim();
    }

    function getRowText(row) {
        return normalize(row.innerText || row.textContent || '');
    }

    function getStatusText(row) {
        const statusCell = row.cells[1];
        return normalize(statusCell ? (statusCell.innerText || statusCell.textContent || '') : '');
    }

    function getSummaryCategory(row) {
        return normalize(row.getAttribute('data-summary-category') || '');
    }

    function getIsProblem(row) {
        return normalize(row.getAttribute('data-problem') || '') === 'true';
    }

    function rowMatchesStatus(row, wanted) {
        if (!wanted) return true;

        const statusText = getStatusText(row);

        if (wanted === 'ERROR:') {
            return statusText.startsWith('error:');
        }

        return statusText === normalize(wanted);
    }

    function rowMatchesProblemPreset(row, preset) {
        const isProblem = getIsProblem(row);
        const statusText = getStatusText(row);

        if (preset === 'problems') return isProblem;
        if (preset === 'licensed') return statusText === 'licensed';
        return true;
    }

    function rowMatchesSummaryFilter(row, currentSummaryFilter) {
        if (!currentSummaryFilter || currentSummaryFilter === 'all') return true;

        const category = getSummaryCategory(row);
        const isProblem = getIsProblem(row);

        if (currentSummaryFilter === 'problems') return isProblem;
        if (currentSummaryFilter === 'licensed') return category === 'licensed';
        if (currentSummaryFilter === 'warnings') return category === 'warnings';
        if (currentSummaryFilter === 'errors') return category === 'errors';

        return true;
    }

    function updateSummaryButtons() {
        summaryButtons.forEach(btn => {
            const value = btn.getAttribute('data-summary-filter') || 'all';
            btn.classList.toggle('active', value === summaryFilter);
        });
    }

    function getRowsPassingNonSummaryFilters() {
        const q = normalize(quickFilter.value);
        const wantedStatus = statusFilter.value;
        const preset = problemFilter.value;

        return Array.from(tbody.rows).filter(row => {
            const textOk = !q || getRowText(row).includes(q);
            const statusOk = rowMatchesStatus(row, wantedStatus);
            const presetOk = rowMatchesProblemPreset(row, preset);
            return textOk && statusOk && presetOk;
        });
    }

    function updateKpis(baseRows) {
        const total = baseRows.length;
        const licensed = baseRows.filter(row => getSummaryCategory(row) === 'licensed').length;
        const warnings = baseRows.filter(row => getSummaryCategory(row) === 'warnings').length;
        const errors = baseRows.filter(row => getSummaryCategory(row) === 'errors').length;
        const problems = baseRows.filter(row => getIsProblem(row)).length;

        if (kpiTotal) kpiTotal.textContent = total.toString();
        if (kpiLicensed) kpiLicensed.textContent = licensed.toString();
        if (kpiWarnings) kpiWarnings.textContent = warnings.toString();
        if (kpiErrors) kpiErrors.textContent = errors.toString();
        if (kpiProblems) kpiProblems.textContent = problems.toString();
    }

    function applyFilters() {
        const baseRows = getRowsPassingNonSummaryFilters();

        let visible = 0;

        Array.from(tbody.rows).forEach(row => {
            const baseMatch = baseRows.includes(row);
            const summaryOk = baseMatch && rowMatchesSummaryFilter(row, summaryFilter);

            row.style.display = summaryOk ? '' : 'none';

            if (summaryOk) visible++;
        });

        visibleCountEl.textContent = visible.toString();
        updateKpis(baseRows);
        updateSummaryButtons();
    }

    function getCellSortValue(row, colIndex) {
        const cell = row.cells[colIndex];
        if (!cell) return '';

        const attr = cell.getAttribute('data-sort-value');
        if (attr !== null) return attr;

        return (cell.innerText || cell.textContent || '').trim();
    }

    function sortTable(colIndex, type, th) {
        const currentDir = th.getAttribute('data-sort-dir') || 'none';
        const newDir = currentDir === 'asc' ? 'desc' : 'asc';

        headers.forEach(h => {
            h.setAttribute('data-sort-dir', 'none');
            const ind = h.querySelector('.sort-ind');
            if (ind) ind.textContent = '⇅';
        });

        th.setAttribute('data-sort-dir', newDir);
        const ind = th.querySelector('.sort-ind');
        if (ind) ind.textContent = newDir === 'asc' ? '▲' : '▼';

        const rows = Array.from(tbody.rows);

        rows.sort((a, b) => {
            let aVal = getCellSortValue(a, colIndex);
            let bVal = getCellSortValue(b, colIndex);

            if (type === 'number') {
                const aNum = parseFloat(aVal);
                const bNum = parseFloat(bVal);

                const aMissing = Number.isNaN(aNum);
                const bMissing = Number.isNaN(bNum);

                if (aMissing && bMissing) return 0;
                if (aMissing) return 1;
                if (bMissing) return -1;

                return newDir === 'asc' ? (aNum - bNum) : (bNum - aNum);
            } else {
                aVal = aVal.toString().toLowerCase();
                bVal = bVal.toString().toLowerCase();

                if (aVal < bVal) return newDir === 'asc' ? -1 : 1;
                if (aVal > bVal) return newDir === 'asc' ? 1 : -1;
                return 0;
            }
        });

        rows.forEach(row => tbody.appendChild(row));
        applyFilters();
    }

    quickFilter.addEventListener('input', applyFilters);
    statusFilter.addEventListener('change', applyFilters);
    problemFilter.addEventListener('change', applyFilters);

    resetFiltersBtn.addEventListener('click', function () {
        quickFilter.value = '';
        statusFilter.value = '';
        problemFilter.value = 'all';
        summaryFilter = 'all';
        applyFilters();
    });

    summaryButtons.forEach(btn => {
        btn.addEventListener('click', function () {
            summaryFilter = btn.getAttribute('data-summary-filter') || 'all';
            applyFilters();
        });
    });

    headers.forEach(th => {
        th.addEventListener('click', function () {
            const colIndex = parseInt(th.getAttribute('data-col'), 10);
            const type = th.getAttribute('data-type') || 'text';
            sortTable(colIndex, type, th);
        });
    });

    applyFilters();
})();
</script>

</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host ""
Write-Host "Valmis." -ForegroundColor Green
Write-Host "CSV : $csvPath"
Write-Host "HTML: $htmlPath"
Write-Host ""

$results | Format-Table Server, Status, Product -AutoSize
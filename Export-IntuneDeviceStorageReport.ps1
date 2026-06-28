<#
.SYNOPSIS
    Intune Device Storage Report.

.DESCRIPTION
    Raportoi Intune-laitteiden tallennustilan kokonaismäärän, vapaan tilan ja käyttöasteen kapasiteettiseurantaa varten.

.REQUIREMENTS
    - Microsoft Graph PowerShell -moduulit ja Intune-laitetietojen lukuoikeudet

.OUTPUTS
    - CSV/HTML-raportti laitteiden tallennustilasta

.EXAMPLE
    .\Export-IntuneDeviceStorageReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Export-IntuneDeviceStorageReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

# Export-IntuneWindowsDeviceStorageReport.ps1
# Intune Windows Device Storage Report
#
# READ-ONLY:
# - Reads Intune managed device data from Microsoft Graph
# - Filters only Windows devices
# - Exports local CSV and interactive HTML reports
# - Does NOT modify Intune, devices, users, compliance, settings, or policies

$OutDir = Join-Path $PSScriptRoot "output\intune-reports"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$CsvFile  = Join-Path $OutDir "Intune_Windows_Device_Storage_Report_$Timestamp.csv"
$HtmlFile = Join-Path $OutDir "Intune_Windows_Device_Storage_Report_$Timestamp.html"

New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

Write-Host ""
Write-Host "=== Intune Windows Device Storage Report ===" -ForegroundColor Cyan
Write-Host "Read-only audit. Haetaan vain Windows-laitteet." -ForegroundColor DarkGray
Write-Host ""

Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -NoWelcome

Write-Host "Haetaan Intune-laitteet Microsoft Graphista..." -ForegroundColor Cyan

$AllDevices = Get-MgDeviceManagementManagedDevice -All -Property `
    "deviceName,userPrincipalName,operatingSystem,osVersion,lastSyncDateTime,totalStorageSpaceInBytes,freeStorageSpaceInBytes"

$Devices = $AllDevices | Where-Object {
    $_.OperatingSystem -eq "Windows"
}

$Total = $Devices.Count
$Counter = 0

Write-Host "Laitteita yhteensä Intunessa: $($AllDevices.Count)" -ForegroundColor DarkGray
Write-Host "Windows-laitteita raporttiin: $Total" -ForegroundColor Cyan
Write-Host ""

$Report = foreach ($Device in $Devices) {
    $Counter++

    $PercentComplete = if ($Total -gt 0) {
        [math]::Round(($Counter / $Total) * 100, 0)
    }
    else {
        100
    }

    Write-Progress `
        -Activity "Luodaan Intune Windows storage -raporttia" `
        -Status "$Counter / $Total : $($Device.DeviceName)" `
        -PercentComplete $PercentComplete

    $TotalBytes = [double]$Device.TotalStorageSpaceInBytes
    $FreeBytes  = [double]$Device.FreeStorageSpaceInBytes

    $TotalGB = if ($TotalBytes -gt 0) {
        [math]::Round($TotalBytes / 1GB, 2)
    }
    else {
        $null
    }

    $FreeGB = if ($FreeBytes -ge 0) {
        [math]::Round($FreeBytes / 1GB, 2)
    }
    else {
        $null
    }

    $UsedGB = if ($TotalBytes -gt 0 -and $FreeBytes -ge 0) {
        [math]::Round(($TotalBytes - $FreeBytes) / 1GB, 2)
    }
    else {
        $null
    }

    $FreePercent = if ($TotalBytes -gt 0) {
        [math]::Round(($FreeBytes / $TotalBytes) * 100, 1)
    }
    else {
        $null
    }

    $StorageStatus = if ($null -eq $FreePercent) {
        "Unknown"
    }
    elseif ($FreePercent -lt 10) {
        "Critical"
    }
    elseif ($FreePercent -lt 15) {
        "Warning"
    }
    elseif ($FreePercent -lt 20) {
        "Notice"
    }
    else {
        "OK"
    }

    [PSCustomObject]@{
        DeviceName        = $Device.DeviceName
        UserPrincipalName = $Device.UserPrincipalName
        OperatingSystem   = $Device.OperatingSystem
        OSVersion         = $Device.OsVersion
        LastSyncDateTime  = if ($Device.LastSyncDateTime) {
            ([datetime]$Device.LastSyncDateTime).ToString("dd.MM.yyyy HH:mm:ss")
        }
        else {
            ""
        }

        TotalGB           = $TotalGB
        FreeGB            = $FreeGB
        UsedGB            = $UsedGB
        FreePercent       = $FreePercent
        StorageStatus     = $StorageStatus
    }
}

Write-Progress `
    -Activity "Luodaan Intune Windows storage -raporttia" `
    -Completed

$Report = $Report | Sort-Object FreePercent

$Report |
    Export-Csv $CsvFile -NoTypeInformation -Encoding UTF8 -Delimiter ";"

$TotalWindows = $Report.Count
$Critical = ($Report | Where-Object { $_.StorageStatus -eq "Critical" }).Count
$Warning  = ($Report | Where-Object { $_.StorageStatus -eq "Warning" }).Count
$Notice   = ($Report | Where-Object { $_.StorageStatus -eq "Notice" }).Count
$OK       = ($Report | Where-Object { $_.StorageStatus -eq "OK" }).Count
$Unknown  = ($Report | Where-Object { $_.StorageStatus -eq "Unknown" }).Count

$GeneratedAt = Get-Date -Format "dd.MM.yyyy HH:mm:ss"

# JSON for HTML/JavaScript
$DeviceDataJson = $Report | ConvertTo-Json -Depth 4 -Compress

# Prevent rare </script> breakage
$DeviceDataJson = $DeviceDataJson -replace '</script>', '<\/script>'

$Html = @"
<!DOCTYPE html>
<html lang="fi">
<head>
<meta charset="UTF-8">
<title>Intune Windows Device Storage Report</title>
<style>
    :root {
        --bg: #0f172a;
        --panel: #111827;
        --panel2: #1f2937;
        --text: #e5e7eb;
        --muted: #9ca3af;
        --border: #374151;
        --ok: #16a34a;
        --notice: #2563eb;
        --warning: #f59e0b;
        --critical: #dc2626;
        --unknown: #6b7280;
        --button: #334155;
        --button-active: #475569;
    }

    * {
        box-sizing: border-box;
    }

    body {
        margin: 0;
        padding: 24px;
        background: var(--bg);
        color: var(--text);
        font-family: Segoe UI, Arial, sans-serif;
        font-size: 14px;
    }

    h1, h2 {
        margin: 0 0 12px 0;
    }

    h1 {
        font-size: 28px;
    }

    h2 {
        font-size: 20px;
    }

    .subtitle {
        color: var(--muted);
        margin-bottom: 24px;
    }

    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 14px;
        margin-bottom: 28px;
    }

    .card {
        background: linear-gradient(180deg, var(--panel2), var(--panel));
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 16px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.20);
    }

    .card.summary-filter {
        text-align: left;
        cursor: pointer;
        color: var(--text);
        width: 100%;
    }

    .card.summary-filter:hover {
        border-color: #93c5fd;
        transform: translateY(-1px);
    }

    .card.summary-filter.active {
        outline: 2px solid #93c5fd;
        background: linear-gradient(180deg, #253247, var(--panel));
    }

    .card .label {
        color: #93c5fd;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }

    .card .value {
        font-size: 30px;
        font-weight: 700;
        margin-top: 8px;
    }

    .value.ok { color: var(--ok); }
    .value.notice { color: var(--notice); }
    .value.warning { color: var(--warning); }
    .value.critical { color: var(--critical); }
    .value.unknown { color: var(--unknown); }

    .section {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 18px;
        margin-top: 18px;
        overflow-x: auto;
    }

    .toolbar {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 14px;
    }

    .filters {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
    }

    button,
    select,
    input {
        background: var(--button);
        color: var(--text);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 8px 11px;
        font: inherit;
    }

    button {
        cursor: pointer;
    }

    button:hover {
        background: var(--button-active);
    }

    button.active {
        outline: 2px solid #93c5fd;
        background: var(--button-active);
    }

    button:disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    input {
        min-width: 280px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        min-width: 1100px;
    }

    th, td {
        border-bottom: 1px solid var(--border);
        padding: 10px 12px;
        text-align: left;
        vertical-align: middle;
        white-space: nowrap;
    }

    th {
        color: #f9fafb;
        background: #020617;
        position: sticky;
        top: 0;
        z-index: 1;
        cursor: pointer;
        user-select: none;
    }

    th:hover {
        background: #111827;
    }

    th.sort-asc::after {
        content: " ▲";
        color: #93c5fd;
    }

    th.sort-desc::after {
        content: " ▼";
        color: #93c5fd;
    }

    tr:hover {
        background: rgba(255,255,255,0.04);
    }

    .num {
        text-align: right;
        font-variant-numeric: tabular-nums;
    }

    .badge {
        display: inline-block;
        padding: 4px 9px;
        border-radius: 999px;
        font-size: 12px;
        font-weight: 700;
    }

    .status-ok {
        background: rgba(22, 163, 74, 0.18);
        color: #86efac;
        border: 1px solid rgba(22, 163, 74, 0.45);
    }

    .status-notice {
        background: rgba(37, 99, 235, 0.18);
        color: #93c5fd;
        border: 1px solid rgba(37, 99, 235, 0.45);
    }

    .status-warning {
        background: rgba(245, 158, 11, 0.18);
        color: #fcd34d;
        border: 1px solid rgba(245, 158, 11, 0.45);
    }

    .status-critical {
        background: rgba(220, 38, 38, 0.18);
        color: #fca5a5;
        border: 1px solid rgba(220, 38, 38, 0.45);
    }

    .status-unknown {
        background: rgba(107, 114, 128, 0.18);
        color: #d1d5db;
        border: 1px solid rgba(107, 114, 128, 0.45);
    }

    .pagination {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
        justify-content: space-between;
        margin-top: 14px;
        color: var(--muted);
    }

    .note {
        color: var(--muted);
        margin-top: 10px;
        line-height: 1.5;
    }

    .footer {
        margin-top: 28px;
        color: var(--muted);
        font-size: 12px;
    }

    @media print {
        body {
            background: white;
            color: black;
            padding: 12px;
        }

        .card,
        .section {
            background: white;
            color: black;
            border: 1px solid #ccc;
            box-shadow: none;
        }

        th {
            background: #eee;
            color: black;
        }

        .subtitle,
        .note,
        .footer {
            color: #444;
        }

        .toolbar,
        .pagination {
            display: none;
        }
    }
</style>
</head>
<body>

<h1>Intune Windows Device Storage Report</h1>
<div class="subtitle">
    Generated: $GeneratedAt |
    Source: Microsoft Graph / Intune managed devices |
    Mode: Read-only
</div>

<div class="grid">
    <button type="button" class="card summary-filter active" data-filter="All">
        <div class="label">Windows devices</div>
        <div class="value">$TotalWindows</div>
    </button>

    <button type="button" class="card summary-filter" data-filter="Critical">
        <div class="label">Critical &lt; 10%</div>
        <div class="value critical">$Critical</div>
    </button>

    <button type="button" class="card summary-filter" data-filter="Warning">
        <div class="label">Warning &lt; 15%</div>
        <div class="value warning">$Warning</div>
    </button>

    <button type="button" class="card summary-filter" data-filter="Notice">
        <div class="label">Notice &lt; 20%</div>
        <div class="value notice">$Notice</div>
    </button>

    <button type="button" class="card summary-filter" data-filter="OK">
        <div class="label">OK</div>
        <div class="value ok">$OK</div>
    </button>

    <button type="button" class="card summary-filter" data-filter="Unknown">
        <div class="label">Unknown</div>
        <div class="value unknown">$Unknown</div>
    </button>
</div>

<div class="section">
    <h2>Top 20 devices with lowest free storage</h2>

    <table id="topTable">
        <thead>
            <tr>
                <th data-key="DeviceName" data-type="text">Device</th>
                <th data-key="UserPrincipalName" data-type="text">User</th>
                <th data-key="OSVersion" data-type="text">OS version</th>
                <th data-key="TotalGB" data-type="number">Total GB</th>
                <th data-key="FreeGB" data-type="number">Free GB</th>
                <th data-key="UsedGB" data-type="number">Used GB</th>
                <th data-key="FreePercent" data-type="number">Free %</th>
                <th data-key="StorageStatus" data-type="status">Status</th>
                <th data-key="LastSyncDateTime" data-type="text">Last sync</th>
            </tr>
        </thead>
        <tbody id="topTableBody"></tbody>
    </table>
</div>

<div class="section" id="allDevicesSection">
    <h2>All Windows devices</h2>

    <div class="toolbar">
        <div class="filters">
            <button type="button" class="filter-btn active" data-filter="All">All ($TotalWindows)</button>
            <button type="button" class="filter-btn" data-filter="Critical">Critical ($Critical)</button>
            <button type="button" class="filter-btn" data-filter="Warning">Warning ($Warning)</button>
            <button type="button" class="filter-btn" data-filter="Notice">Notice ($Notice)</button>
            <button type="button" class="filter-btn" data-filter="OK">OK ($OK)</button>
            <button type="button" class="filter-btn" data-filter="Unknown">Unknown ($Unknown)</button>
        </div>

        <div class="filters">
            <input type="search" id="searchBox" placeholder="Search device, user, OS version...">
            <label>
                Rows per page:
                <select id="pageSize">
                    <option value="10">10</option>
                    <option value="25" selected>25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                    <option value="all">All</option>
                </select>
            </label>
        </div>
    </div>

    <table id="deviceTable">
        <thead>
            <tr>
                <th data-key="DeviceName" data-type="text">Device</th>
                <th data-key="UserPrincipalName" data-type="text">User</th>
                <th data-key="OperatingSystem" data-type="text">OS</th>
                <th data-key="OSVersion" data-type="text">OS version</th>
                <th data-key="TotalGB" data-type="number">Total GB</th>
                <th data-key="FreeGB" data-type="number">Free GB</th>
                <th data-key="UsedGB" data-type="number">Used GB</th>
                <th data-key="FreePercent" data-type="number">Free %</th>
                <th data-key="StorageStatus" data-type="status">Status</th>
                <th data-key="LastSyncDateTime" data-type="text">Last sync</th>
            </tr>
        </thead>
        <tbody id="deviceTableBody"></tbody>
    </table>

    <div class="pagination">
        <div id="resultInfo">Showing results</div>
        <div>
            <button type="button" id="prevPage">Previous</button>
            <span id="pageInfo"></span>
            <button type="button" id="nextPage">Next</button>
        </div>
    </div>

    <div class="note">
        Click column headers to sort. Use status buttons or summary cards to show only selected device groups.
    </div>
</div>

<div class="footer">
    This report is generated locally from Intune managedDevice read-only data.
    No Intune settings, devices, users, compliance states, or policies were modified.
</div>

<script>
const deviceData = $DeviceDataJson;

const statusOrder = {
    Critical: 1,
    Warning: 2,
    Notice: 3,
    OK: 4,
    Unknown: 5
};

function escapeHtml(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function statusClass(status) {
    switch (status) {
        case "Critical":
            return "status-critical";
        case "Warning":
            return "status-warning";
        case "Notice":
            return "status-notice";
        case "OK":
            return "status-ok";
        default:
            return "status-unknown";
    }
}

function formatNumber(value, suffix) {
    if (value === null || value === undefined || value === "") {
        return "";
    }

    return escapeHtml(value) + (suffix || "");
}

function compareValues(a, b, key, type, direction) {
    let av = a[key];
    let bv = b[key];

    if (type === "number") {
        av = Number(av);
        bv = Number(bv);

        if (Number.isNaN(av)) av = Number.POSITIVE_INFINITY;
        if (Number.isNaN(bv)) bv = Number.POSITIVE_INFINITY;

        return direction === "asc" ? av - bv : bv - av;
    }

    if (type === "status") {
        av = statusOrder[av] || 99;
        bv = statusOrder[bv] || 99;

        return direction === "asc" ? av - bv : bv - av;
    }

    av = av === null || av === undefined ? "" : String(av).toLowerCase();
    bv = bv === null || bv === undefined ? "" : String(bv).toLowerCase();

    const result = av.localeCompare(bv, "fi", {
        numeric: true,
        sensitivity: "base"
    });

    return direction === "asc" ? result : -result;
}

function createRow(item, includeOsColumn) {
    const badge = '<span class="badge ' + statusClass(item.StorageStatus) + '">' + escapeHtml(item.StorageStatus) + '</span>';

    if (includeOsColumn) {
        return '<tr>' +
            '<td>' + escapeHtml(item.DeviceName) + '</td>' +
            '<td>' + escapeHtml(item.UserPrincipalName) + '</td>' +
            '<td>' + escapeHtml(item.OperatingSystem) + '</td>' +
            '<td>' + escapeHtml(item.OSVersion) + '</td>' +
            '<td class="num">' + formatNumber(item.TotalGB) + '</td>' +
            '<td class="num">' + formatNumber(item.FreeGB) + '</td>' +
            '<td class="num">' + formatNumber(item.UsedGB) + '</td>' +
            '<td class="num">' + formatNumber(item.FreePercent, " %") + '</td>' +
            '<td>' + badge + '</td>' +
            '<td>' + escapeHtml(item.LastSyncDateTime) + '</td>' +
            '</tr>';
    }

    return '<tr>' +
        '<td>' + escapeHtml(item.DeviceName) + '</td>' +
        '<td>' + escapeHtml(item.UserPrincipalName) + '</td>' +
        '<td>' + escapeHtml(item.OSVersion) + '</td>' +
        '<td class="num">' + formatNumber(item.TotalGB) + '</td>' +
        '<td class="num">' + formatNumber(item.FreeGB) + '</td>' +
        '<td class="num">' + formatNumber(item.UsedGB) + '</td>' +
        '<td class="num">' + formatNumber(item.FreePercent, " %") + '</td>' +
        '<td>' + badge + '</td>' +
        '<td>' + escapeHtml(item.LastSyncDateTime) + '</td>' +
        '</tr>';
}

function setupSortableTable(options) {
    const table = document.getElementById(options.tableId);
    const tbody = document.getElementById(options.bodyId);
    const headers = table.querySelectorAll("th");

    let sortKey = options.defaultSortKey || "FreePercent";
    let sortType = options.defaultSortType || "number";
    let sortDirection = options.defaultSortDirection || "asc";

    function getRows() {
        return options.getData();
    }

    function render() {
        let rows = getRows().slice();

        rows.sort(function(a, b) {
            return compareValues(a, b, sortKey, sortType, sortDirection);
        });

        if (options.limit) {
            rows = rows.slice(0, options.limit);
        }

        tbody.innerHTML = rows.map(function(item) {
            return createRow(item, options.includeOsColumn);
        }).join("");

        headers.forEach(function(header) {
            header.classList.remove("sort-asc", "sort-desc");

            if (header.getAttribute("data-key") === sortKey) {
                header.classList.add(sortDirection === "asc" ? "sort-asc" : "sort-desc");
            }
        });

        if (typeof options.afterRender === "function") {
            options.afterRender(rows.length);
        }
    }

    headers.forEach(function(header) {
        header.addEventListener("click", function() {
            const clickedKey = header.getAttribute("data-key");
            const clickedType = header.getAttribute("data-type") || "text";

            if (sortKey === clickedKey) {
                sortDirection = sortDirection === "asc" ? "desc" : "asc";
            }
            else {
                sortKey = clickedKey;
                sortType = clickedType;
                sortDirection = "asc";
            }

            render();
        });
    });

    return {
        render: render
    };
}

let currentFilter = "All";
let currentPage = 1;
let allTableSortKey = "FreePercent";
let allTableSortType = "number";
let allTableSortDirection = "asc";

const searchBox = document.getElementById("searchBox");
const pageSizeSelect = document.getElementById("pageSize");
const resultInfo = document.getElementById("resultInfo");
const pageInfo = document.getElementById("pageInfo");
const prevPageButton = document.getElementById("prevPage");
const nextPageButton = document.getElementById("nextPage");
const deviceTable = document.getElementById("deviceTable");
const deviceTableBody = document.getElementById("deviceTableBody");
const deviceHeaders = deviceTable.querySelectorAll("th");
const filterButtons = document.querySelectorAll(".filter-btn, .summary-filter");

function getFilteredDeviceData() {
    const search = searchBox.value.trim().toLowerCase();

    return deviceData.filter(function(item) {
        const statusMatch = currentFilter === "All" || item.StorageStatus === currentFilter;

        if (!statusMatch) {
            return false;
        }

        if (!search) {
            return true;
        }

        const haystack = [
            item.DeviceName,
            item.UserPrincipalName,
            item.OperatingSystem,
            item.OSVersion,
            item.LastSyncDateTime,
            item.StorageStatus
        ].join(" ").toLowerCase();

        return haystack.includes(search);
    });
}

function getPageSize() {
    const value = pageSizeSelect.value;

    if (value === "all") {
        return "all";
    }

    return parseInt(value, 10);
}

function renderAllDevicesTable() {
    let rows = getFilteredDeviceData();

    rows.sort(function(a, b) {
        return compareValues(a, b, allTableSortKey, allTableSortType, allTableSortDirection);
    });

    const totalRows = rows.length;
    const pageSize = getPageSize();
    const totalPages = pageSize === "all" ? 1 : Math.max(1, Math.ceil(totalRows / pageSize));

    if (currentPage > totalPages) {
        currentPage = totalPages;
    }

    if (currentPage < 1) {
        currentPage = 1;
    }

    let visibleRows;

    if (pageSize === "all") {
        visibleRows = rows;
    }
    else {
        const start = (currentPage - 1) * pageSize;
        const end = start + pageSize;
        visibleRows = rows.slice(start, end);
    }

    deviceTableBody.innerHTML = visibleRows.map(function(item) {
        return createRow(item, true);
    }).join("");

    const showingStart = totalRows === 0 ? 0 : (pageSize === "all" ? 1 : ((currentPage - 1) * pageSize) + 1);
    const showingEnd = pageSize === "all" ? totalRows : Math.min(currentPage * pageSize, totalRows);

    resultInfo.textContent = "Showing " + showingStart + "-" + showingEnd + " of " + totalRows + " devices";
    pageInfo.textContent = "Page " + currentPage + " / " + totalPages;

    prevPageButton.disabled = currentPage <= 1 || pageSize === "all";
    nextPageButton.disabled = currentPage >= totalPages || pageSize === "all";

    deviceHeaders.forEach(function(header) {
        header.classList.remove("sort-asc", "sort-desc");

        if (header.getAttribute("data-key") === allTableSortKey) {
            header.classList.add(allTableSortDirection === "asc" ? "sort-asc" : "sort-desc");
        }
    });
}

const topTable = setupSortableTable({
    tableId: "topTable",
    bodyId: "topTableBody",
    includeOsColumn: false,
    limit: 20,
    defaultSortKey: "FreePercent",
    defaultSortType: "number",
    defaultSortDirection: "asc",
    getData: function() {
        return deviceData;
    }
});

deviceHeaders.forEach(function(header) {
    header.addEventListener("click", function() {
        const clickedKey = header.getAttribute("data-key");
        const clickedType = header.getAttribute("data-type") || "text";

        if (allTableSortKey === clickedKey) {
            allTableSortDirection = allTableSortDirection === "asc" ? "desc" : "asc";
        }
        else {
            allTableSortKey = clickedKey;
            allTableSortType = clickedType;
            allTableSortDirection = "asc";
        }

        currentPage = 1;
        renderAllDevicesTable();
    });
});

filterButtons.forEach(function(button) {
    button.addEventListener("click", function() {
        const selectedFilter = button.getAttribute("data-filter");

        filterButtons.forEach(function(btn) {
            if (btn.getAttribute("data-filter") === selectedFilter) {
                btn.classList.add("active");
            }
            else {
                btn.classList.remove("active");
            }
        });

        currentFilter = selectedFilter;
        currentPage = 1;
        renderAllDevicesTable();

        const allDevicesSection = document.getElementById("allDevicesSection");
        if (allDevicesSection) {
            allDevicesSection.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        }
    });
});

searchBox.addEventListener("input", function() {
    currentPage = 1;
    renderAllDevicesTable();
});

pageSizeSelect.addEventListener("change", function() {
    currentPage = 1;
    renderAllDevicesTable();
});

prevPageButton.addEventListener("click", function() {
    currentPage--;
    renderAllDevicesTable();
});

nextPageButton.addEventListener("click", function() {
    currentPage++;
    renderAllDevicesTable();
});

topTable.render();
renderAllDevicesTable();
</script>

</body>
</html>
"@

$Html | Out-File -FilePath $HtmlFile -Encoding UTF8

Write-Host ""
Write-Host "Raportit luotu:" -ForegroundColor Green
Write-Host "CSV : $CsvFile" -ForegroundColor Green
Write-Host "HTML: $HtmlFile" -ForegroundColor Green

Write-Host ""
Write-Host "Yhteenveto:" -ForegroundColor Cyan

[PSCustomObject]@{
    WindowsDevices = $TotalWindows
    Critical       = $Critical
    Warning        = $Warning
    Notice         = $Notice
    OK             = $OK
    Unknown        = $Unknown
} | Format-List

Write-Host ""
Write-Host "Top 20 Windows-laitetta, joilla vähiten vapaata levytilaa:" -ForegroundColor Cyan

$Report |
    Select-Object -First 20 `
        DeviceName,
        UserPrincipalName,
        OSVersion,
        TotalGB,
        FreeGB,
        UsedGB,
        FreePercent,
        StorageStatus,
        LastSyncDateTime |
    Format-Table -AutoSize

Disconnect-MgGraph | Out-Null

Write-Host ""
Write-Host "Valmis. Graph-yhteys katkaistu." -ForegroundColor Green
Write-Host "Avaa HTML-raportti selaimessa:" -ForegroundColor Cyan
Write-Host $HtmlFile -ForegroundColor Cyan
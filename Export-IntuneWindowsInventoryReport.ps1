<#
.SYNOPSIS
    Intune Windows Device Inventory and Apps Report.

.DESCRIPTION
    Vie Intunen Windows-laitteiden inventaarion, tallennustiedot ja havaittujen sovellusten yhteenvedot CSV/HTML-muotoon.

.REQUIREMENTS
    - Microsoft Graph PowerShell -moduulit sekä Intune-laitetietojen lukuoikeudet

.OUTPUTS
    - Interaktiivinen HTML-raportti ja CSV-raportit laitteista, tallennuksesta ja sovelluksista

.EXAMPLE
    .\Export-IntuneWindowsInventoryReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Export-IntuneWindowsInventoryReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

# Export-IntuneWindowsInventoryAndStorageReport.ps1
# Intune Windows Device Inventory + Storage + Grouped Detected Apps Report
#
# READ-ONLY:
# - Reads Intune managed device data from Microsoft Graph
# - Filters only Windows devices
# - Reads Intune detected apps summary
# - Optionally maps detected apps to Windows managed devices
# - Exports local CSV and interactive HTML reports
# - Does NOT modify Intune, devices, users, compliance, settings, apps, assignments, or policies

$ErrorActionPreference = "Stop"

# -----------------------------
# Settings
# -----------------------------
$OutDir = Join-Path $PSScriptRoot "output\intune-reports"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Apps report mode
# $true  = fast: only detected apps summary, no device modal
# $false = maps detected apps to Windows devices and enables the Devices modal button
$AppsSummaryOnly = $false

# Safety limit for app-to-device mapping.
# Used only when $AppsSummaryOnly = $false.
# 0 = no limit. With 9000 detected apps, do not use 0 unless you enjoy watching Graph age in real time.
$MaxDetectedAppsToMap = 500

# Optional app-name filter for app-to-device mapping.
# Used only when $AppsSummaryOnly = $false.
# Empty string = no name filter.
# Example: "Chrome|Firefox|Java|Adobe|Teams|FortiClient|7-Zip|VLC"
$AppNameIncludeRegex = ""

$DeviceCsvFile  = Join-Path $OutDir "Intune_Windows_Device_Inventory_Storage_Report_$Timestamp.csv"
$DeviceHtmlFile = Join-Path $OutDir "Intune_Windows_Device_Inventory_Storage_Report_$Timestamp.html"

$AppsCsvFile    = Join-Path $OutDir "Intune_Windows_Detected_Apps_Report_$Timestamp.csv"
$AppsHtmlFile   = Join-Path $OutDir "Intune_Windows_Detected_Apps_Report_$Timestamp.html"

New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

# -----------------------------
# Helper functions
# -----------------------------
function Convert-GraphValueToText {
    param (
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [bool]) {
        return $Value.ToString()
    }

    if ($Value -is [byte] -or
        $Value -is [int] -or
        $Value -is [long] -or
        $Value -is [float] -or
        $Value -is [double] -or
        $Value -is [decimal]) {
        return $Value.ToString()
    }

    if ($Value -is [datetime]) {
        return $Value.ToString("dd.MM.yyyy HH:mm:ss")
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $Items = @()

        foreach ($Item in $Value) {
            $Items += Convert-GraphValueToText $Item
        }

        return ($Items | Where-Object { $_ -ne "" }) -join ", "
    }

    $PropertyNames = $Value.PSObject.Properties.Name

    if ($PropertyNames -contains "Value") {
        return [string]$Value.Value
    }

    if ($PropertyNames -contains "DisplayName") {
        return [string]$Value.DisplayName
    }

    if ($PropertyNames -contains "Name") {
        return [string]$Value.Name
    }

    if ($PropertyNames -contains "AdditionalProperties") {
        $Additional = $Value.AdditionalProperties

        if ($Additional -and $Additional.Count -gt 0) {
            return ($Additional.GetEnumerator() | ForEach-Object {
                "$($_.Key)=$($_.Value)"
            }) -join "; "
        }
    }

    return [string]$Value
}

function Convert-DateToText {
    param (
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return ""
    }

    try {
        return ([datetime]$Value).ToString("dd.MM.yyyy HH:mm:ss")
    }
    catch {
        return Convert-GraphValueToText $Value
    }
}

function Invoke-GraphPagedRequest {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [string]$Activity = "Haetaan Microsoft Graph -dataa",

        [string]$StatusPrefix = "Graph page"
    )

    $Results = @()
    $NextUri = $Uri
    $Page = 0
    $TotalRows = 0

    do {
        $Page++

        Write-Progress `
            -Activity $Activity `
            -Status "$StatusPrefix $Page, rivejä tähän mennessä: $TotalRows" `
            -PercentComplete -1

        $Response = Invoke-MgGraphRequest -Method GET -Uri $NextUri

        if ($Response.value) {
            $Results += $Response.value
            $TotalRows = $Results.Count
        }

        $NextUri = $Response.'@odata.nextLink'
    }
    while ($NextUri)

    Write-Progress `
        -Activity $Activity `
        -Completed

    return $Results
}

function Convert-ReportToJson {
    param (
        [AllowNull()]
        [object[]]$Data
    )

    $Json = @($Data) | ConvertTo-Json -Depth 8 -Compress

    if ([string]::IsNullOrWhiteSpace($Json)) {
        $Json = "[]"
    }

    $Json = $Json -replace '</script>', '<\/script>'

    return $Json
}

function New-InteractiveHtmlReport {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Subtitle,

        [Parameter(Mandatory = $true)]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [object[]]$Columns,

        [Parameter(Mandatory = $true)]
        [string]$DefaultSortKey,

        [Parameter(Mandatory = $true)]
        [string]$DefaultSortType,

        [Parameter(Mandatory = $true)]
        [string]$SearchPlaceholder,

        [Parameter(Mandatory = $true)]
        [string]$SummaryHtml,

        [Parameter(Mandatory = $true)]
        [string]$FooterText,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    $DataJson = Convert-ReportToJson -Data $Data
    $GeneratedAt = Get-Date -Format "dd.MM.yyyy HH:mm:ss"

    $HeaderHtml = ($Columns | ForEach-Object {
        "<th data-key=""$($_.Key)"" data-type=""$($_.Type)"">$($_.Label)</th>"
    }) -join "`n"

    $ColumnJson = $Columns | ConvertTo-Json -Depth 4 -Compress
    $ColumnJson = $ColumnJson -replace '</script>', '<\/script>'

    $Html = @"
<!DOCTYPE html>
<html lang="fi">
<head>
<meta charset="UTF-8">
<title>$Title</title>
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
        --scroll-track: #020617;
        --scroll-thumb: #64748b;
        --scroll-thumb-hover: #94a3b8;
    }

    * {
        box-sizing: border-box;
    }

    html {
        scrollbar-color: var(--scroll-thumb) var(--bg);
        scrollbar-width: thin;
    }

    body {
        margin: 0;
        padding: 24px;
        background: var(--bg);
        color: var(--text);
        font-family: Segoe UI, Arial, sans-serif;
        font-size: 14px;
        overflow-y: auto;
        overflow-x: hidden;
    }

    ::-webkit-scrollbar {
        width: 12px;
        height: 12px;
    }

    ::-webkit-scrollbar-track {
        background: var(--bg);
    }

    ::-webkit-scrollbar-thumb {
        background: var(--scroll-thumb);
        border-radius: 999px;
        border: 3px solid var(--bg);
    }

    ::-webkit-scrollbar-thumb:hover {
        background: var(--scroll-thumb-hover);
    }

    ::-webkit-scrollbar-corner {
        background: var(--bg);
    }

    h1,
    h2 {
        margin: 0 0 12px 0;
    }

    h1 {
        font-size: 28px;
        line-height: 1.2;
    }

    h2 {
        font-size: 20px;
        line-height: 1.3;
    }

    .subtitle {
        color: var(--muted);
        margin-bottom: 24px;
        line-height: 1.5;
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
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.20);
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
        line-height: 1.1;
    }

    .value.ok {
        color: var(--ok);
    }

    .value.notice {
        color: var(--notice);
    }

    .value.warning {
        color: var(--warning);
    }

    .value.critical {
        color: var(--critical);
    }

    .value.unknown {
        color: var(--unknown);
    }

    .section {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 18px;
        margin-top: 18px;
        overflow: visible;
    }

    .table-wrap {
        width: 100%;
        overflow-x: auto;
        overflow-y: visible;
        border: 1px solid var(--border);
        border-radius: 12px;
        background: #020617;
        scrollbar-color: var(--scroll-thumb) var(--scroll-track);
        scrollbar-width: thin;
    }

    .table-wrap::-webkit-scrollbar {
        height: 12px;
    }

    .table-wrap::-webkit-scrollbar-track {
        background: var(--scroll-track);
        border-radius: 999px;
    }

    .table-wrap::-webkit-scrollbar-thumb {
        background: var(--scroll-thumb);
        border-radius: 999px;
        border: 2px solid var(--scroll-track);
    }

    .table-wrap::-webkit-scrollbar-thumb:hover {
        background: var(--scroll-thumb-hover);
    }

    .table-wrap table {
        margin: 0;
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

    button:disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    select {
        cursor: pointer;
    }

    input {
        min-width: 360px;
    }

    input::placeholder {
        color: #94a3b8;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        min-width: 1600px;
    }

    th,
    td {
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

    tbody tr {
        transition: background 0.12s ease;
    }

    tr:hover {
        background: rgba(255, 255, 255, 0.04);
    }

    .num {
        text-align: right;
        font-variant-numeric: tabular-nums;
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

    .pagination button {
        min-width: 72px;
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
        line-height: 1.5;
    }


    .devices-btn {
        background: #1d4ed8;
        border-color: #60a5fa;
        color: #eff6ff;
        padding: 6px 10px;
        border-radius: 999px;
        font-size: 12px;
        font-weight: 700;
    }

    .devices-btn:hover {
        background: #2563eb;
    }

    .devices-btn:disabled {
        background: var(--button);
        border-color: var(--border);
        color: var(--muted);
        opacity: 0.65;
    }

    .modal-backdrop {
        display: none;
        position: fixed;
        inset: 0;
        z-index: 9999;
        background: rgba(2, 6, 23, 0.78);
        padding: 24px;
    }

    .modal-backdrop.open {
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .modal {
        width: min(920px, 96vw);
        max-height: 86vh;
        overflow: hidden;
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 16px;
        box-shadow: 0 25px 80px rgba(0, 0, 0, 0.55);
        display: flex;
        flex-direction: column;
    }

    .modal-header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 16px;
        padding: 18px;
        border-bottom: 1px solid var(--border);
        background: #020617;
    }

    .modal-title {
        font-size: 18px;
        font-weight: 800;
        margin: 0;
    }

    .modal-subtitle {
        color: var(--muted);
        font-size: 12px;
        margin-top: 6px;
        line-height: 1.5;
    }

    .modal-close {
        min-width: auto;
        padding: 6px 10px;
        border-radius: 10px;
    }

    .modal-body {
        padding: 18px;
        overflow: auto;
    }

    .modal-search {
        width: 100%;
        min-width: 0;
        margin-bottom: 12px;
    }

    .device-list {
        margin: 0;
        padding: 0;
        list-style: none;
        display: grid;
        gap: 8px;
    }

    .device-list li {
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 9px 11px;
        background: #0f172a;
        color: var(--text);
        font-family: Consolas, "Segoe UI", Arial, sans-serif;
        font-size: 13px;
        line-height: 1.35;
    }

    @media (max-width: 900px) {
        body {
            padding: 14px;
        }

        h1 {
            font-size: 24px;
        }

        .toolbar {
            align-items: stretch;
        }

        .filters {
            width: 100%;
        }

        input {
            min-width: 100%;
            width: 100%;
        }

        select {
            max-width: 100%;
        }
    }

    @media print {
        html {
            scrollbar-width: auto;
        }

        body {
            background: white;
            color: black;
            padding: 12px;
            overflow: visible;
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

<h1>$Title</h1>

<div class="subtitle">
    Generated: $GeneratedAt |
    $Subtitle |
    Mode: Read-only
</div>

$SummaryHtml

<div class="section">
    <h2>Report data</h2>

    <div class="toolbar">
        <div class="filters">
            <input type="search" id="searchBox" placeholder="$SearchPlaceholder">
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

    <div class="table-wrap">
        <table id="reportTable">
            <thead>
                <tr>
                    $HeaderHtml
                </tr>
            </thead>
            <tbody id="reportTableBody"></tbody>
        </table>
    </div>

    <div class="pagination">
        <div id="resultInfo">Showing results</div>
        <div>
            <button type="button" id="prevPage">Previous</button>
            <span id="pageInfo"></span>
            <button type="button" id="nextPage">Next</button>
        </div>
    </div>

    <div class="note">
        Click column headers to sort. Use search to filter results.
    </div>
</div>

<div class="footer">
    $FooterText
</div>


<div id="devicesModalBackdrop" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="devicesModalTitle">
    <div class="modal">
        <div class="modal-header">
            <div>
                <div id="devicesModalTitle" class="modal-title">Installed devices</div>
                <div id="devicesModalSubtitle" class="modal-subtitle"></div>
            </div>
            <button type="button" id="devicesModalClose" class="modal-close">Close</button>
        </div>
        <div class="modal-body">
            <input type="search" id="devicesModalSearch" class="modal-search" placeholder="Filter device list...">
            <ul id="devicesModalList" class="device-list"></ul>
        </div>
    </div>
</div>

<script>
const reportData = $DataJson;
const columns = $ColumnJson;

let currentPage = 1;
let sortKey = "$DefaultSortKey";
let sortType = "$DefaultSortType";
let sortDirection = "asc";

const searchBox = document.getElementById("searchBox");
const pageSizeSelect = document.getElementById("pageSize");
const resultInfo = document.getElementById("resultInfo");
const pageInfo = document.getElementById("pageInfo");
const prevPageButton = document.getElementById("prevPage");
const nextPageButton = document.getElementById("nextPage");
const table = document.getElementById("reportTable");
const tbody = document.getElementById("reportTableBody");
const headers = table.querySelectorAll("th");
const devicesModalBackdrop = document.getElementById("devicesModalBackdrop");
const devicesModalTitle = document.getElementById("devicesModalTitle");
const devicesModalSubtitle = document.getElementById("devicesModalSubtitle");
const devicesModalClose = document.getElementById("devicesModalClose");
const devicesModalSearch = document.getElementById("devicesModalSearch");
const devicesModalList = document.getElementById("devicesModalList");

let currentVisibleRows = [];
let currentModalDevices = [];


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

function formatValue(value, type) {
    if (value === null || value === undefined || value === "") {
        return "";
    }

    if (type === "percent") {
        return escapeHtml(value) + " %";
    }

    return escapeHtml(value);
}

function isEmptyValue(value) {
    return value === null || value === undefined || String(value).trim() === "";
}

function parseFinnishDate(value) {
    if (isEmptyValue(value)) {
        return null;
    }

    const text = String(value).trim();
    const match = text.match(/^(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/);

    if (!match) {
        return null;
    }

    const day = Number(match[1]);
    const month = Number(match[2]) - 1;
    const year = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);

    return new Date(year, month, day, hour, minute, second).getTime();
}

function parseNumberValue(value) {
    if (isEmptyValue(value)) {
        return null;
    }

    const normalized = String(value)
        .replace("%", "")
        .replace(",", ".")
        .replace(/\s/g, "")
        .trim();

    const number = Number(normalized);

    if (Number.isNaN(number)) {
        return null;
    }

    return number;
}

function compareValues(a, b, key, type, direction) {
    let av = a[key];
    let bv = b[key];

    const aEmpty = isEmptyValue(av);
    const bEmpty = isEmptyValue(bv);

    if (aEmpty && bEmpty) {
        return 0;
    }

    if (aEmpty) {
        return 1;
    }

    if (bEmpty) {
        return -1;
    }

    if (type === "number" || type === "percent") {
        const an = parseNumberValue(av);
        const bn = parseNumberValue(bv);

        if (an === null && bn === null) {
            return 0;
        }

        if (an === null) {
            return 1;
        }

        if (bn === null) {
            return -1;
        }

        return direction === "asc" ? an - bn : bn - an;
    }

    if (type === "date") {
        const ad = parseFinnishDate(av);
        const bd = parseFinnishDate(bv);

        if (ad === null && bd === null) {
            return 0;
        }

        if (ad === null) {
            return 1;
        }

        if (bd === null) {
            return -1;
        }

        return direction === "asc" ? ad - bd : bd - ad;
    }

    if (type === "status") {
        const statusOrder = {
            Critical: 1,
            Warning: 2,
            Notice: 3,
            OK: 4,
            Unknown: 5
        };

        const ao = statusOrder[av] || 99;
        const bo = statusOrder[bv] || 99;

        return direction === "asc" ? ao - bo : bo - ao;
    }

    av = String(av).toLowerCase();
    bv = String(bv).toLowerCase();

    const result = av.localeCompare(bv, "fi", {
        numeric: true,
        sensitivity: "base"
    });

    return direction === "asc" ? result : -result;
}

function getFilteredData() {
    const search = searchBox.value.trim().toLowerCase();

    if (!search) {
        return reportData;
    }

    return reportData.filter(function(item) {
        const haystack = columns.map(function(column) {
            return item[column.Key];
        }).join(" ").toLowerCase();

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

function createRow(item, rowIndex) {
    const cells = columns.map(function(column) {
        const rawValue = item[column.Key];

        if (column.Type === "devicesButton") {
            const count = Number(rawValue || 0);
            const disabled = count <= 0 ? " disabled" : "";
            const label = count > 0 ? "Show " + count : "No devices";
            return "<td><button type=\"button\" class=\"devices-btn\" data-row-index=\"" + rowIndex + "\"" + disabled + ">" + escapeHtml(label) + "</button></td>";
        }

        const value = formatValue(rawValue, column.Type);
        const cssClass = column.Type === "number" || column.Type === "percent" ? " class=\"num\"" : "";
        return "<td" + cssClass + ">" + value + "</td>";
    }).join("");

    return "<tr>" + cells + "</tr>";
}


function splitDevices(value) {
    if (value === null || value === undefined || String(value).trim() === "") {
        return [];
    }

    return String(value)
        .split(/\n/g)
        .map(function(item) {
            return item.trim();
        })
        .filter(function(item) {
            return item.length > 0;
        });
}

function renderModalDeviceList() {
    const search = devicesModalSearch.value.trim().toLowerCase();

    const filtered = currentModalDevices.filter(function(device) {
        if (!search) {
            return true;
        }

        return device.toLowerCase().includes(search);
    });

    devicesModalList.innerHTML = filtered.map(function(device) {
        return "<li>" + escapeHtml(device) + "</li>";
    }).join("");

    devicesModalSubtitle.textContent = filtered.length + " / " + currentModalDevices.length + " devices shown";
}

function openDevicesModal(item) {
    const appName = item.AppName || "Application";
    const publisher = item.Publishers || item.AppPublisher || "";
    const versions = item.Versions || item.AppVersion || "";
    const devices = splitDevices(item.Devices);

    currentModalDevices = devices;

    devicesModalTitle.textContent = appName;
    devicesModalSubtitle.textContent = publisher + (versions ? " | Versions: " + versions : "");
    devicesModalSearch.value = "";

    renderModalDeviceList();

    devicesModalBackdrop.classList.add("open");
    devicesModalSearch.focus();
}

function closeDevicesModal() {
    devicesModalBackdrop.classList.remove("open");
    currentModalDevices = [];
}


function renderTable() {
    let rows = getFilteredData().slice();

    rows.sort(function(a, b) {
        return compareValues(a, b, sortKey, sortType, sortDirection);
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

    currentVisibleRows = visibleRows;
    tbody.innerHTML = visibleRows.map(function(item, index) {
        return createRow(item, index);
    }).join("");

    const showingStart = totalRows === 0 ? 0 : (pageSize === "all" ? 1 : ((currentPage - 1) * pageSize) + 1);
    const showingEnd = pageSize === "all" ? totalRows : Math.min(currentPage * pageSize, totalRows);

    resultInfo.textContent = "Showing " + showingStart + "-" + showingEnd + " of " + totalRows + " rows";
    pageInfo.textContent = "Page " + currentPage + " / " + totalPages;

    prevPageButton.disabled = currentPage <= 1 || pageSize === "all";
    nextPageButton.disabled = currentPage >= totalPages || pageSize === "all";

    headers.forEach(function(header) {
        header.classList.remove("sort-asc", "sort-desc");

        if (header.getAttribute("data-key") === sortKey) {
            header.classList.add(sortDirection === "asc" ? "sort-asc" : "sort-desc");
        }
    });
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

        currentPage = 1;
        renderTable();
    });
});

searchBox.addEventListener("input", function() {
    currentPage = 1;
    renderTable();
});

pageSizeSelect.addEventListener("change", function() {
    currentPage = 1;
    renderTable();
});

prevPageButton.addEventListener("click", function() {
    currentPage--;
    renderTable();
});

nextPageButton.addEventListener("click", function() {
    currentPage++;
    renderTable();
});


tbody.addEventListener("click", function(event) {
    const button = event.target.closest(".devices-btn");

    if (!button) {
        return;
    }

    const rowIndex = Number(button.getAttribute("data-row-index"));
    const item = currentVisibleRows[rowIndex];

    if (item) {
        openDevicesModal(item);
    }
});

devicesModalClose.addEventListener("click", closeDevicesModal);

devicesModalBackdrop.addEventListener("click", function(event) {
    if (event.target === devicesModalBackdrop) {
        closeDevicesModal();
    }
});

devicesModalSearch.addEventListener("input", renderModalDeviceList);

document.addEventListener("keydown", function(event) {
    if (event.key === "Escape" && devicesModalBackdrop.classList.contains("open")) {
        closeDevicesModal();
    }
});


renderTable();
</script>

</body>
</html>
"@

    $Html | Out-File -FilePath $OutputFile -Encoding UTF8
}

# -----------------------------
# Connect to Microsoft Graph
# -----------------------------
Write-Host ""
Write-Host "=== Intune Windows Inventory + Storage + Apps Report ===" -ForegroundColor Cyan
Write-Host "Read-only audit. Haetaan Windows-laitteet ja detected apps -tiedot." -ForegroundColor DarkGray
Write-Host ""

Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -NoWelcome

# -----------------------------
# Managed devices
# -----------------------------
Write-Host "Haetaan Intune-laitteet Microsoft Graphista..." -ForegroundColor Cyan

$SelectFields = @(
    "id",
    "deviceName",
    "managedDeviceName",
    "userPrincipalName",
    "userDisplayName",
    "emailAddress",
    "operatingSystem",
    "osVersion",
    "manufacturer",
    "model",
    "serialNumber",
    "complianceState",
    "managementState",
    "managementAgent",
    "deviceEnrollmentType",
    "managedDeviceOwnerType",
    "enrolledDateTime",
    "lastSyncDateTime",
    "totalStorageSpaceInBytes",
    "freeStorageSpaceInBytes",
    "azureADRegistered",
    "azureADDeviceId",
    "isEncrypted",
    "deviceCategoryDisplayName",
    "wiFiMacAddress",
    "ethernetMacAddress"
) -join ","

$ManagedDevicesUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=$SelectFields"

$AllDevices = @(Invoke-GraphPagedRequest `
    -Uri $ManagedDevicesUri `
    -Activity "Haetaan Intune managed devices -tietoja" `
    -StatusPrefix "Managed devices page")

$Devices = @($AllDevices | Where-Object {
    (Convert-GraphValueToText $_.operatingSystem) -ieq "Windows"
})

$Total = $Devices.Count
$Counter = 0

Write-Host "Laitteita yhteensä Intunessa: $($AllDevices.Count)" -ForegroundColor DarkGray
Write-Host "Windows-laitteita raporttiin: $Total" -ForegroundColor Cyan
Write-Host ""

$DeviceReport = foreach ($Device in $Devices) {
    $Counter++

    $PercentComplete = if ($Total -gt 0) {
        [math]::Round(($Counter / $Total) * 100, 0)
    }
    else {
        100
    }

    Write-Progress `
        -Activity "Luodaan Intune Windows inventory + storage -raporttia" `
        -Status "$Counter / $Total : $($Device.deviceName)" `
        -PercentComplete $PercentComplete

    $TotalBytes = [double]$Device.totalStorageSpaceInBytes
    $FreeBytes  = [double]$Device.freeStorageSpaceInBytes

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

    $LastSyncAgeDays = if ($Device.lastSyncDateTime) {
        try {
            [math]::Round(((Get-Date) - [datetime]$Device.lastSyncDateTime).TotalDays, 1)
        }
        catch {
            $null
        }
    }
    else {
        $null
    }

    $SyncStatus = if ($null -eq $LastSyncAgeDays) {
        "Unknown"
    }
    elseif ($LastSyncAgeDays -gt 30) {
        "Stale > 30d"
    }
    elseif ($LastSyncAgeDays -gt 14) {
        "Old > 14d"
    }
    elseif ($LastSyncAgeDays -gt 7) {
        "Notice > 7d"
    }
    else {
        "OK"
    }

    [PSCustomObject]@{
        DeviceName                = Convert-GraphValueToText $Device.deviceName
        ManagedDeviceName         = Convert-GraphValueToText $Device.managedDeviceName

        UserPrincipalName         = Convert-GraphValueToText $Device.userPrincipalName
        UserDisplayName           = Convert-GraphValueToText $Device.userDisplayName
        EmailAddress              = Convert-GraphValueToText $Device.emailAddress

        OperatingSystem           = Convert-GraphValueToText $Device.operatingSystem
        OSVersion                 = Convert-GraphValueToText $Device.osVersion

        Manufacturer              = Convert-GraphValueToText $Device.manufacturer
        Model                     = Convert-GraphValueToText $Device.model
        SerialNumber              = Convert-GraphValueToText $Device.serialNumber

        ComplianceState           = Convert-GraphValueToText $Device.complianceState
        ManagementState           = Convert-GraphValueToText $Device.managementState
        ManagementAgent           = Convert-GraphValueToText $Device.managementAgent
        DeviceEnrollmentType      = Convert-GraphValueToText $Device.deviceEnrollmentType
        ManagedDeviceOwnerType    = Convert-GraphValueToText $Device.managedDeviceOwnerType
        DeviceCategoryDisplayName = Convert-GraphValueToText $Device.deviceCategoryDisplayName

        EnrolledDateTime          = Convert-DateToText $Device.enrolledDateTime
        LastSyncDateTime          = Convert-DateToText $Device.lastSyncDateTime
        LastSyncAgeDays           = $LastSyncAgeDays
        SyncStatus                = $SyncStatus

        AzureADRegistered         = Convert-GraphValueToText $Device.azureADRegistered
        IsEncrypted               = Convert-GraphValueToText $Device.isEncrypted

        WiFiMacAddress            = Convert-GraphValueToText $Device.wiFiMacAddress
        EthernetMacAddress        = Convert-GraphValueToText $Device.ethernetMacAddress

        TotalGB                   = $TotalGB
        FreeGB                    = $FreeGB
        UsedGB                    = $UsedGB
        FreePercent               = $FreePercent
        StorageStatus             = $StorageStatus

        IntuneDeviceId            = Convert-GraphValueToText $Device.id
        AzureADDeviceId           = Convert-GraphValueToText $Device.azureADDeviceId
    }
}

Write-Progress `
    -Activity "Luodaan Intune Windows inventory + storage -raporttia" `
    -Completed

$DeviceReport = @($DeviceReport | Sort-Object FreePercent)

$DeviceReport |
    Export-Csv $DeviceCsvFile -NoTypeInformation -Encoding UTF8 -Delimiter ";"

$TotalWindows = $DeviceReport.Count
$Critical = ($DeviceReport | Where-Object { $_.StorageStatus -eq "Critical" }).Count
$Warning  = ($DeviceReport | Where-Object { $_.StorageStatus -eq "Warning" }).Count
$Notice   = ($DeviceReport | Where-Object { $_.StorageStatus -eq "Notice" }).Count
$OK       = ($DeviceReport | Where-Object { $_.StorageStatus -eq "OK" }).Count
$Unknown  = ($DeviceReport | Where-Object { $_.StorageStatus -eq "Unknown" }).Count

$NonCompliant = ($DeviceReport | Where-Object { $_.ComplianceState -ieq "noncompliant" }).Count
$Encrypted    = ($DeviceReport | Where-Object { $_.IsEncrypted -ieq "True" }).Count
$NotEncrypted = ($DeviceReport | Where-Object { $_.IsEncrypted -ieq "False" }).Count

$SyncStale  = ($DeviceReport | Where-Object { $_.SyncStatus -eq "Stale > 30d" }).Count
$SyncOld    = ($DeviceReport | Where-Object { $_.SyncStatus -eq "Old > 14d" }).Count
$SyncNotice = ($DeviceReport | Where-Object { $_.SyncStatus -eq "Notice > 7d" }).Count
$SyncOK     = ($DeviceReport | Where-Object { $_.SyncStatus -eq "OK" }).Count
$SyncUnknown = ($DeviceReport | Where-Object { $_.SyncStatus -eq "Unknown" }).Count

$DeviceColumns = @(
    [PSCustomObject]@{ Key = "DeviceName"; Label = "Device"; Type = "text" },
    [PSCustomObject]@{ Key = "ManagedDeviceName"; Label = "Managed name"; Type = "text" },
    [PSCustomObject]@{ Key = "UserPrincipalName"; Label = "UPN"; Type = "text" },
    [PSCustomObject]@{ Key = "UserDisplayName"; Label = "User"; Type = "text" },
    [PSCustomObject]@{ Key = "EmailAddress"; Label = "Email"; Type = "text" },
    [PSCustomObject]@{ Key = "OperatingSystem"; Label = "OS"; Type = "text" },
    [PSCustomObject]@{ Key = "OSVersion"; Label = "OS version"; Type = "text" },
    [PSCustomObject]@{ Key = "Manufacturer"; Label = "Manufacturer"; Type = "text" },
    [PSCustomObject]@{ Key = "Model"; Label = "Model"; Type = "text" },
    [PSCustomObject]@{ Key = "SerialNumber"; Label = "Serial"; Type = "text" },
    [PSCustomObject]@{ Key = "ComplianceState"; Label = "Compliance"; Type = "text" },
    [PSCustomObject]@{ Key = "ManagementState"; Label = "Management state"; Type = "text" },
    [PSCustomObject]@{ Key = "ManagementAgent"; Label = "Agent"; Type = "text" },
    [PSCustomObject]@{ Key = "DeviceEnrollmentType"; Label = "Enrollment"; Type = "text" },
    [PSCustomObject]@{ Key = "ManagedDeviceOwnerType"; Label = "Owner"; Type = "text" },
    [PSCustomObject]@{ Key = "DeviceCategoryDisplayName"; Label = "Category"; Type = "text" },
    [PSCustomObject]@{ Key = "EnrolledDateTime"; Label = "Enrolled"; Type = "date" },
    [PSCustomObject]@{ Key = "LastSyncDateTime"; Label = "Last sync"; Type = "date" },
    [PSCustomObject]@{ Key = "LastSyncAgeDays"; Label = "Last sync age days"; Type = "number" },
    [PSCustomObject]@{ Key = "SyncStatus"; Label = "Sync status"; Type = "text" },
    [PSCustomObject]@{ Key = "AzureADRegistered"; Label = "AAD registered"; Type = "text" },
    [PSCustomObject]@{ Key = "IsEncrypted"; Label = "Encrypted"; Type = "text" },
    [PSCustomObject]@{ Key = "WiFiMacAddress"; Label = "WiFi MAC"; Type = "text" },
    [PSCustomObject]@{ Key = "EthernetMacAddress"; Label = "Ethernet MAC"; Type = "text" },
    [PSCustomObject]@{ Key = "TotalGB"; Label = "Total GB"; Type = "number" },
    [PSCustomObject]@{ Key = "FreeGB"; Label = "Free GB"; Type = "number" },
    [PSCustomObject]@{ Key = "UsedGB"; Label = "Used GB"; Type = "number" },
    [PSCustomObject]@{ Key = "FreePercent"; Label = "Free %"; Type = "percent" },
    [PSCustomObject]@{ Key = "StorageStatus"; Label = "Storage"; Type = "status" },
    [PSCustomObject]@{ Key = "IntuneDeviceId"; Label = "Intune ID"; Type = "text" },
    [PSCustomObject]@{ Key = "AzureADDeviceId"; Label = "Azure AD Device ID"; Type = "text" }
)

$DeviceSummaryHtml = @"
<div class="grid">
    <div class="card">
        <div class="label">Windows devices</div>
        <div class="value">$TotalWindows</div>
    </div>

    <div class="card">
        <div class="label">Critical &lt; 10%</div>
        <div class="value critical">$Critical</div>
    </div>

    <div class="card">
        <div class="label">Warning &lt; 15%</div>
        <div class="value warning">$Warning</div>
    </div>

    <div class="card">
        <div class="label">Notice &lt; 20%</div>
        <div class="value notice">$Notice</div>
    </div>

    <div class="card">
        <div class="label">OK storage</div>
        <div class="value ok">$OK</div>
    </div>

    <div class="card">
        <div class="label">Unknown storage</div>
        <div class="value unknown">$Unknown</div>
    </div>

    <div class="card">
        <div class="label">Non-compliant</div>
        <div class="value critical">$NonCompliant</div>
    </div>

    <div class="card">
        <div class="label">Encrypted</div>
        <div class="value ok">$Encrypted</div>
    </div>

    <div class="card">
        <div class="label">Not encrypted</div>
        <div class="value warning">$NotEncrypted</div>
    </div>

    <div class="card">
        <div class="label">Sync stale &gt; 30d</div>
        <div class="value critical">$SyncStale</div>
    </div>

    <div class="card">
        <div class="label">Sync old &gt; 14d</div>
        <div class="value warning">$SyncOld</div>
    </div>

    <div class="card">
        <div class="label">Sync notice &gt; 7d</div>
        <div class="value notice">$SyncNotice</div>
    </div>
</div>
"@

New-InteractiveHtmlReport `
    -Title "Intune Windows Device Inventory + Storage Report" `
    -Subtitle "Source: Microsoft Graph / Intune managed devices" `
    -Data $DeviceReport `
    -Columns $DeviceColumns `
    -DefaultSortKey "FreePercent" `
    -DefaultSortType "number" `
    -SearchPlaceholder "Search device, user, serial, model, OS, compliance..." `
    -SummaryHtml $DeviceSummaryHtml `
    -FooterText "This report is generated locally from Intune managedDevice read-only data. No Intune settings, devices, users, compliance states, or policies were modified." `
    -OutputFile $DeviceHtmlFile

# -----------------------------
# Detected apps summary / optional mapping
# -----------------------------
Write-Host ""
Write-Host "Haetaan detected apps -tiedot Intunesta..." -ForegroundColor Cyan
Write-Host "AppsSummaryOnly = $AppsSummaryOnly" -ForegroundColor Yellow
Write-Host ""

$DetectedAppsUri = "https://graph.microsoft.com/v1.0/deviceManagement/detectedApps?`$select=id,displayName,version,sizeInByte,publisher,deviceCount"

$DetectedApps = @(Invoke-GraphPagedRequest `
    -Uri $DetectedAppsUri `
    -Activity "Haetaan Intune detected apps -listaa" `
    -StatusPrefix "Detected apps page")

Write-Host "Detected apps yhteensä: $($DetectedApps.Count)" -ForegroundColor Cyan

if ($AppsSummaryOnly) {
    Write-Host "Luodaan detected apps summary -raportti ilman laitekohtaista mappingia." -ForegroundColor Yellow
    Write-Host "Tämä on järkevä oletus 9000 detected apps -rivillä. Täysi mapping olisi Graph-maraton, ei raportti." -ForegroundColor DarkGray

    $RawAppsReport = @(
        $DetectedApps | ForEach-Object {
            $SizeBytes = [double]$_.sizeInByte

            $AppSizeMB = if ($SizeBytes -gt 0) {
                [math]::Round($SizeBytes / 1MB, 2)
            }
            else {
                $null
            }

            $DeviceCountValue = 0

            if ($null -ne $_.deviceCount -and -not [string]::IsNullOrWhiteSpace([string]$_.deviceCount)) {
                try {
                    $DeviceCountValue = [int]$_.deviceCount
                }
                catch {
                    $DeviceCountValue = 0
                }
            }

            [PSCustomObject]@{
                AppName        = Convert-GraphValueToText $_.displayName
                AppVersion     = Convert-GraphValueToText $_.version
                AppPublisher   = Convert-GraphValueToText $_.publisher
                AppSizeMB      = $AppSizeMB
                AppDeviceCount = $DeviceCountValue
                AppId          = Convert-GraphValueToText $_.id
                ReadStatus     = "Summary only"
                ErrorMessage   = ""
            }
        }
    )

    # Group by application name only.
    # Version is intentionally ignored so the same app does not appear many times just because versions differ.
    $AppsReport = @(
        $RawAppsReport |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppName) } |
            Group-Object -Property AppName |
            ForEach-Object {
                $GroupItems = @($_.Group)

                $Versions = @(
                    $GroupItems |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppVersion) } |
                        Select-Object -ExpandProperty AppVersion -Unique |
                        Sort-Object
                )

                $Publishers = @(
                    $GroupItems |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppPublisher) } |
                        Select-Object -ExpandProperty AppPublisher -Unique |
                        Sort-Object
                )

                $AppIds = @(
                    $GroupItems |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppId) } |
                        Select-Object -ExpandProperty AppId -Unique
                )

                $DeviceCountSum = @(
                    $GroupItems |
                        ForEach-Object {
                            try {
                                [int]$_.AppDeviceCount
                            }
                            catch {
                                0
                            }
                        }
                ) | Measure-Object -Sum | Select-Object -ExpandProperty Sum

                $SizeValues = @(
                    $GroupItems |
                        Where-Object { $null -ne $_.AppSizeMB -and $_.AppSizeMB -ne "" } |
                        ForEach-Object {
                            try {
                                [double]$_.AppSizeMB
                            }
                            catch {
                                $null
                            }
                        } |
                        Where-Object { $null -ne $_ }
                )

                $MaxSizeMB = if ($SizeValues.Count -gt 0) {
                    [math]::Round(($SizeValues | Measure-Object -Maximum).Maximum, 2)
                }
                else {
                    $null
                }

                [PSCustomObject]@{
                    AppName          = $_.Name
                    Publishers       = ($Publishers -join "; ")
                    VersionCount     = $Versions.Count
                    Versions         = ($Versions -join "; ")
                    DeviceCountTotal = $DeviceCountSum
                    DetectedRows     = $GroupItems.Count
                    MaxSizeMB        = $MaxSizeMB
                    AppIds           = ($AppIds -join "; ")
                    ReadStatus       = "Grouped by app name"
                    ErrorMessage     = ""
                }
            } |
            Sort-Object AppName
    )

    $AppsReport |
        Export-Csv $AppsCsvFile -NoTypeInformation -Encoding UTF8 -Delimiter ";"

    $TotalAppRows = $RawAppsReport.Count
    $GroupedAppRows = $AppsReport.Count
    $SuccessfulAppRows = $AppsReport.Count
    $UniqueApps = $GroupedAppRows

    $DevicesWithApps = ""
    $DevicesWithoutApps = ""
    $DevicesWithAppErrors = 0

    $AppsColumns = @(
        [PSCustomObject]@{ Key = "AppName"; Label = "App name"; Type = "text" },
        [PSCustomObject]@{ Key = "Publishers"; Label = "Publisher(s)"; Type = "text" },
        [PSCustomObject]@{ Key = "VersionCount"; Label = "Version count"; Type = "number" },
        [PSCustomObject]@{ Key = "Versions"; Label = "Versions"; Type = "text" },
        [PSCustomObject]@{ Key = "DeviceCountTotal"; Label = "Intune count total"; Type = "number" },
        [PSCustomObject]@{ Key = "DetectedRows"; Label = "Detected rows"; Type = "number" },
        [PSCustomObject]@{ Key = "MaxSizeMB"; Label = "Max size MB"; Type = "number" },
        [PSCustomObject]@{ Key = "ReadStatus"; Label = "Read status"; Type = "text" },
        [PSCustomObject]@{ Key = "ErrorMessage"; Label = "Error"; Type = "text" },
        [PSCustomObject]@{ Key = "AppIds"; Label = "Detected app IDs"; Type = "text" }
    )

    $AppsSummaryHtml = @"
<div class="grid">
    <div class="card">
        <div class="label">Detected app rows</div>
        <div class="value">$TotalAppRows</div>
    </div>

    <div class="card">
        <div class="label">Grouped app names</div>
        <div class="value notice">$GroupedAppRows</div>
    </div>

    <div class="card">
        <div class="label">Mode</div>
        <div class="value ok">Summary</div>
    </div>

    <div class="card">
        <div class="label">Read errors</div>
        <div class="value warning">$DevicesWithAppErrors</div>
    </div>
</div>
"@

    New-InteractiveHtmlReport `
        -Title "Intune Detected Apps Summary Report - Grouped by App Name" `
        -Subtitle "Source: Microsoft Graph / Intune detectedApps summary grouped by app name" `
        -Data $AppsReport `
        -Columns $AppsColumns `
        -DefaultSortKey "DeviceCountTotal" `
        -DefaultSortType "number" `
        -SearchPlaceholder "Search app, publisher, version..." `
        -SummaryHtml $AppsSummaryHtml `
        -FooterText "This report is generated locally from Intune detectedApps read-only data. No Intune apps, assignments, devices, users, or policies were modified." `
        -OutputFile $AppsHtmlFile
}
else {
    Write-Host "Luodaan detectedApps -> managedDevices mapping -raportti." -ForegroundColor Yellow

    $DeviceLookup = @{}

    foreach ($Device in $DeviceReport) {
        if (-not [string]::IsNullOrWhiteSpace($Device.IntuneDeviceId)) {
            $DeviceLookup[$Device.IntuneDeviceId] = $Device
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($AppNameIncludeRegex)) {
        $DetectedApps = @(
            $DetectedApps | Where-Object {
                (Convert-GraphValueToText $_.displayName) -match $AppNameIncludeRegex
            }
        )

        Write-Host "AppNameIncludeRegex käytössä: $AppNameIncludeRegex" -ForegroundColor Yellow
        Write-Host "Mapattavia detected apps -rivejä filtterin jälkeen: $($DetectedApps.Count)" -ForegroundColor Yellow
    }

    if ($MaxDetectedAppsToMap -gt 0) {
        $DetectedApps = @(
            $DetectedApps |
                Sort-Object @{ Expression = { [int]($_.deviceCount) }; Descending = $true } |
                Select-Object -First $MaxDetectedAppsToMap
        )

        Write-Host "Mapattavat detected apps -rivit rajattu: $($DetectedApps.Count)" -ForegroundColor Yellow
    }

    $AppsReportList = New-Object System.Collections.Generic.List[object]

    $AppTotal = $DetectedApps.Count
    $AppCounter = 0

    foreach ($App in $DetectedApps) {
        $AppCounter++

        $AppName = Convert-GraphValueToText $App.displayName
        $AppVersion = Convert-GraphValueToText $App.version
        $AppPublisher = Convert-GraphValueToText $App.publisher
        $AppDeviceCount = Convert-GraphValueToText $App.deviceCount
        $AppId = Convert-GraphValueToText $App.id

        $PercentComplete = if ($AppTotal -gt 0) {
            [math]::Round(($AppCounter / $AppTotal) * 100, 0)
        }
        else {
            100
        }

        Write-Progress `
            -Activity "Haetaan detected apps -> managed devices -tietoja" `
            -Status "$AppCounter / $AppTotal : $AppName" `
            -PercentComplete $PercentComplete

        if ([string]::IsNullOrWhiteSpace($AppId)) {
            continue
        }

        $SizeBytes = [double]$App.sizeInByte

        $AppSizeMB = if ($SizeBytes -gt 0) {
            [math]::Round($SizeBytes / 1MB, 2)
        }
        else {
            $null
        }

        $EncodedAppId = [System.Uri]::EscapeDataString($AppId)
        $AppDevicesUri = "https://graph.microsoft.com/v1.0/deviceManagement/detectedApps/$EncodedAppId/managedDevices?`$select=id,deviceName,userPrincipalName,userDisplayName,emailAddress,operatingSystem,osVersion,manufacturer,model,serialNumber"

        try {
            $AppManagedDevices = @(Invoke-GraphPagedRequest `
                -Uri $AppDevicesUri `
                -Activity "Haetaan sovelluksen laitteita" `
                -StatusPrefix $AppName)

            $MatchedWindowsDevices = @(
                $AppManagedDevices | Where-Object {
                    $ManagedDeviceId = Convert-GraphValueToText $_.id
                    $DeviceLookup.ContainsKey($ManagedDeviceId)
                }
            )

            foreach ($ManagedDevice in $MatchedWindowsDevices) {
                $ManagedDeviceId = Convert-GraphValueToText $ManagedDevice.id
                $KnownDevice = $DeviceLookup[$ManagedDeviceId]

                $AppsReportList.Add([PSCustomObject]@{
                    DeviceName        = $KnownDevice.DeviceName
                    UserPrincipalName = $KnownDevice.UserPrincipalName
                    UserDisplayName   = $KnownDevice.UserDisplayName
                    Manufacturer      = $KnownDevice.Manufacturer
                    Model             = $KnownDevice.Model
                    SerialNumber      = $KnownDevice.SerialNumber
                    OSVersion         = $KnownDevice.OSVersion

                    AppName           = $AppName
                    AppVersion        = $AppVersion
                    AppPublisher      = $AppPublisher
                    AppSizeMB         = $AppSizeMB
                    AppDeviceCount    = $AppDeviceCount

                    IntuneDeviceId    = $KnownDevice.IntuneDeviceId
                    AppId             = $AppId
                    ReadStatus        = "OK"
                    ErrorMessage      = ""
                })
            }
        }
        catch {
            $AppsReportList.Add([PSCustomObject]@{
                DeviceName        = ""
                UserPrincipalName = ""
                UserDisplayName   = ""
                Manufacturer      = ""
                Model             = ""
                SerialNumber      = ""
                OSVersion         = ""

                AppName           = $AppName
                AppVersion        = $AppVersion
                AppPublisher      = $AppPublisher
                AppSizeMB         = $AppSizeMB
                AppDeviceCount    = $AppDeviceCount

                IntuneDeviceId    = ""
                AppId             = $AppId
                ReadStatus        = "Error"
                ErrorMessage      = $_.Exception.Message
            })
        }

        Start-Sleep -Milliseconds 150
    }

    Write-Progress `
        -Activity "Haetaan detected apps -> managed devices -tietoja" `
        -Completed

    $RawMappedAppsReport = @($AppsReportList | Sort-Object DeviceName, AppName, AppVersion)

    # Group mapped rows by application name, ignoring version.
    # Devices are stored in a newline-separated field so the HTML report can open them in a modal.
    $AppsReport = @(
        $RawMappedAppsReport |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppName) } |
            Group-Object -Property AppName |
            ForEach-Object {
                $GroupItems = @($_.Group)

                $Versions = @(
                    $GroupItems |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppVersion) } |
                        Select-Object -ExpandProperty AppVersion -Unique |
                        Sort-Object
                )

                $Publishers = @(
                    $GroupItems |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppPublisher) } |
                        Select-Object -ExpandProperty AppPublisher -Unique |
                        Sort-Object
                )

                $Devices = @(
                    $GroupItems |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_.DeviceName) } |
                        Sort-Object DeviceName -Unique |
                        ForEach-Object {
                            $User = if (-not [string]::IsNullOrWhiteSpace($_.UserPrincipalName)) {
                                " | $($_.UserPrincipalName)"
                            }
                            else {
                                ""
                            }

                            $Model = if (-not [string]::IsNullOrWhiteSpace($_.Model)) {
                                " | $($_.Model)"
                            }
                            else {
                                ""
                            }

                            "$($_.DeviceName)$User$Model"
                        }
                )

                $AppIds = @(
                    $GroupItems |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppId) } |
                        Select-Object -ExpandProperty AppId -Unique
                )

                $DeviceCountSum = @(
                    $GroupItems |
                        ForEach-Object {
                            try {
                                [int]$_.AppDeviceCount
                            }
                            catch {
                                0
                            }
                        }
                ) | Measure-Object -Sum | Select-Object -ExpandProperty Sum

                $SizeValues = @(
                    $GroupItems |
                        Where-Object { $null -ne $_.AppSizeMB -and $_.AppSizeMB -ne "" } |
                        ForEach-Object {
                            try {
                                [double]$_.AppSizeMB
                            }
                            catch {
                                $null
                            }
                        } |
                        Where-Object { $null -ne $_ }
                )

                $MaxSizeMB = if ($SizeValues.Count -gt 0) {
                    [math]::Round(($SizeValues | Measure-Object -Maximum).Maximum, 2)
                }
                else {
                    $null
                }

                [PSCustomObject]@{
                    AppName           = $_.Name
                    Publishers        = ($Publishers -join "; ")
                    VersionCount      = $Versions.Count
                    Versions          = ($Versions -join "; ")
                    DeviceCountTotal  = $DeviceCountSum
                    DeviceCountUnique = $Devices.Count
                    Devices           = ($Devices -join "`n")
                    DetectedRows      = $GroupItems.Count
                    MaxSizeMB         = $MaxSizeMB
                    AppIds            = ($AppIds -join "; ")
                    ReadStatus        = "Mapped and grouped"
                    ErrorMessage      = ""
                }
            } |
            Sort-Object AppName
    )

    $AppsReport |
        Export-Csv $AppsCsvFile -NoTypeInformation -Encoding UTF8 -Delimiter ";"

    $TotalAppRows = $RawMappedAppsReport.Count
    $SuccessfulAppRows = $AppsReport.Count
    $UniqueApps = $AppsReport.Count

    $DevicesWithApps = @(
        $RawMappedAppsReport |
        Where-Object { $_.ReadStatus -eq "OK" -and -not [string]::IsNullOrWhiteSpace($_.DeviceName) } |
        Select-Object DeviceName -Unique
    ).Count

    $DevicesWithoutApps = [math]::Max(0, $TotalWindows - $DevicesWithApps)

    $DevicesWithAppErrors = @(
        $RawMappedAppsReport |
        Where-Object { $_.ReadStatus -eq "Error" } |
        Select-Object AppId -Unique
    ).Count

    $AppsColumns = @(
        [PSCustomObject]@{ Key = "AppName"; Label = "App name"; Type = "text" },
        [PSCustomObject]@{ Key = "Publishers"; Label = "Publisher(s)"; Type = "text" },
        [PSCustomObject]@{ Key = "VersionCount"; Label = "Version count"; Type = "number" },
        [PSCustomObject]@{ Key = "Versions"; Label = "Versions"; Type = "text" },
        [PSCustomObject]@{ Key = "DeviceCountTotal"; Label = "Intune count total"; Type = "number" },
        [PSCustomObject]@{ Key = "DeviceCountUnique"; Label = "Devices"; Type = "devicesButton" },
        [PSCustomObject]@{ Key = "DetectedRows"; Label = "Detected rows"; Type = "number" },
        [PSCustomObject]@{ Key = "MaxSizeMB"; Label = "Max size MB"; Type = "number" },
        [PSCustomObject]@{ Key = "ReadStatus"; Label = "Read status"; Type = "text" },
        [PSCustomObject]@{ Key = "ErrorMessage"; Label = "Error"; Type = "text" },
        [PSCustomObject]@{ Key = "AppIds"; Label = "Detected app IDs"; Type = "text" }
    )

    $AppsSummaryHtml = @"
<div class="grid">
    <div class="card">
        <div class="label">Windows devices</div>
        <div class="value">$TotalWindows</div>
    </div>

    <div class="card">
        <div class="label">Devices with app data</div>
        <div class="value ok">$DevicesWithApps</div>
    </div>

    <div class="card">
        <div class="label">Unique apps</div>
        <div class="value notice">$UniqueApps</div>
    </div>

    <div class="card">
        <div class="label">App detections</div>
        <div class="value">$SuccessfulAppRows</div>
    </div>

    <div class="card">
        <div class="label">No app rows</div>
        <div class="value unknown">$DevicesWithoutApps</div>
    </div>

    <div class="card">
        <div class="label">App read errors</div>
        <div class="value warning">$DevicesWithAppErrors</div>
    </div>
</div>
"@

    New-InteractiveHtmlReport `
        -Title "Intune Windows Device Installed Apps Mapping Report - Grouped with Device Modal" `
        -Subtitle "Source: Microsoft Graph / Intune detectedApps mapped to managed devices, grouped by app name" `
        -Data $AppsReport `
        -Columns $AppsColumns `
        -DefaultSortKey "DeviceCountUnique" `
        -DefaultSortType "number" `
        -SearchPlaceholder "Search app, publisher, version..." `
        -SummaryHtml $AppsSummaryHtml `
        -FooterText "This report is generated locally from Intune detectedApps and managedDevices read-only data. No Intune apps, assignments, devices, users, or policies were modified." `
        -OutputFile $AppsHtmlFile
}

# -----------------------------
# Output summary
# -----------------------------
Write-Host ""
Write-Host "Raportit luotu:" -ForegroundColor Green
Write-Host "Device CSV : $DeviceCsvFile" -ForegroundColor Green
Write-Host "Device HTML: $DeviceHtmlFile" -ForegroundColor Green
Write-Host "Apps CSV   : $AppsCsvFile" -ForegroundColor Green
Write-Host "Apps HTML  : $AppsHtmlFile" -ForegroundColor Green

Write-Host ""
Write-Host "Yhteenveto:" -ForegroundColor Cyan

[PSCustomObject]@{
    WindowsDevices        = $TotalWindows
    StorageCritical       = $Critical
    StorageWarning        = $Warning
    StorageNotice         = $Notice
    StorageOK             = $OK
    StorageUnknown        = $Unknown
    NonCompliant          = $NonCompliant
    Encrypted             = $Encrypted
    NotEncrypted          = $NotEncrypted
    AppRows               = $TotalAppRows
    GroupedAppNames       = $UniqueApps
    UniqueApps            = $UniqueApps
    AppsSummaryOnly       = $AppsSummaryOnly
    MaxDetectedAppsToMap  = $MaxDetectedAppsToMap
    AppNameIncludeRegex   = $AppNameIncludeRegex
    SyncStaleOver30d      = $SyncStale
    SyncOldOver14d        = $SyncOld
    SyncNoticeOver7d      = $SyncNotice
} | Format-List

Write-Host ""
Write-Host "Top 20 Windows-laitetta, joilla vähiten vapaata levytilaa:" -ForegroundColor Cyan

$DeviceReport |
    Select-Object -First 20 `
        DeviceName,
        UserPrincipalName,
        Manufacturer,
        Model,
        SerialNumber,
        OSVersion,
        ComplianceState,
        IsEncrypted,
        TotalGB,
        FreeGB,
        UsedGB,
        FreePercent,
        StorageStatus,
        LastSyncDateTime,
        LastSyncAgeDays,
        SyncStatus |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Top 20 detected apps -rivejä:" -ForegroundColor Cyan

$AppsReport |
    Select-Object -First 20 `
        AppName,
        Publishers,
        VersionCount,
        DeviceCountTotal,
        DeviceCountUnique,
        DetectedRows,
        MaxSizeMB,
        ReadStatus |
    Format-Table -AutoSize

Disconnect-MgGraph | Out-Null

Write-Host ""
Write-Host "Valmis. Graph-yhteys katkaistu." -ForegroundColor Green
Write-Host "Avaa HTML-raportit selaimessa:" -ForegroundColor Cyan
Write-Host $DeviceHtmlFile -ForegroundColor Cyan
Write-Host $AppsHtmlFile -ForegroundColor Cyan
<#
.SYNOPSIS
    M365 / Entra Privileged Access Audit.

.DESCRIPTION
    Raportoi Entra ID:n ja Microsoft 365:n korkean oikeustason roolit, admin-käyttäjät ja PIM-/persistent assignment -havainnot.

.REQUIREMENTS
    - Microsoft Graph PowerShell -moduulit ja rooli-/hakemistotietojen lukuoikeudet

.OUTPUTS
    - HTML/CSV-raportit etuoikeutetuista rooleista

.EXAMPLE
    .\Invoke-EntraPrivilegedAccessAudit.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Invoke-EntraPrivilegedAccessAudit.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

# =========================================================
# M365 / Entra Privileged Access Audit (FULL NOC TOOL)
# =========================================================

# =========================================================
# WORKDIR
# =========================================================

$BaseDir = Join-Path $PSScriptRoot "output\m365-privileged"
$HistoryDir = "$BaseDir\history"

New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
New-Item -ItemType Directory -Path $HistoryDir -Force | Out-Null

$MainCsv        = "$BaseDir\M365_Privileged_Users.csv"
$TopCsv         = "$BaseDir\M365_TopRisk_Users.csv"
$GA_NoPIM_Csv   = "$BaseDir\M365_GlobalAdmin_NoPIM.csv"
$DiffFile       = "$BaseDir\M365_Privileged_DIFF.csv"
$HtmlFile       = "$BaseDir\M365_Privileged_Dashboard.html"
$PrevFile       = "$HistoryDir\M365_Privileged_PREV.csv"

# =========================================================
# CONNECT
# =========================================================

Write-Host "🔐 Connecting to Microsoft Graph..."

Connect-MgGraph -Scopes `
"RoleManagement.Read.Directory",
"Directory.Read.All",
"RoleEligibilitySchedule.Read.Directory",
"RoleAssignmentSchedule.Read.Directory",
"AuditLog.Read.All"

# =========================================================
# CACHE
# =========================================================

Write-Host "📦 Loading roles..."
$Roles = Get-MgRoleManagementDirectoryRoleDefinition
$RoleMap = @{}
$Roles | ForEach-Object { $RoleMap[$_.Id] = $_.DisplayName }

Write-Host "📦 Loading users..."
$Users = Get-MgUser -All -Property Id,UserPrincipalName,SignInActivity
$UserMap = @{}
$UserSignIn = @{}

foreach ($u in $Users) {

    $UserMap[$u.Id] = $u.UserPrincipalName

    if ($u.SignInActivity -and $u.SignInActivity.LastSignInDateTime) {

        try {
            # Graph antaa UTC (Z) → muunnetaan Suomen aikaan
            $utc   = [datetime]$u.SignInActivity.LastSignInDateTime
            $local = $utc.ToLocalTime()

            # Suomalainen formaatti (luettava eikä mikään ISO-hirviö)
            $UserSignIn[$u.Id] = $local.ToString("dd.MM.yyyy HH:mm")
        }
        catch {
            $UserSignIn[$u.Id] = $null
        }

    } else {
        $UserSignIn[$u.Id] = $null
    }
}

Write-Host "📦 Loading service principals..."
$SPs = Get-MgServicePrincipal -All -Property Id,DisplayName,PasswordCredentials
$SPMap = @{}
$SPRisk = @{}

foreach ($sp in $SPs) {
    $SPMap[$sp.Id] = "APP: " + $sp.DisplayName

    $expired = $false
    foreach ($cred in $sp.PasswordCredentials) {
        if ($cred.EndDateTime -lt (Get-Date)) { $expired = $true }
    }

    $SPRisk[$sp.Id] = if ($expired) { "EXPIRED_SECRET" } else { "OK" }
}

Write-Host "📦 Loading groups..."
$Groups = Get-MgGroup -All -Property Id,DisplayName
$GroupMap = @{}
$Groups | ForEach-Object { $GroupMap[$_.Id] = "GROUP: " + $_.DisplayName }

function Resolve-Principal {
    param($Id)

    if ($UserMap.ContainsKey($Id)) { return $UserMap[$Id] }
    if ($SPMap.ContainsKey($Id))   { return $SPMap[$Id] }
    if ($GroupMap.ContainsKey($Id)){ return $GroupMap[$Id] }

    return "UNKNOWN: $Id"
}

# =========================================================
# HIGH RISK ROLES
# =========================================================

$HighRiskRoles = @(
"Global Administrator",
"Privileged Role Administrator",
"Security Administrator",
"Exchange Administrator",
"SharePoint Administrator",
"Conditional Access Administrator",
"Application Administrator",
"Cloud Application Administrator"
)

# =========================================================
# DATA
# =========================================================

Write-Host "🔍 Fetching assignments..."

$Active    = Get-MgRoleManagementDirectoryRoleAssignment -All
$Eligible  = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All
$PIMActive = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All

# =========================================================
# PIM MAP
# =========================================================

$PIMMap = @{}
function Add-ToMap { param($p,$r) $PIMMap["$p|$r"] = $true }

$Eligible  | ForEach-Object { Add-ToMap $_.PrincipalId $_.RoleDefinitionId }
$PIMActive | ForEach-Object { Add-ToMap $_.PrincipalId $_.RoleDefinitionId }

# =========================================================
# RISK FUNCTION
# =========================================================

function Get-Risk {
    param($roleName, $isPermanentWithoutPIM, $isActive)

    $score = 0
    if ($HighRiskRoles -contains $roleName) { $score += 50 }
    if ($isActive) { $score += 30 }
    if ($isPermanentWithoutPIM) { $score += 40 }

    if ($score -ge 80) { return "CRITICAL" }
    elseif ($score -ge 50) { return "HIGH" }
    elseif ($score -ge 30) { return "MEDIUM" }
    else { return "LOW" }
}

# =========================================================
# BUILD RESULT
# =========================================================

$Result = @()

foreach ($a in $Active) {

    $role = $RoleMap[$a.RoleDefinitionId]
    $key  = "$($a.PrincipalId)|$($a.RoleDefinitionId)"

    $hasPIM = $PIMMap.ContainsKey($key)

    $Result += [pscustomobject]@{
        Principal = Resolve-Principal $a.PrincipalId
        Role      = $role
        Type      = "Permanent"
        IsActiveNow = "YES"
        PermanentWithoutPIM = if (-not $hasPIM) {"YES"} else {"NO"}
        RiskLevel = Get-Risk $role (-not $hasPIM) $true
        LastSignIn = $UserSignIn[$a.PrincipalId]
        SPRisk = $SPRisk[$a.PrincipalId]
    }
}

foreach ($e in $Eligible) {
    $Result += [pscustomobject]@{
        Principal = Resolve-Principal $e.PrincipalId
        Role      = $RoleMap[$e.RoleDefinitionId]
        Type      = "Eligible"
        IsActiveNow = "NO"
        PermanentWithoutPIM = "N/A"
        RiskLevel = "LOW"
        LastSignIn = $UserSignIn[$e.PrincipalId]
        SPRisk = $SPRisk[$e.PrincipalId]
    }
}

foreach ($p in $PIMActive) {
    $role = $RoleMap[$p.RoleDefinitionId]

    $Result += [pscustomobject]@{
        Principal = Resolve-Principal $p.PrincipalId
        Role      = $role
        Type      = "Active (PIM)"
        IsActiveNow = "YES"
        PermanentWithoutPIM = "N/A"
        RiskLevel = Get-Risk $role $false $true
        LastSignIn = $UserSignIn[$p.PrincipalId]
        SPRisk = $SPRisk[$p.PrincipalId]
    }
}

# =========================================================
# EXPORT CSV
# =========================================================

$Result | Sort-Object Principal, Role -Unique |
Export-Csv $MainCsv -NoTypeInformation -Encoding UTF8

# =========================================================
# SNAPSHOT HISTORY (🔥 uusi lisäys)
# =========================================================

$ts = Get-Date -Format "yyyy-MM-dd_HHmm"
Copy-Item $MainCsv "$HistoryDir\M365_$ts.csv"

# =========================================================
# DIFF
# =========================================================

if (Test-Path $PrevFile) {

    Write-Host "🔍 Lasketaan diff..."

    $Prev = Import-Csv $PrevFile
    $Now  = Import-Csv $MainCsv

    $diff = Compare-Object $Prev $Now -Property Principal,Role,Type -PassThru

    if ($diff) {
        $diff | Export-Csv $DiffFile -NoTypeInformation
        Write-Host "📊 Diff valmis: $DiffFile"
    } else {
        Write-Host "✔️ Ei muutoksia"
    }
}

Copy-Item $MainCsv $PrevFile -Force

# =========================================================
# TOP USERS
# =========================================================

$Result | Group-Object Principal | ForEach-Object {
    $u = $_.Group
    [pscustomobject]@{
        Principal = $_.Name
        RoleCount = $u.Count
        CriticalRoles = ($u | Where {$_.RiskLevel -eq "CRITICAL"}).Count
        PermanentNoPIM = ($u | Where {$_.PermanentWithoutPIM -eq "YES"}).Count
    }
} | Sort-Object CriticalRoles, RoleCount -Descending |
Export-Csv $TopCsv -NoTypeInformation

# =========================================================
# GLOBAL ADMIN NO PIM
# =========================================================

$Result | Where {
    $_.Role -eq "Global Administrator" -and
    $_.PermanentWithoutPIM -eq "YES"
} | Export-Csv $GA_NoPIM_Csv -NoTypeInformation

# =========================================================
# TENANT SCORE
# =========================================================

$score =
($Result | Where {$_.RiskLevel -eq "CRITICAL"}).Count * 5 +
($Result | Where {$_.RiskLevel -eq "HIGH"}).Count * 3 +
($Result | Where {$_.RiskLevel -eq "MEDIUM"}).Count * 1

Write-Host "🔥 Tenant Risk Score: $score"

# =========================================================
# HTML DASHBOARD (NOC + FILTERS + SORT + PAGINATION)
# =========================================================

$Json = ($Result | ConvertTo-Json -Depth 5 -Compress) -replace '</script>','<\/script>'

$Html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>M365 Privileged NOC</title>

<style>
body { font-family:Segoe UI; background:#0b1220; color:#e5e7eb; margin:20px }

.card { display:inline-block; padding:10px; margin:5px; background:#0f172a; border-radius:10px }

.bad { color:#dc2626 }
.warn { color:#eab308 }

table { width:100%; border-collapse:collapse; margin-top:10px }
th,td { padding:8px; border-bottom:1px solid #1f2937 }
th { background:#111827; cursor:pointer; position:sticky; top:0 }

tr:hover { background:#1f2937 }
.row-bad { background: rgba(220,38,38,0.2) }

input, select, button { padding:6px; margin-right:10px }

/* FILTER BUTTONS */
.flt {
    background:#1f2937;
    color:#e5e7eb;
    border:none;
    border-radius:6px;
    cursor:pointer;
}

.flt.active {
    background:#dc2626;
    color:#fff;
}
</style>
</head>

<body>

<h1>M365 Privileged NOC</h1>

<input id="search" placeholder="Search..." onkeyup="filter()">

<select id="pageSize" onchange="changePageSize()">
<option value="5">5</option>
<option value="10" selected>10</option>
<option value="20">20</option>
<option value="50">50</option>
<option value="100">100</option>
<option value="all">ALL</option>
</select>

<!-- 🔥 NOC FILTER BUTTONS -->
<div style="margin-top:10px">
<button class="flt" onclick="toggleFilter('CRITICAL')">CRITICAL</button>
<button class="flt" onclick="toggleFilter('HIGH')">HIGH</button>
<button class="flt" onclick="toggleFilter('ACTIVE')">ACTIVE</button>
<button class="flt" onclick="toggleFilter('NOPIM')">NO PIM</button>
<button class="flt" onclick="resetFilters()">RESET</button>
</div>

<div id="cards"></div>

<table id="tbl">
<thead>
<tr>
<th onclick="sortBy('Principal')">Principal</th>
<th onclick="sortBy('Role')">Role</th>
<th onclick="sortBy('Type')">Type</th>
<th onclick="sortBy('RiskLevel')">Risk</th>
<th onclick="sortBy('IsActiveNow')">Active</th>
<th onclick="sortBy('PermanentWithoutPIM')">No PIM</th>
<th onclick="sortBy('LastSignIn')">Last Sign-In</th>
</tr>
</thead>
<tbody></tbody>
</table>

<script id="data" type="application/json">
$Json
</script>

<script>

// ===== LOAD DATA SAFE =====
let data = [];
try {
    data = JSON.parse(document.getElementById("data").textContent);
} catch(e){
    console.error("JSON parse error:", e);
}

let filtered = [...data];
let sortDir = 1;
let currentPage = 1;
let pageSize = 10;
let activeFilters = new Set();

// ===== SORT =====
function sortBy(key){

    filtered.sort((a,b)=>{

        let x = a[key] || "";
        let y = b[key] || "";

        if(key === "LastSignIn"){
            return (new Date(x||0) - new Date(y||0)) * sortDir;
        }

        return x.toString().localeCompare(y.toString()) * sortDir;
    });

    sortDir *= -1;
    render();
}

// ===== FILTER TEXT =====
function filter(){

    let q = document.getElementById("search").value.toLowerCase();

    let base = data.filter(d =>
        (d.Principal || "").toLowerCase().includes(q) ||
        (d.Role || "").toLowerCase().includes(q)
    );

    filtered = base;
    applyFilters();
}

// ===== NOC FILTER BUTTONS =====
function toggleFilter(type){

    if(activeFilters.has(type)){
        activeFilters.delete(type);
    } else {
        activeFilters.add(type);
    }

    updateFilterUI();
    applyFilters();
}

function resetFilters(){
    activeFilters.clear();
    filtered = [...data];
    updateFilterUI();
    render();
}

function updateFilterUI(){

    document.querySelectorAll(".flt").forEach(btn=>{
        btn.classList.remove("active");

        let txt = btn.innerText.toUpperCase();

        if(activeFilters.has(txt) ||
           (txt === "NO PIM" && activeFilters.has("NOPIM"))){
            btn.classList.add("active");
        }
    });
}

function applyFilters(){

    filtered = filtered.filter(d => {

        let ok = true;

        if(activeFilters.has("CRITICAL")){
            ok = ok && d.RiskLevel === "CRITICAL";
        }

        if(activeFilters.has("HIGH")){
            ok = ok && (d.RiskLevel === "HIGH" || d.RiskLevel === "CRITICAL");
        }

        if(activeFilters.has("ACTIVE")){
            ok = ok && d.IsActiveNow === "YES";
        }

        if(activeFilters.has("NOPIM")){
            ok = ok && d.PermanentWithoutPIM === "YES";
        }

        return ok;
    });

    currentPage = 1;
    render();
}

// ===== PAGINATION =====
function changePageSize(){
    let val = document.getElementById("pageSize").value;
    pageSize = val === "all" ? filtered.length : parseInt(val);
    currentPage = 1;
    render();
}

// ===== RENDER =====
function render(){

    let tbody = document.querySelector("#tbl tbody");
    tbody.innerHTML = "";

    let start = (currentPage - 1) * pageSize;
    let end = pageSize === filtered.length ? filtered.length : start + pageSize;

    let pageData = filtered.slice(start, end);

    let critical = filtered.filter(d => d.RiskLevel==="CRITICAL").length;

    pageData.forEach(d => {

        let tr = document.createElement("tr");

        if(d.RiskLevel==="CRITICAL"){
            tr.className="row-bad";
        }

        tr.innerHTML =
            "<td>"+(d.Principal||"")+"</td>"+
            "<td>"+(d.Role||"")+"</td>"+
            "<td>"+(d.Type||"")+"</td>"+
            "<td>"+(d.RiskLevel||"")+"</td>"+
            "<td>"+(d.IsActiveNow||"")+"</td>"+
            "<td>"+(d.PermanentWithoutPIM||"")+"</td>"+
            "<td>"+(d.LastSignIn||"-")+"</td>";

        tbody.appendChild(tr);
    });

    document.getElementById("cards").innerHTML =
        "<div class='card'>Total: "+filtered.length+"</div>"+
        "<div class='card bad'>Critical: "+critical+"</div>";
}

// ===== INIT =====
render();

</script>

</body>
</html>
"@

$Html | Out-File $HtmlFile -Encoding UTF8

Write-Host "🌐 Dashboard: $HtmlFile"
<#
.SYNOPSIS
    Exchange Online Mail Groups Audit Dashboard.

.DESCRIPTION
    Auditoi Exchange Online- ja Microsoft 365 -ryhmät, jakeluryhmät, jäsenyydet ja näkyvyyteen liittyvät perustiedot.

.REQUIREMENTS
    - ExchangeOnlineManagement-moduuli ja tarvittavat Exchange Online -lukuoikeudet

.OUTPUTS
    - Offline HTML-dashboard ja CSV-raportit ryhmistä

.EXAMPLE
    .\Invoke-ExchangeOnlineGroupAuditReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Invoke-ExchangeOnlineGroupAuditReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

# =========================================================
# Exchange Groups Audit Dashboard v2.3 (CLEAN BASELINE)
# - Offline HTML (file://) works
# - Avoids PowerShell breaking JS template literals (${...})
# - Data embedded as Base64(JSON)
# =========================================================

$OutDir = Join-Path $PSScriptRoot "output\exchange-groups"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$SummaryHtml = Join-Path $OutDir "ExchangeGroups_Dashboard_v2_3.html"
$SummaryCsv  = Join-Path $OutDir "ExchangeGroups_Summary.csv"

Write-Host "🔍 Haetaan ryhmät..."

# -------------------------
# LOAD
# -------------------------
$AllM365Groups = Get-UnifiedGroup -ResultSize Unlimited -WarningAction SilentlyContinue
$AllDGs = Get-DistributionGroup -ResultSize Unlimited -WarningAction SilentlyContinue |
    Where-Object { $_.RecipientTypeDetails -ne "MailUniversalSecurityGroup" }

$AcceptedDomains = Get-AcceptedDomain |
    Select-Object -ExpandProperty DomainName |
    ForEach-Object { $_.ToLower() }

# -------------------------
# HELPERS
# -------------------------
function Get-Class {
    param($R)

    if ($R.ExternalEmailAddress) { return "Guest" }
    if ($R.RecipientTypeDetails -eq "MailContact") { return "Guest" }

    if ($R.PrimarySmtpAddress) {
        $d = ($R.PrimarySmtpAddress -split "@")[-1].ToLower()
        if ($AcceptedDomains -notcontains $d) { return "Guest" }
    }

    return "Internal"
}

function Get-Email {
    param($R)
    if ($R.PrimarySmtpAddress) { return $R.PrimarySmtpAddress.ToString() }
    elseif ($R.ExternalEmailAddress) { return $R.ExternalEmailAddress.ToString() }
    else { return "UNKNOWN" }
}

function Get-OwnersSafe {
    param($ManagedBy)
    $ManagedBy | ForEach-Object {
        try {
            (Get-Recipient $_ -ErrorAction Stop).PrimarySmtpAddress.ToString()
        } catch { $null }
    } | Where-Object { $_ }
}

# -------------------------
# DATA
# -------------------------
$Summary = @()

foreach ($g in $AllM365Groups) {
    $Owners  = Get-UnifiedGroupLinks $g.Identity -LinkType Owners  -ResultSize Unlimited
    $Members = Get-UnifiedGroupLinks $g.Identity -LinkType Members -ResultSize Unlimited

    $ownerArr = @($Owners  | ForEach-Object { $_.PrimarySmtpAddress.ToString() } | Where-Object { $_ })

    $intArr = New-Object System.Collections.Generic.List[string]
    $extArr = New-Object System.Collections.Generic.List[string]

    foreach ($m in $Members) {
        $email = Get-Email $m
        if ((Get-Class $m) -eq "Guest") { $extArr.Add($email) } else { $intArr.Add($email) }
    }

    $risk = if ($ownerArr.Count -eq 0) { "HIGH" } elseif ($extArr.Count -gt 0) { "MEDIUM" } else { "OK" }

    $Summary += [pscustomobject]@{
        GroupType          = "M365Group"
        GroupName          = $g.DisplayName
        Owners             = ($ownerArr -join "; ")
        OwnersArr          = $ownerArr
        MemberCount        = $Members.Count
        Members_Internal   = ($intArr -join "; ")
        Members_Guest      = ($extArr -join "; ")
        MembersInternalArr = @($intArr)
        MembersGuestArr    = @($extArr)
        DirSynced          = [bool]$g.IsDirSynced
        Risk               = $risk
    }
}

foreach ($g in $AllDGs) {
    $ownerArr = @(Get-OwnersSafe $g.ManagedBy)
    $Members  = Get-DistributionGroupMember $g.Identity -ResultSize Unlimited

    $intArr = New-Object System.Collections.Generic.List[string]
    $extArr = New-Object System.Collections.Generic.List[string]

    foreach ($m in $Members) {
        $email = Get-Email $m
        if ((Get-Class $m) -eq "Guest") { $extArr.Add($email) } else { $intArr.Add($email) }
    }

    $risk = if ($ownerArr.Count -eq 0) { "HIGH" } elseif ($extArr.Count -gt 0) { "MEDIUM" } else { "OK" }

    $Summary += [pscustomobject]@{
        GroupType          = "DistributionGroup"
        GroupName          = $g.DisplayName
        Owners             = ($ownerArr -join "; ")
        OwnersArr          = $ownerArr
        MemberCount        = $Members.Count
        Members_Internal   = ($intArr -join "; ")
        Members_Guest      = ($extArr -join "; ")
        MembersInternalArr = @($intArr)
        MembersGuestArr    = @($extArr)
        DirSynced          = [bool]$g.IsDirSynced
        Risk               = $risk
    }
}

# -------------------------
# CLEAN (remove newlines)
# -------------------------
$Summary | ForEach-Object {
    $_.Owners           = $_.Owners           -replace "`r?`n"," "
    $_.Members_Internal = $_.Members_Internal -replace "`r?`n"," "
    $_.Members_Guest    = $_.Members_Guest    -replace "`r?`n"," "
}

# -------------------------
# EXPORT CSV (full)
# -------------------------
$Summary | Export-Csv $SummaryCsv -NoTypeInformation -Encoding UTF8

# -------------------------
# JSON -> Base64 (offline safe)
# -------------------------
$Json = $Summary | ConvertTo-Json -Depth 10 -Compress
$B64  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Json))

# -------------------------
# HTML TEMPLATE
# IMPORTANT: use single-quoted here-string to prevent PowerShell expanding $ inside JS (${...})
# -------------------------
$HtmlTemplate = @'
<!doctype html>
<html lang="fi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exchange Groups NOC v2.3</title>
<style>
  body { font-family: Segoe UI, Arial; background:#0b1220; color:#e5e7eb; margin:20px; }
  h1 { margin: 0 0 10px 0; }
  .toolbar { display:flex; gap:12px; flex-wrap:wrap; align-items:center; margin: 10px 0 12px 0; }
  .card { display:inline-block; padding:12px 14px; background:#0f172a; border-radius:12px; box-shadow: 0 6px 14px rgba(0,0,0,.25); }
  .muted { color:#94a3b8; }
  .bad { color:#f87171; }
  .warn { color:#fbbf24; }
  .ok { color:#34d399; }

  input[type="text"] { padding:10px 12px; width:320px; max-width:80vw; border-radius:10px; border:1px solid #243041; background:#0f172a; color:#e5e7eb; }
  .chip { padding:8px 10px; border:1px solid #243041; border-radius:999px; background:#0f172a; }
  button { padding:10px 12px; border-radius:10px; border:1px solid #243041; background:#111827; color:#e5e7eb; cursor:pointer; }
  button:hover { background:#1f2937; }

  table { width:100%; border-collapse:collapse; margin-top:10px; }
  th, td { padding:10px 10px; border-bottom:1px solid #1f2937; vertical-align:top; }
  th { background:#0f172a; position: sticky; top:0; cursor:pointer; z-index:2; }
  tr:hover { background:#111827; }

  .row-bad  { background: rgba(248,113,113,0.10); }
  .row-warn { background: rgba(251,191,36,0.08); }

  .expander { width:34px; text-align:center; }
  .expbtn { width:28px; height:28px; border-radius:8px; border:1px solid #243041; background:#0b1220; color:#e5e7eb; cursor:pointer; }
  .expbtn:hover { background:#111827; }

  .details { background:#0b1220; }
  .details .grid { display:grid; grid-template-columns: 1fr 1fr; gap:12px; padding: 10px 0; }
  .panel { background:#0f172a; border:1px solid #243041; border-radius:14px; padding:12px; }
  .panel h3 { margin:0 0 8px 0; font-size:14px; color:#cbd5e1; }
  .list { max-height: 220px; overflow:auto; padding-right:6px; }
  .pill { display:inline-block; margin: 4px 6px 0 0; padding: 5px 8px; border-radius:999px; background:#111827; border:1px solid #243041; font-size:12px; }
  .copy { float:right; font-size:12px; padding: 6px 8px; border-radius: 10px; }
  .nowrap { white-space: nowrap; }
  .tooltip { border-bottom: 1px dotted #94a3b8; cursor: help; }
</style>
</head>

<body>
<h1>Exchange Groups NOC <span class="muted">v2.3</span></h1>

<div class="toolbar">
  <input id="search" type="text" placeholder="Hae ryhmä / owner / tyyppi..." onkeyup="applyFilters()">
  <span class="chip"><label><input type="checkbox" id="fHigh" onchange="applyFilters()"> HIGH only</label></span>
  <span class="chip"><label><input type="checkbox" id="fGuests" onchange="applyFilters()"> Guests only</label></span>
  <span class="chip"><label><input type="checkbox" id="fHideOk" onchange="applyFilters()"> Hide OK</label></span>
  <span class="chip"><label><input type="checkbox" id="fM365" checked onchange="applyFilters()"> M365</label></span>
  <span class="chip"><label><input type="checkbox" id="fDG" checked onchange="applyFilters()"> DG</label></span>
  <button onclick="exportVisibleCSV()">Export visible CSV</button>
</div>

<div id="cards" style="display:flex; gap:10px; flex-wrap:wrap;"></div>

<table id="tbl">
  <thead>
    <tr>
      <th class="expander"></th>
      <th onclick="sortBy('GroupType')">Type</th>
      <th onclick="sortBy('GroupName')">Group</th>
      <th onclick="sortBy('Owners')">Owners</th>
      <th onclick="sortBy('MemberCount')" class="nowrap">Size</th>
      <th onclick="sortBy('Risk')">Risk</th>
      <th onclick="sortBy('DirSynced')">Sync</th>
    </tr>
  </thead>
  <tbody></tbody>
</table>

<!-- data: base64(JSON) -->
<script id="data" type="text/plain">__DATA_B64__</script>

<script>
  const esc = (s) => (s ?? "").toString()
    .replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")
    .replaceAll('"',"&quot;").replaceAll("'","&#39;");

  const uniq = (arr) => Array.from(new Set((arr ?? []).filter(Boolean)));

  // Load data from base64
  let data = [];
  try {
    const raw = document.getElementById("data").textContent.trim();
    const decoded = atob(raw);
    if (decoded.trim().startsWith("<")) {
      throw new Error("Decoded payload looks like HTML (should be JSON). First 80 chars: " + decoded.slice(0,80));
    }
    data = JSON.parse(decoded);
  } catch(e) {
    document.body.insertAdjacentHTML("beforeend",
      `<pre style="color:#f87171; white-space:pre-wrap;">${esc(e?.stack || e)}</pre>`);
  }

  // Normalize arrays + compute counts
  data.forEach(d => {
    d.OwnersArr = uniq(d.OwnersArr);
    d.MembersInternalArr = uniq(d.MembersInternalArr);
    d.MembersGuestArr = uniq(d.MembersGuestArr);
    d.GuestCount = d.MembersGuestArr.length;
    d.InternalCount = d.MembersInternalArr.length;
  });

  let filtered = [...data];
  let sortKey = "Risk";
  let sortDir = -1;

  function applyFilters(){
    const q = (document.getElementById("search").value || "").toLowerCase();
    const fHigh   = document.getElementById("fHigh").checked;
    const fGuests = document.getElementById("fGuests").checked;
    const fHideOk = document.getElementById("fHideOk").checked;
    const fM365   = document.getElementById("fM365").checked;
    const fDG     = document.getElementById("fDG").checked;

    filtered = data.filter(d => {
      const matchQ =
        (d.GroupName || "").toLowerCase().includes(q) ||
        (d.Owners || "").toLowerCase().includes(q) ||
        (d.GroupType || "").toLowerCase().includes(q);

      const matchType =
        (fM365 && d.GroupType === "M365Group") ||
        (fDG && d.GroupType === "DistributionGroup");

      const matchHigh   = !fHigh   || d.Risk === "HIGH";
      const matchGuests = !fGuests || d.GuestCount > 0;
      const matchOk     = !fHideOk || d.Risk !== "OK";

      return matchQ && matchType && matchHigh && matchGuests && matchOk;
    });

    sortBy(sortKey, true);
  }

  function sortBy(key, silent=false){
    sortKey = key;
    const orderRisk = { HIGH: 3, MEDIUM: 2, OK: 1 };

    filtered.sort((a,b) => {
      let A = a[key], B = b[key];

      if (key === "MemberCount" || key === "GuestCount" || key === "InternalCount") {
        return (Number(A||0) - Number(B||0)) * sortDir;
      }
      if (key === "Risk") {
        return ((orderRisk[A]||0) - (orderRisk[B]||0)) * sortDir;
      }
      if (key === "DirSynced") {
        return (((A?1:0) - (B?1:0)) * sortDir);
      }
      A = (A ?? "").toString().toLowerCase();
      B = (B ?? "").toString().toLowerCase();
      return A.localeCompare(B) * sortDir;
    });

    if(!silent) sortDir *= -1;
    render();
  }

  function renderPills(arr){
    const a = uniq(arr);
    if (!a.length) return `<span class="muted">-</span>`;
    return a.map(x => `<span class="pill">${esc(x)}</span>`).join("");
  }

  function toggleDetails(ev, idx){
    ev.stopPropagation();
    const btn = ev.currentTarget;
    const row = document.querySelector(`tr[data-details-for="${idx}"]`);
    const isOpen = row.style.display !== "none";
    row.style.display = isOpen ? "none" : "table-row";
    btn.textContent = isOpen ? "▸" : "▾";
  }

  async function copyList(ev, idx, key){
    ev.stopPropagation();
    const d = filtered[idx];
    const items = (d && d[key]) ? uniq(d[key]).join("\r\n") : "";
    try {
      await navigator.clipboard.writeText(items);
      ev.currentTarget.textContent = "Copied!";
      setTimeout(()=> ev.currentTarget.textContent = "Copy", 900);
    } catch {
      alert("Clipboard ei käytettävissä (file:// rajoitus tai selaimen asetukset).");
    }
  }

  function render(){
    const tbody = document.querySelector("#tbl tbody");
    tbody.innerHTML = "";

    let high=0, med=0, ok=0, guests=0;

    filtered.forEach((d, idx) => {
      if (d.Risk === "HIGH") high++;
      else if (d.Risk === "MEDIUM") med++;
      else ok++;

      guests += d.GuestCount;

      const tr = document.createElement("tr");
      if (d.Risk === "HIGH") tr.className = "row-bad";
      if (d.Risk === "MEDIUM") tr.className = "row-warn";

      tr.innerHTML = `
        <td class="expander">
          <button class="expbtn" title="Avaa tiedot" onclick="toggleDetails(event, ${idx})">▸</button>
        </td>
        <td>${esc(d.GroupType)}</td>
        <td>${esc(d.GroupName)}</td>
        <td>${
          (!d.OwnersArr || d.OwnersArr.length === 0)
            ? `<span class="bad tooltip" title="Tällä ryhmällä ei ole owneria (risk HIGH).">NONE</span>`
            : esc(d.OwnersArr.join("; "))
        }</td>
        <td class="nowrap">
          ${d.MemberCount} <span class="muted">(I:${d.InternalCount} / G:${d.GuestCount})</span>
        </td>
        <td class="${esc((d.Risk||"").toLowerCase())}">${esc(d.Risk)}</td>
        <td>${d.DirSynced ? "AD" : "Cloud"}</td>
      `;

      const trD = document.createElement("tr");
      trD.className = "details";
      trD.style.display = "none";
      trD.setAttribute("data-details-for", idx);

      trD.innerHTML = `
        <td colspan="7">
          <div class="grid">
            <div class="panel">
              <button class="copy" onclick="copyList(event, ${idx}, 'OwnersArr')">Copy</button>
              <h3>Owners (${(d.OwnersArr||[]).length})</h3>
              <div class="list">${renderPills(d.OwnersArr)}</div>
            </div>
            <div class="panel">
              <button class="copy" onclick="copyList(event, ${idx}, 'MembersInternalArr')">Copy</button>
              <h3>Internal (${d.InternalCount})</h3>
              <div class="list">${renderPills(d.MembersInternalArr)}</div>
            </div>
            <div class="panel" style="grid-column: 1 / span 2;">
              <button class="copy" onclick="copyList(event, ${idx}, 'MembersGuestArr')">Copy</button>
              <h3>Guests (${d.GuestCount})</h3>
              <div class="list">${renderPills(d.MembersGuestArr)}</div>
            </div>
          </div>
        </td>
      `;

      tbody.appendChild(tr);
      tbody.appendChild(trD);
    });

    document.getElementById("cards").innerHTML = `
      <div class="card">Total: <b>${filtered.length}</b></div>
      <div class="card bad">High: <b>${high}</b></div>
      <div class="card warn">Medium: <b>${med}</b></div>
      <div class="card ok">OK: <b>${ok}</b></div>
      <div class="card">Guests total: <b>${guests}</b></div>
    `;
  }

  function exportVisibleCSV(){
    const header = ["Type","Group","Owners","Size","Risk","Sync","InternalCount","GuestCount"];
    const rows = [header];

    filtered.forEach(d => {
      rows.push([
        d.GroupType,
        d.GroupName,
        (d.OwnersArr||[]).join("; "),
        d.MemberCount,
        d.Risk,
        d.DirSynced ? "AD" : "Cloud",
        d.InternalCount,
        d.GuestCount
      ]);
    });

    const csv = "\uFEFF" + rows.map(r => r.map(v => {
      const s = (v ?? "").toString().replaceAll('"','""');
      return `"${s}"`;
    }).join(";")).join("\r\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "exchange_groups_visible.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  // init
  applyFilters();
</script>

</body>
</html>
'@

# Inject base64 data safely
$Html = $HtmlTemplate -replace '__DATA_B64__', $B64

# Write file
$Html | Out-File $SummaryHtml -Encoding UTF8

# -------------------------
# SELF-HEAL: if file got HTML-encoded for any reason, decode and overwrite
# -------------------------
$firstLine = (Get-Content $SummaryHtml -TotalCount 1 -Raw)
if ($firstLine -match '&lt;!doctype') {
    Write-Host "⚠️ HTML oli escapattu (&lt;...&gt;). Tehdään HtmlDecode ja kirjoitetaan uudelleen..." -ForegroundColor Yellow
    $content = Get-Content $SummaryHtml -Raw
    $decoded = [System.Net.WebUtility]::HtmlDecode($content)
    $decoded | Out-File $SummaryHtml -Encoding UTF8
}

Write-Host "📊 HTML valmis: $SummaryHtml"
Write-Host "📄 CSV valmis:  $SummaryCsv"
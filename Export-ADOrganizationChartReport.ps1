<#
.SYNOPSIS
    Active Directory Organization Chart Report.

.DESCRIPTION
    Luo Active Directoryn manager/report-suhteista HTML-muotoisen organisaatiokaavion ilman ympäristökohtaisia kovakoodauksia.

.REQUIREMENTS
    - ActiveDirectory PowerShell -moduuli ja lukuoikeus AD:hen

.OUTPUTS
    - HTML-organisaatiokaavio

.EXAMPLE
    .\Export-ADOrganizationChartReport.ps1

.NOTES
    Author: Repository maintainer
    Repository: PowerShell audit and reporting scripts
    Script file: Export-ADOrganizationChartReport.ps1

.DISCLAIMER
    AI-ASSISTED: Parts of this script may have been developed with assistance from ChatGPT/OpenAI.
    REVIEW REQUIRED: The author/operator is responsible for reviewing, testing and validating the script before use.
    TEST FIRST: Run and validate in a lab, sandbox, pilot group, test tenant or other non-production environment before production use.
    USE AT YOUR OWN RISK: Provided as-is, without warranty. The author and AI provider are not responsible for damage, data loss or operational impact.
    READ-ONLY INTENT: This script is intended for audit/reporting use. Verify permissions, scopes and commands before execution.
#>

param(
  [string]$DomainController,
  [string]$SearchBase,
  [string]$OutputPath = (Join-Path $PSScriptRoot "organization-chart.html")
)

function New-ADManagersWithReportsHtml {
  param(
    [Parameter(Mandatory)] [string]$Server,
    [Parameter(Mandatory)] [string]$SearchBase
  )

  Add-Type -AssemblyName System.Net

  function Escape-Html([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($s)
  }

  # ----- CSS -----
  $style = @"
<style>
  body{
    font-family:Segoe UI,Arial,sans-serif;
    background:#0b1220;
    color:#e5e7eb;
    padding:20px;
  }
  h1{
    margin:0 0 8px 0;
    font-size:22px;
  }
  .meta{
    color:#94a3b8;
    margin-bottom:14px;
    line-height:1.4;
  }
  .meta-main{
    color:#cbd5e1;
    font-weight:600;
  }
  .meta-sub{
    color:#94a3b8;
    font-size:13px;
    margin-top:2px;
  }
  .toolbar{
    margin:14px 0 16px 0;
  }
  .search{
    width:100%;
    max-width:520px;
    background:#111827;
    color:#e5e7eb;
    border:1px solid #334155;
    border-radius:10px;
    padding:10px 12px;
    font-size:14px;
    outline:none;
  }
  .search:focus{
    border-color:#64748b;
    box-shadow:0 0 0 3px rgba(100,116,139,.15);
  }
  .hint{
    margin-top:6px;
    color:#94a3b8;
    font-size:12px;
  }
  .card{
    background:#0f172a;
    border:1px solid #1f2937;
    border-radius:12px;
    padding:14px;
  }
  ul.tree{
    list-style:none;
    padding-left:0;
    margin:0;
  }
  ul.tree ul{
    list-style:none;
    padding-left:18px;
    margin:8px 0 0 0;
    border-left:1px solid #1f2937;
  }
  li{
    margin:10px 0;
    position:relative;
    padding-left:12px;
  }
  li:before{
    content:"";
    position:absolute;
    left:0;
    top:18px;
    width:10px;
    border-top:1px solid #1f2937;
  }
  .toggle{
    cursor:pointer;
    user-select:none;
    margin-right:8px;
    display:inline-block;
    min-width:18px;
    text-align:center;
    border:1px solid #1f2937;
    border-radius:6px;
    color:#94a3b8;
    font-weight:700;
    font-size:12px;
    line-height:16px;
    vertical-align:top;
    margin-top:8px;
    background:transparent;
  }
  .toggle[data-leaf="1"]{
    opacity:.35;
    cursor:default;
  }
  .person{
    display:inline-block;
    vertical-align:top;
    min-width:320px;
    max-width:420px;
    width:100%;
    background:#111827;
    border:1px solid #1f2937;
    border-radius:10px;
    padding:10px 12px;
    box-sizing:border-box;
  }
  .name{
    font-size:15px;
    font-weight:700;
    color:#f8fafc;
    margin-bottom:8px;
  }
  .row{
    margin:6px 0;
    line-height:1.45;
    display:flex;
    align-items:flex-start;
    gap:8px;
  }
  .label{
    display:block;
    width:120px;
    min-width:120px;
    flex:0 0 120px;
    color:#94a3b8;
    font-weight:600;
  }
  .value{
    color:#e5e7eb;
    display:block;
    flex:1 1 auto;
    min-width:0;
    white-space:normal;
    overflow:visible;
    text-overflow:unset;
    word-break:break-word;
    overflow-wrap:anywhere;
  }
  .value.title{
    font-weight:700;
    color:#f8fafc;
  }
  .value.dept{
    color:#94a3b8;
  }
  .badge{
    display:inline-block;
    padding:2px 8px;
    border-radius:999px;
    font-size:12px;
    font-weight:700;
    border:1px solid transparent;
    white-space:nowrap;
  }
  .badge-enabled{
    background:rgba(16,185,129,.12);
    color:#86efac;
    border-color:rgba(16,185,129,.35);
  }
  .badge-disabled{
    background:rgba(239,68,68,.12);
    color:#fca5a5;
    border-color:rgba(239,68,68,.35);
  }
  .children{
    margin-top:8px;
  }
  .collapsed{
    display:none;
  }
  .hidden-by-filter{
    display:none !important;
  }
  .no-results{
    display:none;
    margin-top:12px;
    color:#fca5a5;
    background:#111827;
    border:1px solid #3f1d1d;
    border-radius:10px;
    padding:10px 12px;
  }
  .top-grid{
    display:grid;
    grid-template-columns:repeat(3, minmax(0,1fr));
    gap:22px;
    padding-left:0 !important;
  }
  .top-grid > li{
    list-style:none;
    padding-left:0;
    margin-left:0;
    min-width:0;
  }
  .top-grid > li:before{
    content:none;
  }
  @media (max-width:1400px){
    .top-grid{
      grid-template-columns:repeat(2, minmax(0,1fr));
    }
  }
  @media (max-width:900px){
    .top-grid{
      grid-template-columns:repeat(1, minmax(0,1fr));
    }
  }
</style>
"@

  # ----- PERSON CARD BUILDER -----
  function NodeText($user) {
    $name       = Escape-Html $user.Name
    $title      = Escape-Html $user.Title
    $department = Escape-Html $user.Department
    $company    = Escape-Html $user.Company
    $mail       = Escape-Html $user.mail
    $tel        = Escape-Html $user.telephoneNumber

    $searchBlob = Escape-Html (("$($user.Name) $($user.Title) $($user.Department) $($user.Company) $($user.mail) $($user.telephoneNumber)").ToLower())

    if ($user.Enabled) {
      $statusBadge = "<span class='badge badge-enabled'>Aktiivinen</span>"
    }
    else {
      $statusBadge = "<span class='badge badge-disabled'>Pois käytöstä</span>"
    }

    return @"
<div class='person' data-search='$searchBlob'>
  <div class='name'>$name</div>

  <div class='row'>
    <span class='label'>Nimike</span>
    <span class='value title'>$title</span>
  </div>

  <div class='row'>
    <span class='label'>Osasto</span>
    <span class='value dept'>$department</span>
  </div>

  <div class='row'>
    <span class='label'>Yritys</span>
    <span class='value'>$company</span>
  </div>

  <div class='row'>
    <span class='label'>Sähköposti</span>
    <span class='value'>$mail</span>
  </div>

  <div class='row'>
    <span class='label'>Puhelin</span>
    <span class='value'>$tel</span>
  </div>

  <div class='row'>
    <span class='label'>Tila</span>
    <span class='value'>$statusBadge</span>
  </div>
</div>
"@
  }

  # Recursive tree builder
  function Build-Tree([string]$ManagerDN) {
    $children = Get-ADUser -Server $Server -LDAPFilter "(manager=$ManagerDN)" `
      -Properties Title,Department,Company,Enabled,mail,telephoneNumber |
      Sort-Object Name

    if (-not $children) { return "" }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("<ul>")

    foreach ($u in $children) {
      $sub = Build-Tree $u.DistinguishedName

      if ($sub) {
        [void]$sb.AppendLine("<li><button class='toggle' aria-expanded='false'>+</button>$(NodeText $u)<div class='children collapsed'>$sub</div></li>")
      }
      else {
        [void]$sb.AppendLine("<li><button class='toggle' data-leaf='1' aria-expanded='false'>•</button>$(NodeText $u)</li>")
      }
    }

    [void]$sb.AppendLine("</ul>")
    return $sb.ToString()
  }

  # Root managers
  $managerDns = Get-ADUser -Server $Server -SearchBase $SearchBase `
    -LDAPFilter "(manager=*)" -Properties manager |
    Select-Object -ExpandProperty manager -Unique

  $generatedAt = Get-Date
  $generatedAtEpochMs = ([DateTimeOffset]$generatedAt).ToUnixTimeMilliseconds()

  $meta = @"
<div class='meta'>
  <div class='meta-main'>
    Luotu: <span id='createdAt' data-epoch='$generatedAtEpochMs'>$($generatedAt.ToString("dd.MM.yyyy HH.mm"))</span>
  </div>
</div>
"@

  if (-not $managerDns) {
    $treeHtml = "<div class='meta'>(Ei esihenkilöitä löytynyt tältä OU:lta.)</div>"
  }
  else {
    $mgrObjs = @()

    foreach ($dn in $managerDns) {
      try {
        $obj = Get-ADUser -Server $Server -Identity $dn -Properties Title,Department,Company,Enabled,mail,telephoneNumber
        if ($null -ne $obj) {
          $mgrObjs += $obj
        }
      }
      catch {
      }
    }

    $sbTop = New-Object System.Text.StringBuilder
    [void]$sbTop.AppendLine("<ul class='tree top-grid' id='orgTree'>")

    foreach ($m in ($mgrObjs | Sort-Object Name)) {
      $sub = Build-Tree $m.DistinguishedName
      if ($sub) {
        [void]$sbTop.AppendLine("<li><button class='toggle' aria-expanded='false'>+</button>$(NodeText $m)<div class='children collapsed'>$sub</div></li>")
      }
    }

    [void]$sbTop.AppendLine("</ul>")
    $treeHtml = $sbTop.ToString()
  }

  # ---- FULL HTML ----
  $html = @"
<!DOCTYPE html>
<html lang='fi'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Organisaatio</title>
$style
</head>
<body>

<h1>Organisaatio</h1>
$meta

<div class='toolbar'>
  <input type='text' id='filterInput' class='search' autocomplete='off'
    placeholder='Hae nimellä, nimikkeellä, osastolla, yrityksellä, sähköpostilla tai puhelimella…'>
  <div class='hint'>Vähintään 2 merkkiä. Tyhjennä näyttääksesi kaiken.</div>
</div>

<div class='card'>
  $treeHtml
  <div id='noResults' class='no-results'>Ei hakutuloksia.</div>
</div>

<script>
(function(){

const tree = document.getElementById("orgTree");
const input = document.getElementById("filterInput");
const noResults = document.getElementById("noResults");

if(!tree) return;

tree.addEventListener("click", function(e){
  const btn = e.target.closest(".toggle");
  if(!btn || btn.dataset.leaf === "1") return;

  const li = btn.closest("li");
  const box = li && li.querySelector(":scope > .children");
  if(!box) return;

  const collapsed = box.classList.toggle("collapsed");
  btn.textContent = collapsed ? "+" : "−";
  btn.setAttribute("aria-expanded", (!collapsed).toString());
});

let t = null;
input.addEventListener("input", () => {
  clearTimeout(t);
  t = setTimeout(filterTree, 150);
});

function filterTree(){
  const q = (input.value || "").toLowerCase().trim();
  const items = Array.from(tree.querySelectorAll("li"));

  if(q.length < 2){
    items.forEach(li => {
      li.classList.remove("hidden-by-filter");
      const box = li.querySelector(":scope > .children");
      const btn = li.querySelector(":scope > .toggle");
      if(box) box.classList.add("collapsed");
      if(btn && btn.dataset.leaf !== "1"){
        btn.textContent = "+";
        btn.setAttribute("aria-expanded","false");
      }
    });
    noResults.style.display = "none";
    return;
  }

  items.forEach(li => li.classList.add("hidden-by-filter"));
  let matches = 0;

  items.forEach(li => {
    const person = li.querySelector(":scope > .person");
    if(!person) return;

    const blob = person.getAttribute("data-search") || "";
    if(blob.indexOf(q) !== -1){
      matches++;
      li.classList.remove("hidden-by-filter");

      let p = li.parentElement;
      while(p){
        if(p.tagName && p.tagName.toLowerCase() === "ul"){
          const ownerLi = p.closest("li");
          if(ownerLi){
            ownerLi.classList.remove("hidden-by-filter");
            const ownerBox = ownerLi.querySelector(":scope > .children");
            const ownerBtn = ownerLi.querySelector(":scope > .toggle");
            if(ownerBox) ownerBox.classList.remove("collapsed");
            if(ownerBtn && ownerBtn.dataset.leaf !== "1"){
              ownerBtn.textContent = "−";
              ownerBtn.setAttribute("aria-expanded","true");
            }
          }
        }
        p = p.parentElement;
      }

      li.querySelectorAll(".children").forEach(box => box.classList.remove("collapsed"));
      li.querySelectorAll(".toggle").forEach(btn => {
        if(btn.dataset.leaf !== "1"){
          btn.textContent = "−";
          btn.setAttribute("aria-expanded","true");
        }
      });
    }
  });

  noResults.style.display = (matches === 0) ? "block" : "none";
}
})();
</script>

</body>
</html>
"@

  return $html
}

# === MAIN ===
Import-Module ActiveDirectory -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($DomainController)) {
  $DomainController = (Get-ADDomainController -Discover -ErrorAction Stop).HostName
}

if ([string]::IsNullOrWhiteSpace($SearchBase)) {
  $SearchBase = (Get-ADDomain -ErrorAction Stop).DistinguishedName
}

$html = New-ADManagersWithReportsHtml -Server $DomainController -SearchBase $SearchBase

$parent = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

$html | Out-File $OutputPath -Encoding UTF8

Write-Host "HTML-raportti luotu: $OutputPath"
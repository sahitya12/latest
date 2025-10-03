param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$ClientId,
  [Parameter(Mandatory=$true)][string]$ClientSecret,
  [Parameter(Mandatory=$true)][string]$ProdCsvPath,      # headers: resource_group_name,role_definition_name,ad_group_name
  [Parameter(Mandatory=$true)][string]$NonProdCsvPath,   # same headers
  [string]$adh_group = "",
  [string[]]$adh_groups = @(),
  [string]$OutputDir = "",
  [string]$BranchName = ""
)

$ErrorActionPreference = 'Stop'
Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop

function Ensure-Dir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ $p = Join-Path (Get-Location) 'rg-perms-out' }
  if(-not(Test-Path $p)){ New-Item -ItemType Directory -Path $p -Force | Out-Null }
  return $p
}
function Normalize([string]$s){ ($s -replace '[_\s]','').ToLowerInvariant() }
function Load-Expected($p){
  if(-not (Test-Path $p)){ throw "CSV not found: $p" }
  $raw = Import-Csv $p
  if(-not $raw){ throw "CSV empty: $p" }
  $map=@{}; foreach($h in $raw[0].psobject.Properties.Name){ $map[(Normalize $h)]=$h }
  foreach($need in 'resourcegroupname','roledefinitionname','adgroupname'){
    if(-not $map.ContainsKey($need)){ throw "CSV '$p' missing column like '$need'" }
  }
  $rows=@()
  foreach($r in $raw){
    $rows += [pscustomobject]@{
      RG   = "$($r.$($map['resourcegroupname']))".Trim()
      Role = "$($r.$($map['roledefinitionname']))".Trim()
      AAD  = "$($r.$($map['adgroupname']))".Trim()
    }
  }
  $rows
}
function Get-EnvFromSub([string]$n){ if($n -match '(?i)\b(prod|production|prd)\b'){ 'PRODUCTION' } else { 'NONPRODUCTION' } }
function Resolve-Group([string]$name){
  if([string]::IsNullOrWhiteSpace($name)){ return $null }
  $g = Get-AzADGroup -DisplayName $name -ErrorAction SilentlyContinue
  if(-not $g){ $g = Get-AzADGroup -SearchString $name -ErrorAction SilentlyContinue |? { $_.DisplayName -eq $name } | select -First 1 }
  return $g
}

# ---- Login
$sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$cred = [pscredential]::new($ClientId,$sec)
Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred | Out-Null

# ---- Normalize custodian inputs
$custodians = New-Object System.Collections.Generic.List[string]
if ($adh_groups) { foreach($c in $adh_groups){ $t="$c".Trim(); if($t){ [void]$custodians.Add($t) } } }
if (-not [string]::IsNullOrWhiteSpace($adh_group)) { [void]$custodians.Add($adh_group.Trim()) }
$custodians = ($custodians | Select-Object -Unique)
if ($custodians.Count -eq 0){ throw "Provide -adh_group or -adh_groups for ByCustodian scan." }

# ---- Output paths
$OutputDir = Ensure-Dir $OutputDir
$stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$outCsv  = Join-Path $OutputDir "rg_permissions_ByCustodian_$stamp.csv"
$outHtml = Join-Path $OutputDir "rg_permissions_ByCustodian_$stamp.html"
$outJson = Join-Path $OutputDir "rg_permissions_ByCustodian_$stamp.json"

$rowsProd    = Load-Expected $ProdCsvPath
$rowsNonProd = Load-Expected $NonProdCsvPath
$allOut = New-Object System.Collections.Generic.List[object]

# ---- Iterate each custodian
$allSubs = Get-AzSubscription | ? { $_.Name -match '(?i)ADH' }
foreach($cust in $custodians){
  $subs = $allSubs | ? { $_.Name -match [regex]::Escape($cust) }
  if(-not $subs){ Write-Warning "No subscriptions found for adh_group '$cust'"; continue }

  foreach($sub in $subs){
    Set-AzContext -Tenant $TenantId -SubscriptionId $sub.Id | Out-Null
    $env = Get-EnvFromSub $sub.Name
    $expected = if($env -eq 'PRODUCTION'){ $rowsProd } else { $rowsNonProd }

    $rgList = Get-AzResourceGroup -ErrorAction SilentlyContinue
    $rgMap = @{}; foreach($rg in $rgList){ $rgMap[$rg.ResourceGroupName.ToLowerInvariant()]=$rg }

    foreach($e in $expected){
      $rgName   = $e.RG   -replace '<Custodian>', $cust
      $roleName = $e.Role -replace '<Custodian>', $cust
      $aadName  = $e.AAD  -replace '<Custodian>', $cust

      $rgObj = $null
      $rgKey = ($rgName ? $rgName.ToLowerInvariant() : '')
      if($rgKey -and $rgMap.ContainsKey($rgKey)){ $rgObj = $rgMap[$rgKey] }

      if(-not $rgObj){
        $allOut.Add([pscustomobject]@{
          Custodian=$cust; SubscriptionName=$sub.Name; SubscriptionId=$sub.Id; Environment=$env
          InputResourceGroup=$e.RG; ScannedResourceGroup=$rgName
          RoleDefinition=$roleName; InputAdGroup=$e.AAD; ResolvedAdGroup=$aadName
          RGStatus='NOT_FOUND'; PermissionStatus='N/A_RG_NOT_FOUND'; Details='Resource group not found'
        })
        continue
      }

      $grp = Resolve-Group $aadName
      if(-not $grp){
        $allOut.Add([pscustomobject]@{
          Custodian=$cust; SubscriptionName=$sub.Name; SubscriptionId=$sub.Id; Environment=$env
          InputResourceGroup=$e.RG; ScannedResourceGroup=$rgName
          RoleDefinition=$roleName; InputAdGroup=$e.AAD; ResolvedAdGroup=$aadName
          RGStatus='EXISTS'; PermissionStatus='N/A_GROUP_NOT_FOUND'; Details='Entra ID group not found'
        })
        continue
      }

      $scope = "/subscriptions/$($sub.Id)/resourceGroups/$rgName"
      $ra = Get-AzRoleAssignment -Scope $scope -ObjectId $grp.Id -RoleDefinitionName $roleName -ErrorAction SilentlyContinue

      $allOut.Add([pscustomobject]@{
        Custodian=$cust; SubscriptionName=$sub.Name; SubscriptionId=$sub.Id; Environment=$env
        InputResourceGroup=$e.RG; ScannedResourceGroup=$rgName
        RoleDefinition=$roleName; InputAdGroup=$e.AAD; ResolvedAdGroup=$aadName; GroupObjectId=($grp.Id)
        RGStatus='EXISTS'; PermissionStatus=($(if($ra){'EXISTS'}else{'MISSING'})); Details=$(if($ra){''}else{'Role assignment not found'})
      })
    }
  }
}

$allOut | Export-Csv $outCsv -NoTypeInformation -Encoding UTF8
($allOut | ConvertTo-Html -Title "RG Permissions ByCustodian $stamp" -PreContent "<h2>RG Permissions ByCustodian ($BranchName)</h2>") | Set-Content -Path $outHtml -Encoding UTF8
$allOut | ConvertTo-Json -Depth 6 | Set-Content -Path $outJson -Encoding UTF8

Write-Host "CSV:  $outCsv"
Write-Host "HTML: $outHtml"
Write-Host "JSON: $outJson"

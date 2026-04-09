<#PSScriptInfo

.VERSION 1.2.0

.PRERELEASESTRING

.GUID 4129a3f4-6bb2-4dea-9d84-895d5dd2d3b7

.AUTHOR Joao Paulo Costa

.DESCRIPTION This script generates an Azure Health Check HTML report for: governance, compute, storage, network, Key Vault, Activity Log, SQL inventory, Azure Policy, Defender for Cloud plan coverage, stopped VMs, and resource tagging gaps.

.COMPANYNAME getpractical.co.uk

.COPYRIGHT

.TAGS
    getpractical
    Azure HealthCheck Governance Report HTML Cloud Security

.LICENSEURI
    https://github.com/jpsantoscosta/Azure-HealthCheck/blob/main/LICENSE
.PROJECTURI
    https://github.com/jpsantoscosta/Azure-HealthCheck
.ICONURI

.EXTERNALMODULEDEPENDENCIES

.RELEASENOTES
    v1.0.0 - Initial release
    v1.0.1 - Fix the broken lines (ASCII)
    v1.0.2 - Update HTML entity for no rows message
    v1.0.3 - Fix formatting and punctuation in health check report
    v1.0.4 - Fix formatting and punctuation in health check report
    v1.0.5 - Add checks: Activity Log diagnostic settings (any destination), SQL instances inventory (Azure SQL, Managed Instance, SQL on VM), and Azure Policy assignments inventory
    v1.0.6 - Security: HTML-encode table output to mitigate XSS; Reliability: make Policy assignment parsing forward-compatible + suppress Az.Policy breaking-change warning; Add compute check: VMs with high CPU (P95 over last 7 days)
    v1.0.7 - Fix: replace all non-ASCII characters (en/em dashes, ellipsis, <= symbol) with ASCII equivalents for PS Gallery compatibility
    v1.0.8 - Suppress Az module warnings: Get-AzSubscription tenant auth, Get-AzMetric DetailedOutput deprecation, Get-AzDiagnosticSetting breaking-change, Az.Network unapproved-verb noise
    v1.0.9 - Fix tenant auth warning properly: scope Get-AzSubscription to the authenticated tenant via -TenantId from Get-AzContext
    v1.1.0 - Add checks: Defender for Cloud plan coverage (Standard vs Free), stopped VMs (OS-stopped but not deallocated -- still incurring compute charges), and resource tagging gaps (RGs and VMs with no tags, or missing required tags via -RequiredTags param)
    v1.2.0 - Security: public-facing resources (App Services, Storage Accounts, and SQL servers/Managed Instances with public network access enabled) and privileged identity (permanent Owner/Contributor role assignments for users and groups that should be managed via PIM)
#>

<#
.SYNOPSIS
    Generates an Azure Health Check HTML report across all subscriptions in the current context.

.PARAMETER OpenAfterExport
    Automatically opens the generated HTML report in the default browser after export.

.PARAMETER CpuHighThresholdPercent
    P95 CPU utilisation threshold (%) above which a VM is flagged as high-CPU. Default: 80.

.PARAMETER CpuTopNPerSubscription
    Maximum number of high-CPU VMs reported per subscription. Default: 20.

.PARAMETER RequiredTags
    List of required tag names to check on resource groups and VMs (e.g. 'Environment','Owner').
    If empty, resources with no tags at all are reported.

.EXAMPLE
    Invoke-AzHealthCheck

.EXAMPLE
    Invoke-AzHealthCheck -OpenAfterExport

.EXAMPLE
    Invoke-AzHealthCheck -RequiredTags 'Environment','Owner' -CpuHighThresholdPercent 90

.LINK
    https://github.com/jpsantoscosta/Azure-HealthCheck
#>

[CmdletBinding()]
param(
    [switch]$OpenAfterExport,

    # v1.0.6 - CPU check guardrails
    [int]$CpuHighThresholdPercent = 80,
    [int]$CpuTopNPerSubscription  = 20,

    # v1.1.0 - Tagging gaps: optional list of required tag names to check (e.g. 'Environment','Owner')
    # If empty, reports resources with NO tags at all.
    [string[]]$RequiredTags = @()
)

#=============================
# Helper: logging
#=============================
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

#=============================
# Helper: safe HTML encoding (XSS mitigation)
#=============================
function ConvertTo-PlainString {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    try {
        if ($Value -is [datetime]) { return $Value.ToString("u") }
        return [string]$Value
    } catch {
        return ""
    }
}

function HtmlEncode {
    param([object]$Value)
    $s = ConvertTo-PlainString -Value $Value
    return [System.Net.WebUtility]::HtmlEncode($s)
}

function SafeHtmlId {
    param([string]$Id)
    if (-not $Id) { return "" }
    # Replace anything not safe for an id with "_"
    $safe = ($Id -replace '[^a-zA-Z0-9\-_]', '_')
    # Avoid empty / weird ids
    if (-not $safe) { $safe = "id_" + ([guid]::NewGuid().ToString("N")) }
    return $safe
}

#=============================
# Helper: small note block (metrics disclaimer)
#=============================
function New-NoteHtml {
    param([string]$Text)
    if (-not $Text) { return "" }
    return "<div class='empty' style='margin-top:4px;'>$(HtmlEncode $Text)</div>"
}

#=============================
# Helper: percentile for CPU metrics
#=============================
function Get-Percentile {
    param(
        [Parameter(Mandatory)]
        [double[]]$Values,
        [ValidateRange(0,100)]
        [double]$Percent
    )

    if (-not $Values -or $Values.Count -eq 0) { return $null }

    $sorted = $Values | Sort-Object
    $n = $sorted.Count
    if ($n -eq 1) { return [double]$sorted[0] }

    # Nearest-rank method
    $rank = [math]::Ceiling(($Percent / 100.0) * $n)
    if ($rank -lt 1) { $rank = 1 }
    if ($rank -gt $n) { $rank = $n }

    return [double]$sorted[$rank - 1]
}

#=============================
# Helper: HTML table builder
#  - Always shows section title
#  - Shows "No rows..." when empty
#  - Highlights risk rows
#  - Adds "Export CSV" button for non-empty tables
#  - v1.0.6: HTML-encodes values (XSS mitigation)
#=============================
function New-TableHtml {
    param(
        [Parameter()]
        [object]$Data,
        [string]$Id,
        [string]$Title
    )

    $rows = @()
    if ($Data) { $rows = @($Data) }

    $hasRows = $rows.Count -gt 0

    $safeId = SafeHtmlId -Id $Id

    $sb = New-Object -TypeName System.Text.StringBuilder
    [void]$sb.AppendLine("<div class='table-wrap'>")

    $titleEnc = HtmlEncode -Value $Title
    if ($Title) {
        if ($safeId -and $hasRows) {
            [void]$sb.AppendLine("<div class='table-header'><div class='table-title'>$titleEnc</div><button type='button' class='export-btn' data-table-id='$([System.Net.WebUtility]::HtmlEncode($safeId))'>Export CSV</button></div>")
        } else {
            [void]$sb.AppendLine("<div class='table-title'>$titleEnc</div>")
        }
    }

    if (-not $hasRows) {
        [void]$sb.AppendLine("<div class='empty'>&#10003; No rows to display for this section.</div>")
        [void]$sb.AppendLine("</div>")
        return $sb.ToString()
    }

    $first = $rows[0]
    $props = $first.PSObject.Properties.Name
    if (-not $props -or $props.Count -eq 0) {
        [void]$sb.AppendLine("<div class='empty'>&#10003; No rows to display for this section.</div>")
        [void]$sb.AppendLine("</div>")
        return $sb.ToString()
    }

    [void]$sb.AppendLine("<div class='table-scroll'><table id='$([System.Net.WebUtility]::HtmlEncode($safeId))'>")

    # Header
    [void]$sb.AppendLine("<thead><tr>")
    foreach ($p in $props) {
        [void]$sb.AppendLine("<th>$(HtmlEncode -Value $p)</th>")
    }
    [void]$sb.AppendLine("</tr></thead>")

    # Body
    [void]$sb.AppendLine("<tbody>")
    foreach ($row in $rows) {
        $trClass = ""

        if ($row.PSObject.Properties.Name -contains 'BackupProtected') {
            if (-not $row.BackupProtected) { $trClass = " class='row-risk'" }
        }
        elseif ($row.PSObject.Properties.Name -contains 'RiskCategory') {
            if ($row.RiskCategory -and $row.RiskCategory -ne 'None') { $trClass = " class='row-risk'" }
        }
        elseif ($row.PSObject.Properties.Name -contains 'IsRisk') {
            if ($row.IsRisk) { $trClass = " class='row-risk'" }
        }

        [void]$sb.AppendLine("<tr$trClass>")
        foreach ($p in $props) {
            $val = $row.$p
            if ($null -eq $val) { $val = "" }

            $enc = HtmlEncode -Value $val

            # Optional readability: preserve new lines safely
            $enc = $enc -replace "(\r\n|\n|\r)", "<br/>"

            [void]$sb.AppendLine("<td>$enc</td>")
        }
        [void]$sb.AppendLine("</tr>")
    }
    [void]$sb.AppendLine("</tbody></table></div></div>")

    $sb.ToString()
}

#=============================
# Connect to Azure (no custom grid)
#=============================
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Connect-AzAccount -ErrorAction Stop | Out-Null
    $ctx = Get-AzContext -ErrorAction Stop
}

# Az.Network wraps Microsoft.Azure.PowerShell.Cmdlets.Network, which contains cmdlets
# with non-standard verb names. Pre-loading it with -DisableNameChecking (the documented
# PowerShell mechanism for acknowledging known non-standard verbs) prevents the warning
# from appearing when the sub-module is auto-loaded the first time a network cmdlet runs.
$_netCmdletsModule = Get-Module -ListAvailable -Name 'Microsoft.Azure.PowerShell.Cmdlets.Network*' |
    Sort-Object Version -Descending | Select-Object -First 1
if ($_netCmdletsModule) {
    Import-Module $_netCmdletsModule.Name -DisableNameChecking -ErrorAction SilentlyContinue
}
Remove-Variable _netCmdletsModule -ErrorAction SilentlyContinue
Import-Module Az.Network -DisableNameChecking -ErrorAction SilentlyContinue

# Get all subs scoped to the authenticated tenant -- prevents token errors for other tenants
$tenantId = $ctx.Tenant.Id
$subscriptions = Get-AzSubscription -TenantId $tenantId -WarningAction SilentlyContinue |
    Where-Object { $_.State -in @('Enabled', 'Warned') } |
    Sort-Object Name

if (-not $subscriptions) {
    throw "No subscriptions found for the current login."
}

$runTimeUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
$userName   = $ctx.Account.Id

Write-Info ("Processing {0} subscription(s) under tenant {1}" -f $subscriptions.Count, $tenantId)

#=============================
# Data collections
#=============================
$govResults          = @()
$vmResults           = @()
$diskResults         = @()
$pipResults          = @()
$storageResults      = @()
$subStats            = @()

$vmDiskModernResults = @()
$kvResults           = @()
$kvExpiryResults     = @()
$nsgSubnetsMissing   = @()
$nsgNicsMissing      = @()
$nsgOpenMgmtRules    = @()

# v1.0.5
$activityLogDiagResults  = @()
$sqlInstanceResults      = @()
$policyAssignmentResults = @()

# v1.0.6
$vmCpuHighResults = @()  # VMs with high CPU (P95 over last 7 days)

# v1.1.0
$defenderResults   = @()  # Defender for Cloud plan coverage
$vmStoppedResults  = @()  # VMs in OS-stopped state (still incurring compute charges)
$taggingGapResults = @()  # RGs and VMs with missing/no tags

# v1.2.0
$publicAppServiceResults = @()  # App Services with public network access enabled
$publicSqlResults        = @()  # SQL logical servers and MIs with public network access enabled
$privIdentityResults     = @()  # Permanent Owner/Contributor assignments for users/groups (no PIM)

[int]$totalRgAll      = 0
[int]$totalVmAll      = 0
[int]$totalStorageAll = 0

#=============================
# Subscription score helper
#=============================
function Get-SubScore {
    param(
        [int]$RgBad,
        [int]$VmBad,
        [int]$StorageBad,
        [int]$UnattachedDisks,
        [int]$FreePips,
        [int]$VmHdd,
        [int]$VmUnmanaged,
        [int]$VmHighCpu,
        [int]$SubnetsNoNsg,
        [int]$NicsNoNsg,
        [int]$NsgOpenMgmtRules,
        [int]$KeyVaultsNoPurge,
        [int]$KvSecretsExpiring60,
        [int]$ActivityLogNoDiag,
        [int]$DefenderFreePlans,
        [int]$VmStopped,
        [int]$TaggingGaps,
        [int]$PublicFacingCount,
        [int]$PrivIdentityCount
    )

    $score = 100

    $score -= [math]::Min(40, $VmBad * 2)
    $score -= [math]::Min(20, $RgBad)
    $score -= [math]::Min(20, $StorageBad * 2)
    $score -= [math]::Min(10, ($UnattachedDisks + $FreePips))
    $score -= [math]::Min(10, ($VmHdd + $VmUnmanaged))
    $score -= [math]::Min(10, $VmHighCpu)
    $score -= [math]::Min(10, ($SubnetsNoNsg + $NicsNoNsg))
    $score -= [math]::Min(10, ($NsgOpenMgmtRules + $KeyVaultsNoPurge + [int]([math]::Ceiling($KvSecretsExpiring60 / 5.0))))

    # Missing Activity Log diagnostics (any destination) -> small penalty (0 or 10)
    $score -= [math]::Min(10, $ActivityLogNoDiag * 10)

    $score -= [math]::Min(15, $DefenderFreePlans * 2)
    $score -= [math]::Min(10, $VmStopped * 2)
    $score -= [math]::Min(5,  [int]([math]::Ceiling($TaggingGaps / 10.0)))

    # v1.2.0
    $score -= [math]::Min(15, $PublicFacingCount * 2)
    $score -= [math]::Min(20, $PrivIdentityCount * 5)

    if ($score -lt 0)   { $score = 0 }
    if ($score -gt 100) { $score = 100 }
    return [int]$score
}

#=============================
# Per-subscription processing
#=============================
foreach ($sub in $subscriptions) {

    $sid   = $sub.Id
    $sname = $sub.Name

    Write-Info ("[{0:D2}/{1}] Starting '{2}' ({3})" -f
        ($subscriptions.IndexOf($sub) + 1),
        $subscriptions.Count,
        $sname, $sid
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    Set-AzContext -SubscriptionId $sid -ErrorAction Stop | Out-Null

    # ---- local counters (avoid O(n^2)) ----
    [int]$sqlInstancesSub      = 0
    [int]$policyAssignSub      = 0
    [int]$activityLogNoDiagSub = 0
    [int]$vmHighCpuSub         = 0
    [int]$defenderFreeSub      = 0
    [int]$vmStoppedSub         = 0
    [int]$taggingGapsSub       = 0
    [int]$publicFacingSub      = 0
    [int]$privIdentitySub      = 0

    #-------------------------
    # Governance - RGs without locks
    #-------------------------
    $rgList     = Get-AzResourceGroup
    $rgTotalSub = $rgList.Count

    $allLocks = @()
    try { $allLocks = Get-AzResourceLock -AtSubscriptionLevel -ErrorAction SilentlyContinue } catch { }

    foreach ($rg in $rgList) {
        $locksForRg = $allLocks | Where-Object { $_.ResourceGroupName -eq $rg.ResourceGroupName }

        $lockLevels = $locksForRg |
            Where-Object { $_ -and ($_.PSObject.Properties.Name -contains 'Level') } |
            Select-Object -ExpandProperty Level -Unique -ErrorAction SilentlyContinue

        $lockCount = ($lockLevels | Measure-Object).Count
        if (-not $lockLevels) { $lockLevels = 'None' }

        if ($lockCount -eq 0) {
            $govResults += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceGroup    = $rg.ResourceGroupName
                Location         = $rg.Location
                LockLevels       = $lockLevels -join ', '
                LockCount        = $lockCount
            }
        }

        # v1.1.0 - Tagging gap check for this RG
        $missingRgTags = @()
        if ($RequiredTags.Count -gt 0) {
            foreach ($tagName in $RequiredTags) {
                if (-not $rg.Tags -or -not $rg.Tags.ContainsKey($tagName)) {
                    $missingRgTags += $tagName
                }
            }
        } else {
            if (-not $rg.Tags -or $rg.Tags.Count -eq 0) {
                $missingRgTags += '(no tags)'
            }
        }
        if ($missingRgTags.Count -gt 0) {
            $taggingGapsSub++
            $taggingGapResults += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceType     = 'ResourceGroup'
                ResourceGroup    = $rg.ResourceGroupName
                ResourceName     = $rg.ResourceGroupName
                Location         = $rg.Location
                MissingTags      = ($missingRgTags -join ', ')
            }
        }
    }

    #-------------------------
    # Compute - VMs (backup + legacy disks + v1.0.6 CPU p95)
    #-------------------------
    $vmList     = Get-AzVM -Status -ErrorAction SilentlyContinue
    $vmTotalSub = $vmList.Count

    $protectedVmNames = [System.Collections.Generic.HashSet[string]]::new()

    $vaults = Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue
    foreach ($vault in $vaults) {
        try {
            $items = Get-AzRecoveryServicesBackupItem `
                -VaultId $vault.ID `
                -BackupManagementType AzureVM `
                -WorkloadType AzureVM `
                -ErrorAction SilentlyContinue

            foreach ($item in $items) {
                $vmName = $null

                if ($item.PSObject.Properties.Name -contains 'Properties' -and
                    $item.Properties -and
                    $item.Properties.PSObject.Properties.Name -contains 'FriendlyName' -and
                    $item.Properties.FriendlyName) {

                    $vmName = $item.Properties.FriendlyName
                }
                elseif ($item.PSObject.Properties.Name -contains 'FriendlyName' -and $item.FriendlyName) {
                    $vmName = $item.FriendlyName
                }
                elseif ($item.Name -and ($item.Name -match ';([^;]+)$')) {
                    $vmName = $Matches[1]
                }

                if ($vmName) { [void]$protectedVmNames.Add($vmName.ToLowerInvariant()) }
            }
        } catch { }
    }

    # CPU window
    $cpuEnd   = Get-Date
    $cpuStart = $cpuEnd.AddDays(-7)

    Write-Info ("Fetching CPU metrics for {0} VM(s) (one API call per VM -- may take a moment)..." -f $vmList.Count)
    foreach ($vm in $vmList) {
        $vmName   = $vm.Name
        $rgName   = $vm.ResourceGroupName
        $location = $vm.Location

        # Backup protection
        $isProtected = $protectedVmNames.Contains($vmName.ToLowerInvariant())

        # v1.1.0 - Stopped VM check (OS-stopped but not deallocated -- still incurring compute charges)
        $powerState = ''
        if ($vm.PSObject.Properties.Name -contains 'PowerState') { $powerState = $vm.PowerState }
        if ($powerState -eq 'VM stopped') {
            $vmStoppedSub++
            $vmStoppedResults += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceGroup    = $rgName
                VMName           = $vmName
                Location         = $location
                PowerState       = $powerState
            }
        }

        # v1.1.0 - Tagging gap check for this VM
        $missingVmTags = @()
        if ($RequiredTags.Count -gt 0) {
            foreach ($tagName in $RequiredTags) {
                if (-not $vm.Tags -or -not $vm.Tags.ContainsKey($tagName)) {
                    $missingVmTags += $tagName
                }
            }
        } else {
            if (-not $vm.Tags -or $vm.Tags.Count -eq 0) {
                $missingVmTags += '(no tags)'
            }
        }
        if ($missingVmTags.Count -gt 0) {
            $taggingGapsSub++
            $taggingGapResults += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceType     = 'VirtualMachine'
                ResourceGroup    = $rgName
                ResourceName     = $vmName
                Location         = $location
                MissingTags      = ($missingVmTags -join ', ')
            }
        }

        if (-not $isProtected) {
            $vmResults += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceGroup    = $rgName
                VMName           = $vmName
                Location         = $location
                BackupProtected  = $false
            }
        }

        # Disk modernisation (HDD / unmanaged)
        $hasHdd       = $false
        $hasUnmanaged = $false
        $osDiskType   = ''
        $dataTypes    = @()

        $osDisk = $vm.StorageProfile.OSDisk
        if ($osDisk) {
            if ($osDisk.ManagedDisk) {
                $osDiskType = $osDisk.ManagedDisk.StorageAccountType
                if ($osDiskType -eq 'Standard_LRS') { $hasHdd = $true }
            }
            elseif ($osDisk.Vhd) {
                $hasUnmanaged = $true
                $osDiskType   = 'Unmanaged'
            }
        }

        foreach ($dd in $vm.StorageProfile.DataDisks) {
            if ($dd.ManagedDisk) {
                $dtype = $dd.ManagedDisk.StorageAccountType
                $dataTypes += $dtype
                if ($dtype -eq 'Standard_LRS') { $hasHdd = $true }
            }
            elseif ($dd.Vhd) {
                $hasUnmanaged = $true
                $dataTypes += 'Unmanaged'
            }
        }

        if ($hasHdd -or $hasUnmanaged) {
            $vmDiskModernResults += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceGroup    = $rgName
                VMName           = $vmName
                Location         = $location
                HasHddDisk       = $hasHdd
                HasUnmanagedDisk = $hasUnmanaged
                OsDiskType       = $osDiskType
                DataDiskTypes    = ($dataTypes -join ', ')
            }
        }

        # v1.0.6 - CPU high check (P95 over last 7 days)
        # Note: one metrics API call per VM -- can be slow in large estates.
        try {
            if ($vm.Id) {
                $metric = Get-AzMetric `
                    -ResourceId $vm.Id `
                    -MetricName "Percentage CPU" `
                    -StartTime $cpuStart `
                    -EndTime $cpuEnd `
                    -TimeGrain 01:00:00 `
                    -AggregationType Average `
                    -ErrorAction SilentlyContinue `
                    -WarningAction SilentlyContinue

                $avgVals = @()
                if ($metric -and $metric.Data) {
                    $avgVals = @($metric.Data | Where-Object { $null -ne $_.Average } | ForEach-Object { [double]$_.Average })
                }

                if ($avgVals.Count -gt 0) {
                    $p95 = Get-Percentile -Values $avgVals -Percent 95
                    $avg = [math]::Round((($avgVals | Measure-Object -Average).Average), 2)
                    $max = [math]::Round((($avgVals | Measure-Object -Maximum).Maximum), 2)

                    if ($null -ne $p95 -and $p95 -ge [double]$CpuHighThresholdPercent) {
                        $vmHighCpuSub++

                        $vmCpuHighResults += [pscustomobject]@{
                            SubscriptionId   = $sid
                            SubscriptionName = $sname
                            ResourceGroup    = $rgName
                            VMName           = $vmName
                            Location         = $location
                            CpuAvg7d         = $avg
                            CpuP95_7d        = [math]::Round($p95, 2)
                            CpuMaxSample7d   = $max
                            Threshold        = $CpuHighThresholdPercent
                            IsRisk           = $true
                        }
                    }
                }
            }
        } catch {
            Write-Info "WARNING: Could not read CPU metrics for '$vmName' ($rgName) -- $_"
        }
    }

    # If you want to strictly cap output to top-N per subscription, trim at the end:
    if ($CpuTopNPerSubscription -gt 0) {
        $subCpuRows = @($vmCpuHighResults | Where-Object { $_.SubscriptionId -eq $sid })
        if ($subCpuRows.Count -gt $CpuTopNPerSubscription) {
            # Keep highest P95 only
            $keep = $subCpuRows | Sort-Object CpuP95_7d -Descending | Select-Object -First $CpuTopNPerSubscription

            # Remove existing rows for this sub and re-add kept rows (preserve other subs)
            $vmCpuHighResults = @($vmCpuHighResults | Where-Object { $_.SubscriptionId -ne $sid }) + @($keep)

            $vmHighCpuSub = $keep.Count
        }
    }

    #-------------------------
    # Compute - Unattached disks
    #-------------------------
    $disks = Get-AzDisk -ErrorAction SilentlyContinue
    foreach ($disk in $disks) {
        if (-not $disk.ManagedBy) {
            $diskResults += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceGroup    = $disk.ResourceGroupName
                DiskName         = $disk.Name
                Location         = $disk.Location
                SkuName          = $disk.Sku.Name
                DiskSizeGB       = $disk.DiskSizeGB
            }
        }
    }

    #-------------------------
    # Compute - Unattached Public IPs
    #-------------------------
    $pips = Get-AzPublicIpAddress -ErrorAction SilentlyContinue
    foreach ($pip in $pips) {
        if (-not $pip.IpConfiguration) {
            $pipResults += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceGroup    = $pip.ResourceGroupName
                PublicIpName     = $pip.Name
                Location         = $pip.Location
                AllocationMethod = $pip.PublicIpAllocationMethod
                SkuName          = $pip.Sku.Name
                IpAddress        = $pip.IpAddress
            }
        }
    }

    #-------------------------
    # Storage accounts - TLS, public access, soft delete, replication
    #-------------------------
    $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
    $storageTotalSub = $storageAccounts.Count

    foreach ($st in $storageAccounts) {

        $rawTls = $st.MinimumTlsVersion
        $friendlyTls = switch ($rawTls) {
            'TLS1_0' { '1.0' }
            'TLS1_1' { '1.1' }
            'TLS1_2' { '1.2' }
            default  { '' }
        }

        $allowBlobPublic   = $false
        $publicNetwork     = ''
        $softDeleteState   = 'Unknown'
        $riskCategory      = 'None'

        try { $publicNetwork = $st.NetworkRuleSet.DefaultAction } catch { }
        try { $allowBlobPublic = $st.AllowBlobPublicAccess } catch { }

        try {
            $blobProps = Get-AzStorageBlobServiceProperty -ResourceGroupName $st.ResourceGroupName -AccountName $st.StorageAccountName -ErrorAction Stop
            if ($blobProps -and $blobProps.DeleteRetentionPolicy) {
                $softDeleteState = if ($blobProps.DeleteRetentionPolicy.Enabled) { 'Enabled' } else { 'Disabled' }
            }
        } catch { }

        try {
            $fileProps = Get-AzStorageFileServiceProperty -ResourceGroupName $st.ResourceGroupName -AccountName $st.StorageAccountName -ErrorAction Stop
            if ($fileProps -and $fileProps.ShareDeleteRetentionPolicy) {
                $softDeleteState = if ($fileProps.ShareDeleteRetentionPolicy.Enabled) { 'Enabled' } else { 'Disabled' }
            }
        } catch { }

        if ($rawTls -in @('TLS1_0','TLS1_1')) { $riskCategory = 'TLS < 1.2' }
        if ($allowBlobPublic -eq $true) {
            if ($riskCategory -eq 'None') { $riskCategory = 'Blob public access' }
            else { $riskCategory = $riskCategory + '; Blob public access' }
        }

        $replication = $st.Sku.Name

        $storageResults += [pscustomobject]@{
            SubscriptionId        = $sid
            SubscriptionName      = $sname
            ResourceGroup         = $st.ResourceGroupName
            StorageAccountName    = $st.StorageAccountName
            Location              = $st.Location
            Kind                  = $st.Kind
            Replication           = $replication
            MinimumTlsVersion     = $friendlyTls
            AllowBlobPublicAccess = $allowBlobPublic
            SoftDeleteEnabled     = $softDeleteState
            PublicNetworkAccess   = $publicNetwork
            RiskCategory          = $riskCategory
            RawTls                = $rawTls
        }
    }

    #-------------------------
    # Key Vault - config & expiring objects
    #-------------------------
    $kvList = Get-AzKeyVault -ErrorAction SilentlyContinue
    $now    = Get-Date
    $limit  = $now.AddDays(90)

    foreach ($kv in $kvList) {
        $softDelete = $false
        $purgeProt  = $false

        if ($kv.PSObject.Properties.Name -contains 'EnableSoftDelete') {
            $softDelete = [bool]$kv.EnableSoftDelete
        } elseif ($kv.PSObject.Properties.Name -contains 'SoftDeleteEnabled') {
            $softDelete = [bool]$kv.SoftDeleteEnabled
        }

        if ($kv.PSObject.Properties.Name -contains 'EnablePurgeProtection') {
            $purgeProt = [bool]$kv.EnablePurgeProtection
        } elseif ($kv.PSObject.Properties.Name -contains 'PurgeProtectionEnabled') {
            $purgeProt = [bool]$kv.PurgeProtectionEnabled
        }

        $kvResults += [pscustomobject]@{
            SubscriptionId   = $sid
            SubscriptionName = $sname
            ResourceGroup    = $kv.ResourceGroupName
            VaultName        = $kv.VaultName
            Location         = $kv.Location
            SoftDelete       = $softDelete
            PurgeProtection  = $purgeProt
        }

        try { $secrets = Get-AzKeyVaultSecret -VaultName $kv.VaultName -ErrorAction Stop } catch { $secrets = @() }
        foreach ($sec in $secrets) {
            $exp = $sec.Attributes.Expires
            if ($exp -and $exp -gt $now -and $exp -le $limit) {
                $days = [math]::Round(($exp - $now).TotalDays)
                $kvExpiryResults += [pscustomobject]@{
                    SubscriptionId   = $sid
                    SubscriptionName = $sname
                    ResourceGroup    = $kv.ResourceGroupName
                    VaultName        = $kv.VaultName
                    ObjectType       = 'Secret'
                    Name             = $sec.Name
                    ExpiresOn        = $exp.ToString('u')
                    DaysToExpiry     = $days
                }
            }
        }

        try { $certs = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -ErrorAction Stop } catch { $certs = @() }
        foreach ($cert in $certs) {
            $exp = $cert.Attributes.Expires
            if ($exp -and $exp -gt $now -and $exp -le $limit) {
                $days = [math]::Round(($exp - $now).TotalDays)
                $kvExpiryResults += [pscustomobject]@{
                    SubscriptionId   = $sid
                    SubscriptionName = $sname
                    ResourceGroup    = $kv.ResourceGroupName
                    VaultName        = $kv.VaultName
                    ObjectType       = 'Certificate'
                    Name             = $cert.Name
                    ExpiresOn        = $exp.ToString('u')
                    DaysToExpiry     = $days
                }
            }
        }

        try { $keys = Get-AzKeyVaultKey -VaultName $kv.VaultName -ErrorAction Stop } catch { $keys = @() }
        foreach ($key in $keys) {
            $exp = $key.Attributes.Expires
            if ($exp -and $exp -gt $now -and $exp -le $limit) {
                $days = [math]::Round(($exp - $now).TotalDays)
                $kvExpiryResults += [pscustomobject]@{
                    SubscriptionId   = $sid
                    SubscriptionName = $sname
                    ResourceGroup    = $kv.ResourceGroupName
                    VaultName        = $kv.VaultName
                    ObjectType       = 'Key'
                    Name             = $key.Name
                    ExpiresOn        = $exp.ToString('u')
                    DaysToExpiry     = $days
                }
            }
        }
    }

    #-------------------------
    # Network - NSG coverage & exposed ports
    #-------------------------
    $vNets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
    foreach ($vnet in $vNets) {
        foreach ($subnet in $vnet.Subnets) {
            if (-not $subnet.NetworkSecurityGroup) {
                $nsgSubnetsMissing += [pscustomobject]@{
                    SubscriptionId   = $sid
                    SubscriptionName = $sname
                    ResourceGroup    = $vnet.ResourceGroupName
                    VNetName         = $vnet.Name
                    SubnetName       = $subnet.Name
                }
            }
        }
    }

    $nics = Get-AzNetworkInterface -ErrorAction SilentlyContinue
    foreach ($nic in $nics) {
        if (-not $nic.NetworkSecurityGroup) {
            $nsgNicsMissing += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceGroup    = $nic.ResourceGroupName
                NicName          = $nic.Name
                Location         = $nic.Location
            }
        }
    }

    $nsgs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue
    foreach ($nsg in $nsgs) {
        foreach ($rule in $nsg.SecurityRules) {
            if ($rule.Direction -ne 'Inbound' -or $rule.Access -ne 'Allow') { continue }

            $srcPrefixes = @()
            if ($rule.SourceAddressPrefix)   { $srcPrefixes += $rule.SourceAddressPrefix }
            if ($rule.SourceAddressPrefixes) { $srcPrefixes += $rule.SourceAddressPrefixes }

            $isInternet = $false
            foreach ($sp in $srcPrefixes) {
                if ($sp -in @('*','0.0.0.0/0','Internet')) { $isInternet = $true; break }
            }
            if (-not $isInternet) { continue }

            $destPorts = @()
            if ($rule.DestinationPortRange)  { $destPorts += $rule.DestinationPortRange }
            if ($rule.DestinationPortRanges) { $destPorts += $rule.DestinationPortRanges }

            $exposesMgmt = $false
            foreach ($p in $destPorts) {
                if ($p -eq '*') { $exposesMgmt = $true; break }
                if ($p -match '^\d+$') {
                    if ($p -in @('22','3389')) { $exposesMgmt = $true; break }
                }
                elseif ($p -match '^(\d+)-(\d+)$') {
                    $from = [int]$Matches[1]
                    $to   = [int]$Matches[2]
                    if ((22 -ge $from -and 22 -le $to) -or (3389 -ge $from -and 3389 -le $to)) {
                        $exposesMgmt = $true; break
                    }
                }
            }

            if ($exposesMgmt) {
                $nsgOpenMgmtRules += [pscustomobject]@{
                    SubscriptionId   = $sid
                    SubscriptionName = $sname
                    ResourceGroup    = $nsg.ResourceGroupName
                    NsgName          = $nsg.Name
                    RuleName         = $rule.Name
                    Source           = ($srcPrefixes -join ',')
                    DestinationPorts = ($destPorts -join ',')
                    Priority         = $rule.Priority
                }
            }
        }
    }

    #-------------------------
    # v1.0.5 - Activity Log diagnostic settings (any destination)
    #-------------------------
    $subResourceId   = "/subscriptions/$sid"
    $diagConfigured  = $false
    $diagDestinations = @()

    try {
        $diagSettings = Get-AzDiagnosticSetting -ResourceId $subResourceId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($diagSettings) {
            $diagConfigured = $true
            foreach ($d in @($diagSettings)) {
                if ($d.WorkspaceId)                 { $diagDestinations += "Log Analytics" }
                if ($d.StorageAccountId)            { $diagDestinations += "Storage" }
                if ($d.EventHubAuthorizationRuleId) { $diagDestinations += "Event Hub" }
                if ($d.MarketplacePartnerId)        { $diagDestinations += "Partner" }
            }
        }
    } catch { }

    $diagDestinations = ($diagDestinations | Select-Object -Unique)

    if (-not $diagConfigured) { $activityLogNoDiagSub = 1 } else { $activityLogNoDiagSub = 0 }

    $activityLogDiagResults += [pscustomobject]@{
        SubscriptionId         = $sid
        SubscriptionName       = $sname
        DiagnosticConfigured   = $diagConfigured
        Destinations           = ($diagDestinations -join ', ')
        IsRisk                 = (-not $diagConfigured)
    }

    #-------------------------
    # v1.0.5 - SQL instances inventory (Azure SQL / MI / SQL on VM)
    #-------------------------
    $sqlTypes = @(
        "Microsoft.Sql/servers",
        "Microsoft.Sql/managedInstances",
        "Microsoft.SqlVirtualMachine/sqlVirtualMachines"
    )

    foreach ($t in $sqlTypes) {
        $sqlRes = @()
        try { $sqlRes = Get-AzResource -ResourceType $t -ErrorAction SilentlyContinue } catch { $sqlRes = @() }

        foreach ($r in @($sqlRes)) {
            $sqlInstancesSub++
            $sqlInstanceResults += [pscustomobject]@{
                SubscriptionId   = $sid
                SubscriptionName = $sname
                ResourceGroup    = $r.ResourceGroupName
                ResourceType     = $t
                Name             = $r.Name
                Location         = $r.Location
            }
        }
    }

    #-------------------------
    # v1.0.5 / v1.0.6 - Azure Policy assignments inventory (subscription scope)
    #  - v1.0.6: forward-compatible parsing + suppress breaking-change warning noise
    #-------------------------
    $policyAssignments = @()
    try {
        $policyAssignments = Get-AzPolicyAssignment -Scope $subResourceId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    } catch { $policyAssignments = @() }

    foreach ($pa in @($policyAssignments)) {
        $policyAssignSub++

        # Forward-compatible: prefer top-level props if present, else fallback to .Properties
        $displayName = $null
        $scope       = $null
        $defId       = $null

        if ($pa.PSObject.Properties.Name -contains 'DisplayName' -and $pa.DisplayName) {
            $displayName = $pa.DisplayName
        } elseif ($pa.PSObject.Properties.Name -contains 'Properties' -and $pa.Properties -and
                  $pa.Properties.PSObject.Properties.Name -contains 'DisplayName') {
            $displayName = $pa.Properties.DisplayName
        }

        if ($pa.PSObject.Properties.Name -contains 'Scope' -and $pa.Scope) {
            $scope = $pa.Scope
        } elseif ($pa.PSObject.Properties.Name -contains 'Properties' -and $pa.Properties -and
                  $pa.Properties.PSObject.Properties.Name -contains 'Scope') {
            $scope = $pa.Properties.Scope
        }

        if ($pa.PSObject.Properties.Name -contains 'PolicyDefinitionId' -and $pa.PolicyDefinitionId) {
            $defId = $pa.PolicyDefinitionId
        } elseif ($pa.PSObject.Properties.Name -contains 'Properties' -and $pa.Properties -and
                  $pa.Properties.PSObject.Properties.Name -contains 'PolicyDefinitionId') {
            $defId = $pa.Properties.PolicyDefinitionId
        }

        $policyAssignmentResults += [pscustomobject]@{
            SubscriptionId      = $sid
            SubscriptionName    = $sname
            Name                = $pa.Name
            DisplayName         = $displayName
            Scope               = $scope
            PolicyDefinitionId  = $defId
        }
    }

    #-------------------------
    # v1.1.0 - Defender for Cloud plan coverage
    #-------------------------
    $defenderPlans = @()
    try {
        $defenderPlans = Get-AzSecurityPricing -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    } catch { $defenderPlans = @() }

    foreach ($plan in @($defenderPlans)) {
        $tier = $null
        if ($plan.PSObject.Properties.Name -contains 'PricingTier') { $tier = $plan.PricingTier }
        elseif ($plan.PSObject.Properties.Name -contains 'Properties' -and $plan.Properties) { $tier = $plan.Properties.PricingTier }

        $isRisk = ($tier -eq 'Free')
        if ($isRisk) { $defenderFreeSub++ }

        $defenderResults += [pscustomobject]@{
            SubscriptionId   = $sid
            SubscriptionName = $sname
            PlanName         = $plan.Name
            Tier             = $tier
            IsRisk           = $isRisk
        }
    }

    #-------------------------
    # v1.2.0 - Public-facing App Services
    #-------------------------
    $webApps = @()
    try { $webApps = Get-AzWebApp -ErrorAction SilentlyContinue } catch { $webApps = @() }

    foreach ($app in @($webApps)) {
        $pna = $null
        try { $pna = $app.PublicNetworkAccess } catch { }

        # Flag if NOT explicitly disabled (default = publicly accessible)
        if ($pna -ne 'Disabled') {
            $publicFacingSub++
            $publicAppServiceResults += [pscustomobject]@{
                SubscriptionId       = $sid
                SubscriptionName     = $sname
                ResourceGroup        = $app.ResourceGroup
                AppServiceName       = $app.Name
                Location             = $app.Location
                Kind                 = $app.Kind
                PublicNetworkAccess  = if ($pna) { $pna } else { 'Enabled (default)' }
                IsRisk               = $true
            }
        }
    }

    #-------------------------
    # v1.2.0 - Public-facing SQL (logical servers + Managed Instances)
    #-------------------------
    $sqlPublicTypes = @(
        @{ Type = 'Microsoft.Sql/servers';           PropName = 'publicNetworkAccess';      IsEnabled = { param($v) $v -ne 'Disabled' } }
        @{ Type = 'Microsoft.Sql/managedInstances';  PropName = 'publicDataEndpointEnabled'; IsEnabled = { param($v) $v -eq $true -or $v -eq 'true' } }
    )

    foreach ($entry in $sqlPublicTypes) {
        $sqlRes = @()
        try { $sqlRes = Get-AzResource -ResourceType $entry.Type -ExpandProperties -ErrorAction SilentlyContinue } catch { $sqlRes = @() }

        foreach ($r in @($sqlRes)) {
            $propVal = $null
            try {
                if ($r.Properties -and $r.Properties.PSObject.Properties.Name -contains $entry.PropName) {
                    $propVal = $r.Properties.($entry.PropName)
                }
            } catch { }

            if (& $entry.IsEnabled $propVal) {
                $publicFacingSub++
                $publicSqlResults += [pscustomobject]@{
                    SubscriptionId      = $sid
                    SubscriptionName    = $sname
                    ResourceGroup       = $r.ResourceGroupName
                    ResourceType        = $entry.Type
                    Name                = $r.Name
                    Location            = $r.Location
                    PublicNetworkAccess = if ($null -ne $propVal) { [string]$propVal } else { 'Enabled (default)' }
                    IsRisk              = $true
                }
            }
        }
    }

    #-------------------------
    # v1.2.0 - Privileged Identity: permanent Owner/Contributor for users/groups (should use PIM)
    #-------------------------
    $roleAssignments = @()
    try {
        $roleAssignments = Get-AzRoleAssignment -Scope $subResourceId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    } catch { $roleAssignments = @() }

    foreach ($ra in @($roleAssignments)) {
        $roleDefName = $null
        $objectType  = $null
        $principalId = $null
        $principalName = $null
        $scopeVal    = $null

        try { $roleDefName  = $ra.RoleDefinitionName } catch { }
        try { $objectType   = $ra.ObjectType }         catch { }
        try { $principalId  = $ra.ObjectId }           catch { }
        try { $principalName = $ra.DisplayName }       catch { }
        try { $scopeVal     = $ra.Scope }              catch { }

        if ($roleDefName -notin @('Owner', 'Contributor')) { continue }
        if ($objectType -notin @('User', 'Group'))          { continue }

        $privIdentitySub++
        $privIdentityResults += [pscustomobject]@{
            SubscriptionId   = $sid
            SubscriptionName = $sname
            PrincipalName    = $principalName
            PrincipalType    = $objectType
            PrincipalId      = $principalId
            Role             = $roleDefName
            Scope            = $scopeVal
            IsRisk           = $true
        }
    }

    #-------------------------
    # Aggregate per-subscription stats
    #-------------------------
    $rgWithoutLocks   = ($govResults     | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $vmWithoutBackup  = ($vmResults      | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $unattachedDisks  = ($diskResults    | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $freePips         = ($pipResults     | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $storageRisksSub  = ($storageResults | Where-Object { $_.SubscriptionId -eq $sid -and $_.RiskCategory -ne 'None' } | Measure-Object).Count

    $vmHddSub         = ($vmDiskModernResults | Where-Object { $_.SubscriptionId -eq $sid -and $_.HasHddDisk }        | Measure-Object).Count
    $vmUnmanagedSub   = ($vmDiskModernResults | Where-Object { $_.SubscriptionId -eq $sid -and $_.HasUnmanagedDisk } | Measure-Object).Count

    $subnetsNoNsgSub  = ($nsgSubnetsMissing | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $nicsNoNsgSub     = ($nsgNicsMissing    | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $openMgmtRulesSub = ($nsgOpenMgmtRules  | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count

    $kvWithoutPurgeSub = ($kvResults       | Where-Object { $_.SubscriptionId -eq $sid -and -not $_.PurgeProtection } | Measure-Object).Count
    $kvExpiring60Sub   = ($kvExpiryResults | Where-Object { $_.SubscriptionId -eq $sid -and $_.DaysToExpiry -le 60 -and $_.DaysToExpiry -ge 0 } | Measure-Object).Count

    $hasIssue = (
        $rgWithoutLocks + $vmWithoutBackup + $unattachedDisks + $freePips + $storageRisksSub +
        $vmHddSub + $vmUnmanagedSub +
        $subnetsNoNsgSub + $nicsNoNsgSub + $openMgmtRulesSub +
        $kvWithoutPurgeSub + $kvExpiring60Sub +
        $activityLogNoDiagSub +
        $vmHighCpuSub +
        $defenderFreeSub + $vmStoppedSub + $taggingGapsSub +
        $publicFacingSub + $privIdentitySub
    ) -gt 0

    $score = Get-SubScore `
        -RgBad $rgWithoutLocks -VmBad $vmWithoutBackup -StorageBad $storageRisksSub `
        -UnattachedDisks $unattachedDisks -FreePips $freePips `
        -VmHdd $vmHddSub -VmUnmanaged $vmUnmanagedSub -VmHighCpu $vmHighCpuSub `
        -SubnetsNoNsg $subnetsNoNsgSub -NicsNoNsg $nicsNoNsgSub -NsgOpenMgmtRules $openMgmtRulesSub `
        -KeyVaultsNoPurge $kvWithoutPurgeSub -KvSecretsExpiring60 $kvExpiring60Sub `
        -ActivityLogNoDiag $activityLogNoDiagSub `
        -DefenderFreePlans $defenderFreeSub -VmStopped $vmStoppedSub -TaggingGaps $taggingGapsSub `
        -PublicFacingCount $publicFacingSub -PrivIdentityCount $privIdentitySub

    $subStats += [pscustomobject]@{
        Id                   = $sid
        Name                 = $sname
        HasIssue             = $hasIssue
        Score                = $score
        RgBad                = $rgWithoutLocks
        RgTotal              = $rgTotalSub
        VmBad                = $vmWithoutBackup
        VmTotal              = $vmTotalSub
        StorageBad           = $storageRisksSub
        StorageTotal         = $storageTotalSub
        UnattachedDisks      = $unattachedDisks
        FreePips             = $freePips
        VmHdd                = $vmHddSub
        VmUnmanaged          = $vmUnmanagedSub
        VmHighCpu            = $vmHighCpuSub
        SubnetsNoNsg         = $subnetsNoNsgSub
        NicsNoNsg            = $nicsNoNsgSub
        NsgOpenMgmtRules     = $openMgmtRulesSub
        KeyVaultsNoPurge     = $kvWithoutPurgeSub
        KvSecretsExpiring60  = $kvExpiring60Sub
        ActivityLogNoDiag    = $activityLogNoDiagSub
        SqlInstances         = $sqlInstancesSub
        PolicyAssignments    = $policyAssignSub
        DefenderFree         = $defenderFreeSub
        VmStopped            = $vmStoppedSub
        TaggingGaps          = $taggingGapsSub
        PublicFacing         = $publicFacingSub
        PrivIdentity         = $privIdentitySub
    }

    $totalRgAll      += $rgTotalSub
    $totalVmAll      += $vmTotalSub
    $totalStorageAll += $storageTotalSub

    $sw.Stop()
    Write-Info ("[{0:D2}/{1}] Finished '{2}' ({3}) in {4}" -f
        ($subscriptions.IndexOf($sub) + 1),
        $subscriptions.Count,
        $sname, $sid,
        $sw.Elapsed.ToString()
    )
}

#=============================
# Global summary numbers
#=============================
$totalSubs            = $subscriptions.Count
$totalRgNoLocks       = ($govResults | Measure-Object).Count
$totalVmNoBackup      = ($vmResults | Measure-Object).Count
$totalStorageRisks    = ($storageResults | Where-Object { $_.RiskCategory -ne 'None' } | Measure-Object).Count

$subsWithIssues = ($subStats | Where-Object HasIssue).Count
$subBadGlobal   = $subsWithIssues
$subGoodGlobal  = $totalSubs - $subsWithIssues

$rgBadGlobal      = ($subStats | Measure-Object -Property RgBad      -Sum).Sum
$vmBadGlobal      = ($subStats | Measure-Object -Property VmBad      -Sum).Sum
$storageBadGlobal = ($subStats | Measure-Object -Property StorageBad -Sum).Sum

if (-not $rgBadGlobal)      { $rgBadGlobal = 0 }
if (-not $vmBadGlobal)      { $vmBadGlobal = 0 }
if (-not $storageBadGlobal) { $storageBadGlobal = 0 }

function Get-PercentPair {
    param([int]$Bad, [int]$Total)
    if ($Total -le 0) { return ,(0, 0) }
    $badP  = [math]::Round(($Bad * 100.0) / $Total)
    $goodP = 100 - $badP
    return ,($badP, $goodP)
}

$subsPerc    = Get-PercentPair -Bad $subBadGlobal     -Total $totalSubs
$rgPerc      = Get-PercentPair -Bad $rgBadGlobal      -Total $totalRgAll
$vmPerc      = Get-PercentPair -Bad $vmBadGlobal      -Total $totalVmAll
$storagePerc = Get-PercentPair -Bad $storageBadGlobal -Total $totalStorageAll

$subsBadPercent,    $subsGoodPercent    = $subsPerc
$rgBadPercent,      $rgGoodPercent      = $rgPerc
$vmBadPercent,      $vmGoodPercent      = $vmPerc
$storageBadPercent, $storageGoodPercent = $storagePerc

$totalVmLegacyDisks = ($vmDiskModernResults | Measure-Object).Count
$totalVmHighCpu     = ($vmCpuHighResults   | Measure-Object).Count
$totalSubnetsNoNsg  = ($nsgSubnetsMissing  | Measure-Object).Count
$totalNicsNoNsg     = ($nsgNicsMissing     | Measure-Object).Count
$totalNsgOpenRules  = ($nsgOpenMgmtRules   | Measure-Object).Count
$totalKvNoPurge     = ($kvResults          | Where-Object { -not $_.PurgeProtection } | Measure-Object).Count
$totalKvExpiring60  = ($kvExpiryResults    | Where-Object { $_.DaysToExpiry -le 60 -and $_.DaysToExpiry -ge 0 } | Measure-Object).Count

$totalActivityLogNoDiag = ($activityLogDiagResults | Where-Object { -not $_.DiagnosticConfigured } | Measure-Object).Count
$totalSqlInstances      = ($sqlInstanceResults     | Measure-Object).Count
$totalPolicyAssignments = ($policyAssignmentResults| Measure-Object).Count

$totalDefenderFree  = ($defenderResults   | Where-Object { $_.IsRisk } | Measure-Object).Count
$totalVmStopped     = ($vmStoppedResults  | Measure-Object).Count
$totalTaggingGaps   = ($taggingGapResults | Measure-Object).Count

# v1.2.0
$totalPublicAppServices = ($publicAppServiceResults | Measure-Object).Count
$totalPublicSql         = ($publicSqlResults        | Measure-Object).Count
$totalPublicFacing      = $totalPublicAppServices + $totalPublicSql +
                          ($storageResults | Where-Object { $_.PublicNetworkAccess -eq 'Allow' } | Measure-Object).Count
$totalPrivIdentity      = ($privIdentityResults | Measure-Object).Count

$securityMetrics = @(
    [pscustomobject]@{ Name = 'Unattached Public IPs';                        Value = ($pipResults | Measure-Object).Count }
    [pscustomobject]@{ Name = 'Unattached disks';                             Value = ($diskResults | Measure-Object).Count }
    [pscustomobject]@{ Name = 'VMs without backup';                           Value = $totalVmNoBackup }
    [pscustomobject]@{ Name = 'VMs with legacy disks (HDD/unmanaged)';        Value = $totalVmLegacyDisks }
    [pscustomobject]@{ Name = "VMs with high CPU (P95 >= $CpuHighThresholdPercent% over 7d)"; Value = $totalVmHighCpu }
    [pscustomobject]@{ Name = 'RGs without locks';                            Value = $totalRgNoLocks }
    [pscustomobject]@{ Name = 'TLS < 1.2';                                    Value = ($storageResults | Where-Object { $_.RiskCategory -like '*TLS < 1.2*' } | Measure-Object).Count }
    [pscustomobject]@{ Name = 'Storage Account Public Access Enabled';        Value = ($storageResults | Where-Object { $_.RiskCategory -like '*Blob public access*' } | Measure-Object).Count }
    [pscustomobject]@{ Name = 'Subnets without NSG';                          Value = $totalSubnetsNoNsg }
    [pscustomobject]@{ Name = 'NICs without NSG';                             Value = $totalNicsNoNsg }
    [pscustomobject]@{ Name = 'NSG rules exposing RDP/SSH';                   Value = $totalNsgOpenRules }
    [pscustomobject]@{ Name = 'Key Vaults without purge protection';          Value = $totalKvNoPurge }
    [pscustomobject]@{ Name = 'KV objects expiring <=60 days';                 Value = $totalKvExpiring60 }
    [pscustomobject]@{ Name = 'Activity Log diagnostics not configured';      Value = $totalActivityLogNoDiag }
    [pscustomobject]@{ Name = 'SQL instances (inventory)';                    Value = $totalSqlInstances }
    [pscustomobject]@{ Name = 'Azure Policy assignments (inventory)';         Value = $totalPolicyAssignments }
    [pscustomobject]@{ Name = 'Defender for Cloud plans on Free tier';        Value = $totalDefenderFree }
    [pscustomobject]@{ Name = 'VMs in stopped state (still incurring charges)'; Value = $totalVmStopped }
    [pscustomobject]@{ Name = 'Resources with tagging gaps (RGs + VMs)';      Value = $totalTaggingGaps }
    [pscustomobject]@{ Name = 'Public-facing resources (App Services + SQL with public network access)'; Value = $totalPublicFacing }
    [pscustomobject]@{ Name = 'Permanent Owner/Contributor assignments (users/groups without PIM)'; Value = $totalPrivIdentity }
)

$maxMetric = ($securityMetrics.Value | Measure-Object -Maximum).Maximum
if (-not $maxMetric -or $maxMetric -eq 0) { $maxMetric = 1 }

$topSubs = $subStats | ForEach-Object {
    $issues = $_.RgBad + $_.VmBad + $_.StorageBad + $_.UnattachedDisks + $_.FreePips +
              $_.VmHdd + $_.VmUnmanaged + $_.VmHighCpu +
              $_.SubnetsNoNsg + $_.NicsNoNsg + $_.NsgOpenMgmtRules +
              $_.KeyVaultsNoPurge + $_.KvSecretsExpiring60 +
              $_.ActivityLogNoDiag +
              $_.DefenderFree + $_.VmStopped + $_.TaggingGaps +
              $_.PublicFacing + $_.PrivIdentity

    [pscustomobject]@{
        Name   = $_.Name
        Id     = $_.Id
        Score  = $_.Score
        Issues = $issues
    }
} | Sort-Object Issues -Descending | Select-Object -First 5

#=============================
# Data for charts (donut, heat map, top-5 bars)
#=============================
$categoryBreakdown = @(
    [pscustomobject]@{ Category = 'Governance';  Count = $totalRgNoLocks }
    [pscustomobject]@{ Category = 'Backup';      Count = $totalVmNoBackup }
    [pscustomobject]@{ Category = 'Compute';     Count = $totalVmLegacyDisks + $totalVmHighCpu }
    [pscustomobject]@{ Category = 'Storage';     Count = $totalStorageRisks }
    [pscustomobject]@{ Category = 'Network';     Count = $totalSubnetsNoNsg + $totalNicsNoNsg + $totalNsgOpenRules }
    [pscustomobject]@{ Category = 'KeyVault';    Count = $totalKvNoPurge + $totalKvExpiring60 }
    [pscustomobject]@{ Category = 'ActivityLog'; Count = $totalActivityLogNoDiag }
    [pscustomobject]@{ Category = 'Defender';    Count = ($defenderResults | Where-Object { $_.IsRisk } | Measure-Object).Count }
    [pscustomobject]@{ Category = 'StoppedVMs';  Count = $totalVmStopped }
    [pscustomobject]@{ Category = 'Tagging';     Count = $totalTaggingGaps }
    [pscustomobject]@{ Category = 'PublicAccess'; Count = $totalPublicFacing }
    [pscustomobject]@{ Category = 'PrivIdentity'; Count = $totalPrivIdentity }
) | Where-Object { $_.Count -gt 0 }

$categoryJson = ($categoryBreakdown | ConvertTo-Json -Compress) -replace '</script>', '<\/script>'

$heatMapRows = foreach ($s in $subStats) {
    [pscustomobject]@{
        Subscription = $s.Name
        Governance   = [int]$s.RgBad
        Backup       = [int]$s.VmBad
        Compute      = [int]($s.VmHdd + $s.VmUnmanaged + $s.VmHighCpu)
        Storage      = [int]$s.StorageBad
        Network      = [int]($s.SubnetsNoNsg + $s.NicsNoNsg + $s.NsgOpenMgmtRules)
        KeyVault     = [int]($s.KeyVaultsNoPurge + $s.KvSecretsExpiring60)
        ActivityLog  = [int]$s.ActivityLogNoDiag
        SQL          = [int]$s.SqlInstances
        Policy       = [int]$s.PolicyAssignments
        Defender     = [int]$s.DefenderFree
        StoppedVMs   = [int]$s.VmStopped
        Tagging      = [int]$s.TaggingGaps
        PublicAccess = [int]$s.PublicFacing
        PrivIdentity = [int]$s.PrivIdentity
    }
}

$heatMapJson = ($heatMapRows | ConvertTo-Json -Compress) -replace '</script>', '<\/script>'
$topSubsJson = ($topSubs | Select-Object Name, Issues | ConvertTo-Json -Compress) -replace '</script>', '<\/script>'

#=============================
# Build HTML
#=============================
$css = @"
<style>
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #f3f4f6;
    margin: 0;
    padding: 0;
    color: #1f2933;
}
.header {
    background: #2563EB;
    color: white;
    padding: 24px 32px 20px 32px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.15);
}
.header-title {
    font-size: 28px;
    font-weight: 600;
    margin-bottom: 4px;
}
.header-sub {
    font-size: 14px;
    opacity: 0.9;
}
.header-sub a {
    color: #bfdbfe;
    text-decoration: underline;
}
.header-meta {
    margin-top: 8px;
    font-size: 12px;
    opacity: 0.9;
}
.header-links {
    margin-top: 6px;
    font-size: 12px;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
}
.header-links a {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: #dbeafe;
    text-decoration: none;
}
.header-links a:hover {
    text-decoration: underline;
}
.header-links .icon {
    width: 14px;
    height: 14px;
    fill: #dbeafe;
}
.main {
    padding: 24px 32px 40px 32px;
    max-width: 1400px;
    margin: 0 auto;
}
.summary-cards {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 16px;
    margin-top: 16px;
}
.card {
    background: white;
    border-radius: 16px;
    padding: 16px 20px;
    box-shadow: 0 1px 4px rgba(15,23,42,0.12);
}
.card-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: #6b7280;
}
.card-value {
    font-size: 26px;
    font-weight: 600;
    margin-top: 4px;
}
.card-sub {
    font-size: 11px;
    margin-top: 4px;
    color: #6b7280;
}
.bad {
    color: #b91c1c;
    font-weight: 500;
}
.good {
    color: #15803d;
    font-weight: 500;
}
.subscription-filters {
    margin-top: 20px;
    margin-bottom: 8px;
    font-size: 12px;
}
.subscription-filters-controls {
    margin-bottom: 6px;
}
.subscription-filters-controls button {
    margin-right: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    border: 1px solid #d1d5db;
    background: #ffffff;
    cursor: pointer;
    font-size: 11px;
}
.subscription-filters-controls button:hover {
    background: #eff6ff;
}
.subscription-list {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 10px;
    margin-top: 4px;
}
.subscription-list label {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 2px 6px;
    border-radius: 999px;
    background: #e5edff;
    color: #1d4ed8;
}
.subscription-list input[type=checkbox] {
    accent-color: #2563eb;
}
.sub-header {
    margin-top: 30px;
    margin-bottom: 6px;
    font-size: 14px;
}
.sub-header strong {
    font-weight: 600;
}
.sub-meta {
    font-size: 11px;
    color: #6b7280;
}
.sub-metrics {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 12px;
    margin-top: 10px;
    margin-bottom: 10px;
}
.sub-card {
    background: white;
    border-radius: 16px;
    padding: 10px 14px;
    box-shadow: 0 1px 4px rgba(15,23,42,0.08);
}
.sub-card-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: #6b7280;
}
.sub-card-value {
    font-size: 20px;
    font-weight: 600;
    margin-top: 2px;
}
.section {
    margin-top: 10px;
    margin-bottom: 26px;
    padding: 16px 18px;
    background: #f9fafb;
    border-radius: 18px;
    box-shadow: 0 1px 3px rgba(15,23,42,0.06);
}
.table-wrap {
    margin-top: 12px;
}
.table-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 4px;
}
.table-title {
    font-size: 13px;
    font-weight: 600;
}
.export-btn {
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 999px;
    border: 1px solid #d1d5db;
    background: #ffffff;
    cursor: pointer;
}
.export-btn:hover {
    background: #eff6ff;
}
.table-scroll {
    max-height: 260px;
    overflow: auto;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
    background: white;
}
.table-scroll table {
    border-collapse: collapse;
    width: 100%;
    font-size: 12px;
}
.table-scroll th {
    position: sticky;
    top: 0;
    background: #eff6ff;
    text-align: left;
    padding: 6px 8px;
    border-bottom: 1px solid #d1d5db;
}
.table-scroll td {
    padding: 5px 8px;
    border-bottom: 1px solid #f3f4f6;
}
.table-scroll tr:nth-child(even) td {
    background: #f9fafb;
}
.row-risk td {
    background: #fef2f2 !important;
}
.empty {
    font-size: 12px;
    color: #6b7280;
    margin-top: 6px;
}
.footer {
    margin-top: 32px;
    font-size: 11px;
    color: #9ca3af;
    text-align: right;
}
.hidden-sub { display: none; }

.charts-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
    margin-top: 20px;
}
.chart-card {
    background: white;
    border-radius: 16px;
    padding: 14px 16px;
    box-shadow: 0 1px 4px rgba(15,23,42,0.08);
}
.chart-title {
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 2px;
}
.chart-sub {
    font-size: 11px;
    color: #6b7280;
    margin-bottom: 8px;
}
.chart-card canvas {
    width: 100%;
    max-height: 260px;
}
.chart-card-full { margin-top: 10px; }

.heatmap-legend {
    margin-top: 8px;
    font-size: 11px;
    color: #6b7280;
}
.heat-legend-dot {
    display: inline-block;
    width: 16px;
    height: 8px;
    border-radius: 999px;
    margin-right: 4px;
}
.heat-none { background: #e5e7eb; }
.heat-low  { background: #facc15; }
.heat-med  { background: #fb923c; }
.heat-high { background: #dc2626; }

.about-list {
    margin-top: 8px;
    padding-left: 18px;
    font-size: 12px;
    color: #4b5563;
}
.about-list li { margin-bottom: 3px; }

@media (max-width: 1100px) {
    .summary-cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .sub-metrics   { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .charts-grid   { grid-template-columns: 1fr; }
}
@media (max-width: 768px) {
    .summary-cards { grid-template-columns: 1fr; }
    .sub-metrics   { grid-template-columns: 1fr 1fr; }
}
</style>
"@

$htmlSb = New-Object -TypeName System.Text.StringBuilder
[void]$htmlSb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8' />")
[void]$htmlSb.AppendLine("<title>Azure Health Check</title>")
[void]$htmlSb.AppendLine("<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>")
[void]$htmlSb.AppendLine("<script src='https://cdn.jsdelivr.net/npm/chartjs-chart-matrix@2.0.0'></script>")
[void]$htmlSb.AppendLine($css)
[void]$htmlSb.AppendLine("</head><body>")

$header = @"
<div class="header">
  <div class="header-title">Azure Health Check</div>
  <div class="header-sub">Environment overview for governance, compute, storage, network and Key Vault</div>
  <div class="header-sub">Author: Joao Paulo Costa</div>

  <div class="header-links">
    <a href="https://getpractical.co.uk" target="_blank" rel="noopener noreferrer">
      <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 2a10 10 0 1 0 .001 20.001A10 10 0 0 0 12 2zm-1 17.93A8.001 8.001 0 0 1 4.07 13H7c.46 2.28 1.57 4.31 3 5.93v1zM4.07 11A8.001 8.001 0 0 1 11 4.07V5c-1.43 1.62-2.54 3.65-3 5.93H4.07zM13 4.07A8.001 8.001 0 0 1 19.93 11H17c-.46-2.28-1.57-4.31-3-5.93V4.07zM17 13h2.93A8.001 8.001 0 0 1 13 19.93V19c1.43-1.62 2.54-3.65 3-5.93z" />
      </svg>
      getpractical.co.uk
    </a>

    <a href="https://www.linkedin.com/in/jpsantoscosta" target="_blank" rel="noopener noreferrer">
      <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M4.98 3.5C4.98 4.88 3.9 6 2.5 6S0 4.88 0 3.5 1.08 1 2.5 1s2.48 1.12 2.48 2.5zM.2 8.26h4.6V23H.2zM8.34 8.26h4.41v2.01h.06c.61-1.16 2.1-2.39 4.33-2.39 4.63 0 5.48 3.05 5.48 7.01V23h-4.6v-7.1c0-1.69-.03-3.86-2.35-3.86-2.36 0-2.72 1.84-2.72 3.74V23h-4.6z" />
      </svg>
      LinkedIn
    </a>

    <a href="https://github.com/jpsantoscosta" target="_blank" rel="noopener noreferrer">
      <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.09 3.29 9.4 7.86 10.93.58.11.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.7-3.88-1.54-3.88-1.54-.53-1.34-1.3-1.7-1.3-1.7-1.06-.73.08-.72.08-.72 1.17.08 1.78 1.2 1.78 1.2 1.04 1.77 2.73 1.26 3.4.96.11-.76.41-1.26.75-1.55-2.56-.29-5.26-1.28-5.26-5.7 0-1.26.45-2.29 1.19-3.09-.12-.29-.52-1.47.11-3.06 0 0 .97-.31 3.18 1.18a10.9 10.9 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.77.11 3.06.74.8 1.18 1.83 1.18 3.09 0 4.43-2.7 5.41-5.28 5.69.42.36.8 1.09.8 2.2 0 1.59-.02 2.87-.02 3.26 0 .31.21.68.8.56A10.52 10.52 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5z" />
      </svg>
      GitHub
    </a>
  </div>

  <div class="header-meta">
    Tenant: $(HtmlEncode $tenantId) |
    Subscriptions: $totalSubs |
    Run (UTC): $(HtmlEncode $runTimeUtc) |
    User: $(HtmlEncode $userName)
  </div>
</div>
<div class="main">
"@
[void]$htmlSb.AppendLine($header)

[void]$htmlSb.AppendLine(@"
<div class="section">
  <div class="table-title">About this report</div>
  <div class="sub-meta">
    This report provides a high-level health overview of your Azure subscriptions. It focuses on common
    governance, protection and hygiene issues that typically surface during health checks and readiness
    reviews.
  </div>
  <ul class="about-list">
    <li><strong>Governance</strong> - Resource groups without management locks.</li>
    <li><strong>Backup</strong> - Azure VMs that do not appear to be protected by Azure Backup.</li>
    <li><strong>Compute hygiene</strong> - VMs using legacy disk types (HDD / unmanaged) and VMs with high CPU (P95 over last 7 days).</li>
    <li><strong>Storage</strong> - TLS &lt; 1.2, public blob access enabled, soft delete unclear.</li>
    <li><strong>Network</strong> - Subnets and NICs without NSG, and NSG rules exposing RDP/SSH from the Internet.</li>
    <li><strong>Key Vault</strong> - Key Vaults without purge protection and objects expiring soon.</li>
    <li><strong>Activity Log</strong> - Whether subscription Activity Log diagnostics are configured (any destination).</li>
    <li><strong>SQL</strong> - Inventory of SQL instances (Azure SQL logical servers, Managed Instances, SQL on Azure VMs).</li>
    <li><strong>Azure Policy</strong> - Inventory of Policy assignments at subscription scope.</li>
    <li><strong>Defender for Cloud</strong> - Defender plan coverage per subscription (Standard vs Free). Free tier means the workload is not actively monitored by Defender.</li>
    <li><strong>Stopped VMs</strong> - Virtual Machines in OS-stopped state (not deallocated). These still incur compute charges.</li>
    <li><strong>Resource Tagging</strong> - Resource groups and VMs with no tags (or missing required tags if -RequiredTags is specified).</li>
    <li><strong>Public-facing Resources</strong> - App Services, Storage Accounts, and SQL servers/Managed Instances with public network access not explicitly disabled.</li>
    <li><strong>Privileged Identity</strong> - Permanent Owner/Contributor role assignments for users and groups that should be managed via PIM instead of direct assignment.</li>
  </ul>
</div>
"@)

[void]$htmlSb.AppendLine("<div class='summary-cards'>")

[void]$htmlSb.AppendLine(@"
<div class='card'>
  <div class='card-title'>Subscriptions</div>
  <div class='card-value'><span id='summary-subs-value'>$totalSubs</span></div>
  <div class='card-sub'>
    <span class='bad'><span id='summary-subs-bad'>$subsBadPercent</span>% affected</span>
    &nbsp;&middot;&nbsp;
    <span class='good'><span id='summary-subs-good'>$subsGoodPercent</span>% healthy</span>
  </div>
</div>
"@)

[void]$htmlSb.AppendLine(@"
<div class='card'>
  <div class='card-title'>RGs without locks</div>
  <div class='card-value'><span id='summary-rg-value'>$totalRgNoLocks</span></div>
  <div class='card-sub'>
    <span class='bad'><span id='summary-rg-bad'>$rgBadPercent</span>% affected</span>
    &nbsp;&middot;&nbsp;
    <span class='good'><span id='summary-rg-good'>$rgGoodPercent</span>% ok</span>
  </div>
</div>
"@)

[void]$htmlSb.AppendLine(@"
<div class='card'>
  <div class='card-title'>VMs without backup</div>
  <div class='card-value'><span id='summary-vm-value'>$totalVmNoBackup</span></div>
  <div class='card-sub'>
    <span class='bad'><span id='summary-vm-bad'>$vmBadPercent</span>% affected</span>
    &nbsp;&middot;&nbsp;
    <span class='good'><span id='summary-vm-good'>$vmGoodPercent</span>% ok</span>
  </div>
</div>
"@)

[void]$htmlSb.AppendLine(@"
<div class='card'>
  <div class='card-title'>Storage risks</div>
  <div class='card-value'><span id='summary-storage-value'>$totalStorageRisks</span></div>
  <div class='card-sub'>
    <span class='bad'><span id='summary-storage-bad'>$storageBadPercent</span>% affected</span>
    &nbsp;&middot;&nbsp;
    <span class='good'><span id='summary-storage-good'>$storageGoodPercent</span>% ok</span>
  </div>
</div>
"@)

[void]$htmlSb.AppendLine("</div>")  # summary-cards

[void]$htmlSb.AppendLine(@"
<div class='section'>
  <div class='table-title'>Risk overview</div>
  <div class='sub-meta'>Global risk distribution and per-subscription concentration.</div>
  <div class='charts-grid'>
    <div class='chart-card'>
      <div class='chart-title'>Risk by category</div>
      <div class='chart-sub'>Split of all findings across categories (includes Activity Log diagnostics missing).</div>
      <canvas id='riskDonut'></canvas>
    </div>
    <div class='chart-card'>
      <div class='chart-title'>Heat map by subscription</div>
      <div class='chart-sub'>Subscriptions (rows) vs categories (columns). Colour indicates severity based on finding count.</div>
      <canvas id='heatMap'></canvas>
      <div class='heatmap-legend'>
        <span class='heat-legend-dot heat-none'></span>None&nbsp;&nbsp;
        <span class='heat-legend-dot heat-low'></span>Low&nbsp;&nbsp;
        <span class='heat-legend-dot heat-med'></span>Medium&nbsp;&nbsp;
        <span class='heat-legend-dot heat-high'></span>High
      </div>
    </div>
  </div>
</div>
"@)

[void]$htmlSb.AppendLine("<div class='section'>")
[void]$htmlSb.AppendLine("<div class='table-title'>Top 5 subscriptions by issue count</div>")
[void]$htmlSb.AppendLine("<div class='chart-card chart-card-full'><canvas id='topSubsChart'></canvas></div>")
[void]$htmlSb.AppendLine("<div class='table-scroll'><table><thead><tr><th>Subscription</th><th>Score</th><th>Approx. issues</th></tr></thead><tbody>")
foreach ($ts in $topSubs) {
    [void]$htmlSb.AppendLine("<tr><td>$(HtmlEncode $ts.Name)</td><td>$(HtmlEncode $ts.Score)</td><td>$(HtmlEncode $ts.Issues)</td></tr>")
}
[void]$htmlSb.AppendLine("</tbody></table></div></div>")

[void]$htmlSb.AppendLine("<div class='subscription-filters'>")
[void]$htmlSb.AppendLine("<div class='subscription-filters-controls'><strong>Subscriptions:</strong> <button type='button' id='btn-select-all'>Select all</button><button type='button' id='btn-clear-all'>Clear all</button></div>")
[void]$htmlSb.AppendLine("<div class='subscription-list'>")
foreach ($sub in $subscriptions) {
    $sid   = $sub.Id
    $sname = $sub.Name
    [void]$htmlSb.AppendLine("<label><input type='checkbox' class='sub-toggle' data-sub-id='$([System.Net.WebUtility]::HtmlEncode($sid))' checked /> $(HtmlEncode $sname)</label>")
}
[void]$htmlSb.AppendLine("</div></div>")

#-----------------------------
# Per subscription sections
#-----------------------------
foreach ($sub in $subscriptions) {
    $sid   = $sub.Id
    $sname = $sub.Name

    $govSub        = $govResults          | Where-Object { $_.SubscriptionId -eq $sid }
    $vmSub         = $vmResults           | Where-Object { $_.SubscriptionId -eq $sid }
    $vmDiskSub     = $vmDiskModernResults | Where-Object { $_.SubscriptionId -eq $sid }
    $vmCpuSub      = $vmCpuHighResults    | Where-Object { $_.SubscriptionId -eq $sid }
    $diskSub       = $diskResults         | Where-Object { $_.SubscriptionId -eq $sid }
    $pipSub        = $pipResults          | Where-Object { $_.SubscriptionId -eq $sid }
    $storageSub    = $storageResults      | Where-Object { $_.SubscriptionId -eq $sid }
    $kvSub         = $kvResults           | Where-Object { $_.SubscriptionId -eq $sid }
    $kvExpSub      = $kvExpiryResults     | Where-Object { $_.SubscriptionId -eq $sid }
    $nsgSubnetsSub = $nsgSubnetsMissing   | Where-Object { $_.SubscriptionId -eq $sid }
    $nsgNicsSub    = $nsgNicsMissing      | Where-Object { $_.SubscriptionId -eq $sid }
    $nsgRulesSub   = $nsgOpenMgmtRules    | Where-Object { $_.SubscriptionId -eq $sid }

    $actLogSub     = $activityLogDiagResults  | Where-Object { $_.SubscriptionId -eq $sid }
    $sqlSub        = $sqlInstanceResults      | Where-Object { $_.SubscriptionId -eq $sid }
    $policySub     = $policyAssignmentResults | Where-Object { $_.SubscriptionId -eq $sid }

    $defenderSub      = $defenderResults        | Where-Object { $_.SubscriptionId -eq $sid }
    $vmStoppedSub2    = $vmStoppedResults       | Where-Object { $_.SubscriptionId -eq $sid }
    $taggingGapSub    = $taggingGapResults      | Where-Object { $_.SubscriptionId -eq $sid }
    $publicAppSub     = $publicAppServiceResults | Where-Object { $_.SubscriptionId -eq $sid }
    $publicSqlSub     = $publicSqlResults        | Where-Object { $_.SubscriptionId -eq $sid }
    $publicStorageSub = $storageResults          | Where-Object { $_.SubscriptionId -eq $sid -and $_.PublicNetworkAccess -eq 'Allow' }
    $privIdentitySub2 = $privIdentityResults     | Where-Object { $_.SubscriptionId -eq $sid }

    $stats         = $subStats | Where-Object { $_.Id -eq $sid }

    $rgWithoutLocks   = $stats.RgBad
    $vmWithoutBackup  = $stats.VmBad
    $unattachedDisks  = ($diskSub | Measure-Object).Count
    $freePips         = ($pipSub  | Measure-Object).Count
    $storageRisksSub  = $stats.StorageBad
    $scoreSub         = $stats.Score

    $rgTotalSub       = $stats.RgTotal
    $vmTotalSub       = $stats.VmTotal
    $storageTotalSub  = $stats.StorageTotal
    $hasIssue         = $stats.HasIssue

    $storageSubDisplay = $storageSub | Select-Object `
        SubscriptionId, SubscriptionName, ResourceGroup, StorageAccountName, Location, Kind, Replication, `
        MinimumTlsVersion, AllowBlobPublicAccess, SoftDeleteEnabled, PublicNetworkAccess, RiskCategory

    $kvSubDisplay = $kvSub | Select-Object `
        SubscriptionId, SubscriptionName, ResourceGroup, VaultName, Location, SoftDelete, PurgeProtection

    $actLogSubDisplay = $actLogSub | Select-Object `
        SubscriptionId, SubscriptionName, DiagnosticConfigured, Destinations, IsRisk

    $sqlSubDisplay = $sqlSub | Select-Object `
        SubscriptionId, SubscriptionName, ResourceGroup, ResourceType, Name, Location

    $policySubDisplay = $policySub | Select-Object `
        SubscriptionId, SubscriptionName, DisplayName, Scope, PolicyDefinitionId

    $vmCpuSubDisplay = $vmCpuSub | Select-Object `
        SubscriptionId, SubscriptionName, ResourceGroup, VMName, Location, CpuAvg7d, CpuP95_7d, CpuMaxSample7d, Threshold, IsRisk

    $defenderSubDisplay    = $defenderSub    | Select-Object SubscriptionId, SubscriptionName, PlanName, Tier, IsRisk
    $vmStoppedSubDisplay   = $vmStoppedSub2  | Select-Object SubscriptionId, SubscriptionName, ResourceGroup, VMName, Location, PowerState
    $taggingGapSubDisplay  = $taggingGapSub  | Select-Object SubscriptionId, SubscriptionName, ResourceType, ResourceGroup, ResourceName, Location, MissingTags

    $publicAppSubDisplay     = $publicAppSub     | Select-Object SubscriptionId, SubscriptionName, ResourceGroup, AppServiceName, Location, Kind, PublicNetworkAccess
    $publicSqlSubDisplay     = $publicSqlSub     | Select-Object SubscriptionId, SubscriptionName, ResourceGroup, ResourceType, Name, Location, PublicNetworkAccess
    $publicStorageSubDisplay = $publicStorageSub | Select-Object SubscriptionId, SubscriptionName, ResourceGroup, StorageAccountName, Location, Kind, PublicNetworkAccess
    $privIdentitySubDisplay  = $privIdentitySub2 | Select-Object SubscriptionId, SubscriptionName, PrincipalName, PrincipalType, PrincipalId, Role, Scope

    $sidSafe = SafeHtmlId -Id $sid

    $govHtml        = New-TableHtml -Data $govSub             -Id "gov-$sidSafe"      -Title "Governance - Resource group locks"
    $vmHtml         = New-TableHtml -Data $vmSub              -Id "vm-$sidSafe"       -Title "Compute - Virtual machines without backup"
    $vmDiskHtml     = New-TableHtml -Data $vmDiskSub          -Id "vmdisk-$sidSafe"   -Title "Compute - VMs with legacy disk types (HDD / unmanaged)"
    $vmCpuHtml      = New-TableHtml -Data $vmCpuSubDisplay    -Id "vmcpu-$sidSafe"    -Title "Compute - VMs with high CPU (P95 over last 7 days)"
    $diskHtml       = New-TableHtml -Data $diskSub            -Id "disk-$sidSafe"     -Title "Compute - Unattached disks"
    $pipHtml        = New-TableHtml -Data $pipSub             -Id "pip-$sidSafe"      -Title "Compute - Unattached Public IPs"
    $storageHtml    = New-TableHtml -Data $storageSubDisplay  -Id "stg-$sidSafe"      -Title "Storage accounts"
    $kvHtml         = New-TableHtml -Data $kvSubDisplay       -Id "kv-$sidSafe"       -Title "Key Vaults - configuration"
    $kvExpHtml      = New-TableHtml -Data $kvExpSub           -Id "kvexp-$sidSafe"    -Title "Key Vault objects expiring in next 90 days"
    $nsgSubnetsHtml = New-TableHtml -Data $nsgSubnetsSub      -Id "nsgsub-$sidSafe"   -Title "Network - subnets without NSG"
    $nsgNicsHtml    = New-TableHtml -Data $nsgNicsSub         -Id "nsgnic-$sidSafe"   -Title "Network - NICs without NSG"
    $nsgRulesHtml   = New-TableHtml -Data $nsgRulesSub        -Id "nsgrule-$sidSafe"  -Title "Network - NSG rules exposing RDP/SSH from Internet"

    $actLogHtml     = New-TableHtml -Data $actLogSubDisplay   -Id "actlog-$sidSafe"   -Title "Activity Log - diagnostic settings (any destination)"
    $sqlHtml        = New-TableHtml -Data $sqlSubDisplay      -Id "sql-$sidSafe"      -Title "SQL - instances inventory (Azure SQL / MI / SQL on VM)"
    $policyHtml     = New-TableHtml -Data $policySubDisplay   -Id "pol-$sidSafe"      -Title "Azure Policy - assignments (subscription scope)"

    $defenderHtml     = New-TableHtml -Data $defenderSubDisplay   -Id "def-$sidSafe"    -Title "Defender for Cloud - plan coverage"
    $vmStoppedHtml    = New-TableHtml -Data $vmStoppedSubDisplay  -Id "vstop-$sidSafe"  -Title "Compute - VMs in stopped state (not deallocated)"
    $taggingGapHtml   = New-TableHtml -Data $taggingGapSubDisplay -Id "tag-$sidSafe"    -Title "Tagging gaps - resource groups and VMs"

    $publicAppHtml     = New-TableHtml -Data $publicAppSubDisplay     -Id "pubapp-$sidSafe"   -Title "Security - App Services with public network access enabled"
    $publicSqlHtml     = New-TableHtml -Data $publicSqlSubDisplay     -Id "pubsql-$sidSafe"   -Title "Security - SQL servers/Managed Instances with public network access enabled"
    $publicStorageHtml = New-TableHtml -Data $publicStorageSubDisplay -Id "pubstg-$sidSafe"   -Title "Security - Storage Accounts with no network firewall (DefaultAction: Allow)"
    $privIdentityHtml  = New-TableHtml -Data $privIdentitySubDisplay  -Id "privid-$sidSafe"   -Title "Security - Permanent Owner/Contributor assignments (users/groups without PIM)"

    # ---- v1.0.6+ UI note: metrics disclaimer under CPU table ----
    $cpuNote = "Note: CPU metrics may be missing for some VMs if Azure Monitor metrics are not available/disabled, the VM was recently created, the VM was deallocated for long periods, or you don't have permission to read metrics. Missing metrics are not treated as a failure by this report."
    $vmCpuHtml = $vmCpuHtml + (New-NoteHtml -Text $cpuNote)

    $stoppedNote = "Note: 'VM stopped' means the OS was shut down but the VM was not deallocated. Azure still charges for compute in this state. Deallocated VMs are not listed here."
    $vmStoppedHtml = $vmStoppedHtml + (New-NoteHtml -Text $stoppedNote)

    $taggingNote = "Note: Only resource groups and virtual machines are checked for tagging gaps. Use -RequiredTags to specify required tag names; if omitted, resources with no tags at all are reported."
    $taggingGapHtml = $taggingGapHtml + (New-NoteHtml -Text $taggingNote)

    $publicAppNote = "Note: App Services listed here have PublicNetworkAccess not explicitly set to 'Disabled'. This means they may be reachable from the public internet. Consider enabling access restrictions or VNet integration."
    $publicAppHtml = $publicAppHtml + (New-NoteHtml -Text $publicAppNote)

    $publicSqlNote = "Note: SQL logical servers where publicNetworkAccess is not Disabled, and Managed Instances where publicDataEndpointEnabled is true, are listed here."
    $publicSqlHtml = $publicSqlHtml + (New-NoteHtml -Text $publicSqlNote)

    $publicStorageNote = "Note: Storage Accounts where the network firewall default action is 'Allow' (no IP or VNet rules applied) are listed here. This is separate from blob-level public access."
    $publicStorageHtml = $publicStorageHtml + (New-NoteHtml -Text $publicStorageNote)

    $privIdentityNote = "Note: Only permanent direct role assignments for users and groups are returned here. PIM-eligible (not yet activated) assignments do not appear as permanent assignments and are not listed. Service principals and managed identities are excluded."
    $privIdentityHtml = $privIdentityHtml + (New-NoteHtml -Text $privIdentityNote)

    $issueFlag = if ($hasIssue) { 1 } else { 0 }

    [void]$htmlSb.AppendLine("<div class='section sub-section' data-subscription-id='$([System.Net.WebUtility]::HtmlEncode($sid))' data-rg-no-locks='$rgWithoutLocks' data-rg-total='$rgTotalSub' data-vm-no-backup='$vmWithoutBackup' data-vm-total='$vmTotalSub' data-storage-risks='$storageRisksSub' data-storage-total='$storageTotalSub' data-has-issue='$issueFlag'>")
    [void]$htmlSb.AppendLine("<div class='sub-header'><strong>Subscription:</strong> $(HtmlEncode $sname)</div>")
    [void]$htmlSb.AppendLine("<div class='sub-meta'>$(HtmlEncode $sid)</div>")

    [void]$htmlSb.AppendLine("<div class='sub-metrics'>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>Score</div><div class='sub-card-value'>$(HtmlEncode $scoreSub)</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>RGs without locks</div><div class='sub-card-value'>$(HtmlEncode $rgWithoutLocks)</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>VMs without backup</div><div class='sub-card-value'>$(HtmlEncode $vmWithoutBackup)</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>Unattached disks</div><div class='sub-card-value'>$(HtmlEncode $unattachedDisks)</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>Unattached Public IPs</div><div class='sub-card-value'>$(HtmlEncode $freePips)</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>Storage risks</div><div class='sub-card-value'>$(HtmlEncode $storageRisksSub)</div></div>")
    [void]$htmlSb.AppendLine("</div>")

    [void]$htmlSb.AppendLine($govHtml)
    [void]$htmlSb.AppendLine($vmHtml)
    [void]$htmlSb.AppendLine($vmDiskHtml)
    [void]$htmlSb.AppendLine($vmCpuHtml)
    [void]$htmlSb.AppendLine($diskHtml)
    [void]$htmlSb.AppendLine($pipHtml)
    [void]$htmlSb.AppendLine($storageHtml)
    [void]$htmlSb.AppendLine($kvHtml)
    [void]$htmlSb.AppendLine($kvExpHtml)
    [void]$htmlSb.AppendLine($nsgSubnetsHtml)
    [void]$htmlSb.AppendLine($nsgNicsHtml)
    [void]$htmlSb.AppendLine($nsgRulesHtml)

    [void]$htmlSb.AppendLine($actLogHtml)
    [void]$htmlSb.AppendLine($sqlHtml)
    [void]$htmlSb.AppendLine($policyHtml)
    [void]$htmlSb.AppendLine($defenderHtml)
    [void]$htmlSb.AppendLine($vmStoppedHtml)
    [void]$htmlSb.AppendLine($taggingGapHtml)
    [void]$htmlSb.AppendLine($publicAppHtml)
    [void]$htmlSb.AppendLine($publicSqlHtml)
    [void]$htmlSb.AppendLine($publicStorageHtml)
    [void]$htmlSb.AppendLine($privIdentityHtml)

    [void]$htmlSb.AppendLine("</div>")
}

[void]$htmlSb.AppendLine("<div class='footer'>Report generated at $(HtmlEncode $runTimeUtc) (UTC)</div>")
[void]$htmlSb.AppendLine("</div>") # main

#=============================
# JavaScript for live summary + select/clear all + export CSV
#=============================
$js = @'
<script>
document.addEventListener("DOMContentLoaded", function () {
  function updateSummary() {
    var checkboxes = document.querySelectorAll(".sub-toggle");
    var subsTotalSelected = 0;
    var subsBad = 0;
    var rgBad = 0, rgTotal = 0;
    var vmBad = 0, vmTotal = 0;
    var storageBad = 0, storageTotal = 0;

    checkboxes.forEach(function (cb) {
      var subId = cb.getAttribute("data-sub-id");
      var section = document.querySelector(".sub-section[data-subscription-id='" + subId + "']");
      if (!section) { return; }

      if (!cb.checked) {
        section.classList.add("hidden-sub");
        return;
      }

      section.classList.remove("hidden-sub");
      subsTotalSelected++;

      var rgBadSub = parseInt(section.getAttribute("data-rg-no-locks") || "0");
      var rgTotalSub = parseInt(section.getAttribute("data-rg-total") || "0");
      var vmBadSub = parseInt(section.getAttribute("data-vm-no-backup") || "0");
      var vmTotalSub = parseInt(section.getAttribute("data-vm-total") || "0");
      var storageBadSub = parseInt(section.getAttribute("data-storage-risks") || "0");
      var storageTotalSub = parseInt(section.getAttribute("data-storage-total") || "0");
      var hasIssue = section.getAttribute("data-has-issue") === "1";

      rgBad += rgBadSub;
      rgTotal += rgTotalSub;
      vmBad += vmBadSub;
      vmTotal += vmTotalSub;
      storageBad += storageBadSub;
      storageTotal += storageTotalSub;

      if (hasIssue) { subsBad++; }
    });

    function calcPerc(bad, total) {
      if (!total || total === 0) {
        return { bad: 0, good: 0 };
      }
      var badP = Math.round((bad * 100) / total);
      return { bad: badP, good: 100 - badP };
    }

    var pSubs = calcPerc(subsBad, subsTotalSelected || 0);
    var pRg = calcPerc(rgBad, rgTotal);
    var pVm = calcPerc(vmBad, vmTotal);
    var pStg = calcPerc(storageBad, storageTotal);

    function setText(id, value) {
      var el = document.getElementById(id);
      if (el) { el.textContent = value; }
    }

    setText("summary-subs-value", subsTotalSelected);
    setText("summary-rg-value", rgBad);
    setText("summary-vm-value", vmBad);
    setText("summary-storage-value", storageBad);

    setText("summary-subs-bad", pSubs.bad);
    setText("summary-subs-good", pSubs.good);
    setText("summary-rg-bad", pRg.bad);
    setText("summary-rg-good", pRg.good);
    setText("summary-vm-bad", pVm.bad);
    setText("summary-vm-good", pVm.good);
    setText("summary-storage-bad", pStg.bad);
    setText("summary-storage-good", pStg.good);
  }

  function tableToCsv(table) {
    var rows = Array.from(table.querySelectorAll("tr"));
    return rows.map(function (row) {
      var cells = Array.from(row.querySelectorAll("th,td"));
      return cells.map(function (cell) {
        var text = cell.textContent || "";
        text = text.replace(/"/g, '""');
        return '"' + text + '"';
      }).join(",");
    }).join("\r\n");
  }

  function downloadCsv(csv, filename) {
    var blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  document.querySelectorAll(".export-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var tableId = btn.getAttribute("data-table-id");
      var table = document.getElementById(tableId);
      if (!table) { return; }
      var csv = tableToCsv(table);
      var stamp = new Date().toISOString().replace(/[:\.]/g, "-");
      var filename = tableId + "_" + stamp + ".csv";
      downloadCsv(csv, filename);
    });
  });

  document.querySelectorAll(".sub-toggle").forEach(function (cb) {
    cb.addEventListener("change", updateSummary);
  });

  var btnSelectAll = document.getElementById("btn-select-all");
  if (btnSelectAll) {
    btnSelectAll.addEventListener("click", function () {
      document.querySelectorAll(".sub-toggle").forEach(function (cb) {
        cb.checked = true;
      });
      updateSummary();
    });
  }

  var btnClearAll = document.getElementById("btn-clear-all");
  if (btnClearAll) {
    btnClearAll.addEventListener("click", function () {
      document.querySelectorAll(".sub-toggle").forEach(function (cb) {
        cb.checked = false;
      });
      updateSummary();
    });
  }

  updateSummary();
});
</script>
'@

#=============================
# JavaScript for charts (donut, heat map, top-5)
#=============================
$chartsJs = @"
<script>
document.addEventListener('DOMContentLoaded', function () {
  if (typeof Chart === 'undefined') { return; }

  var donutData = $categoryJson;
  var heatMapData = $heatMapJson;
  var topSubsData = $topSubsJson;

  if (!Array.isArray(donutData)) { donutData = []; }
  if (!Array.isArray(heatMapData)) { heatMapData = []; }
  if (!Array.isArray(topSubsData)) { topSubsData = []; }

  // ----- Risk donut -----
  var donutCanvas = document.getElementById('riskDonut');
  if (donutCanvas && donutData.length > 0) {
    var ctxD = donutCanvas.getContext('2d');
    new Chart(ctxD, {
      type: 'doughnut',
      data: {
        labels: donutData.map(function (x) { return x.Category; }),
        datasets: [{
          data: donutData.map(function (x) { return x.Count; }),
          borderWidth: 1
        }]
      },
      options: {
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#374151', font: { size: 11 } }
          }
        }
      }
    });
  }

  // ----- Heat map (subscription vs category) -----
  var heatCanvas = document.getElementById('heatMap');
  if (heatCanvas && heatMapData.length > 0) {
    var ctxH = heatCanvas.getContext('2d');

    // Keep heatmap focused on risk categories (exclude SQL/Policy inventory)
    var categories = ['Governance','Backup','Compute','Storage','Network','KeyVault','ActivityLog','PublicAccess','PrivIdentity'];
    var subs = heatMapData.map(function (r) { return r.Subscription; });

    function countToSeverity(count) {
      if (count >= 10) return 3;
      if (count >= 4)  return 2;
      if (count >= 1)  return 1;
      return 0;
    }
    function sevToColor(v) {
      if (v === 3) return 'rgba(220,38,38,0.95)';
      if (v === 2) return 'rgba(249,115,22,0.95)';
      if (v === 1) return 'rgba(250,204,21,0.9)';
      return 'rgba(243,244,246,1)';
    }

    var values = [];
    heatMapData.forEach(function (row) {
      categories.forEach(function (cat) {
        var count = row[cat] || 0;
        var sev = countToSeverity(count);
        values.push({ x: cat, y: row.Subscription, v: sev, count: count });
      });
    });

    new Chart(ctxH, {
      type: 'matrix',
      data: {
        datasets: [{
          data: values,
          borderWidth: 1,
          borderColor: 'rgba(209,213,219,1)',
          width: function(ctx) {
            var a = ctx.chart.chartArea || {};
            return (a.right - a.left) / categories.length - 4;
          },
          height: function(ctx) {
            var a = ctx.chart.chartArea || {};
            return (a.bottom - a.top) / subs.length - 4;
          },
          backgroundColor: function(ctx) {
            return sevToColor(ctx.raw.v);
          }
        }]
      },
      options: {
        maintainAspectRatio: false,
        scales: {
          x: { type: 'category', labels: categories, offset: true, ticks: { color: '#4b5563', font: { size: 10 } }, grid: { display: false } },
          y: { type: 'category', labels: subs, offset: true, ticks: { color: '#4b5563', font: { size: 10 } }, grid: { display: false } }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: function(items) {
                var r = items[0].raw;
                return r.y + ' / ' + r.x;
              },
              label: function(ctx) {
                var r = ctx.raw;
                var count = r.count || 0;
                if (r.v === 3) return count + ' item(s) - High';
                if (r.v === 2) return count + ' item(s) - Medium';
                if (r.v === 1) return count + ' item(s) - Low';
                return 'No items';
              }
            }
          }
        }
      }
    });
  }

  // ----- Top 5 subscriptions bar chart -----
  var topCanvas = document.getElementById('topSubsChart');
  if (topCanvas && topSubsData.length > 0) {
    var ctxT = topCanvas.getContext('2d');
    new Chart(ctxT, {
      type: 'bar',
      data: {
        labels: topSubsData.map(function (x) { return x.Name; }),
        datasets: [{
          data: topSubsData.map(function (x) { return x.Issues; }),
          borderWidth: 1
        }]
      },
      options: {
        indexAxis: 'y',
        scales: {
          x: { ticks: { color: '#4b5563', precision: 0 }, grid: { color: 'rgba(229,231,235,1)' } },
          y: { ticks: { color: '#4b5563' }, grid: { display: false } }
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: function (ctx) { return ctx.raw + ' finding(s)'; } } }
        }
      }
    });
  }
});
</script>
"@

[void]$htmlSb.AppendLine($js)
[void]$htmlSb.AppendLine($chartsJs)
[void]$htmlSb.AppendLine("</body></html>")

#=============================
# Write file
#=============================
$basePath = "C:\TEMP\Health Check script"
if (-not (Test-Path $basePath)) {
    New-Item -Path $basePath -ItemType Directory -Force | Out-Null
}

$multiSuffix = "MULTI"
$fileName = "Azure-HealthCheck_{0}_{1}_{2}.html" -f $tenantId, $multiSuffix, (Get-Date -Format "yyyyMMdd-HHmmss")
$fullPath = Join-Path $basePath $fileName

$htmlSb.ToString() | Out-File -FilePath $fullPath -Encoding UTF8

Write-Info "Report written to: $fullPath"

if ($OpenAfterExport) {
    Start-Process $fullPath
}

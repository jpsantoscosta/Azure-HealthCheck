<#PSScriptInfo

.VERSION 1.0.0

.GUID 4129a3f4-6bb2-4dea-9d84-895d5dd2d3b7

.AUTHOR Joao Paulo Costa

.COMPANYNAME getpractical.co.uk

.COPYRIGHT

.TAGS
    getpractical
    Microsoft Azure

.LICENSEURI
    https://github.com/jpsantoscosta/Azure-HealthCheck/blob/main/LICENSE 
.PROJECTURI
    https://github.com/jpsantoscosta/Azure-HealthCheck
.ICONURI

.EXTERNALMODULEDEPENDENCIES

.RELEASENOTES
    v1.0.0 - Initial release
#>
 
 <#
.SYNOPSIS
 Azure Health Check – governance, compute and storage overview, HTML report.

.NOTES
 Author: Joao Paulo Costa (getpractical.co.uk)
#>

[CmdletBinding()]
param(
    [switch]$OpenAfterExport
)

#=============================
# Helper: logging
#=============================
function Write-Info {
    param(
        [string]$Message
    )
    Write-Host "[INFO] $Message"
}

#=============================
# Helper: HTML table builder
#  - Always shows section title
#  - Shows "No rows..." when empty
#  - Highlights risk rows
#  - Adds "Export CSV" button for non-empty tables
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

    $sb = New-Object -TypeName System.Text.StringBuilder
    [void]$sb.AppendLine("<div class='table-wrap'>")

    if ($Title) {
        if ($Id -and $hasRows) {
            # Title + export button
            [void]$sb.AppendLine("<div class='table-header'><div class='table-title'>$Title</div><button type='button' class='export-btn' data-table-id='$Id'>Export CSV</button></div>")
        }
        else {
            [void]$sb.AppendLine("<div class='table-title'>$Title</div>")
        }
    }

    if (-not $hasRows) {
        [void]$sb.AppendLine("<div class='empty'>✓ No rows to display for this section.</div>")
        [void]$sb.AppendLine("</div>")
        return $sb.ToString()
    }

    $first = $rows[0]
    $props = $first.PSObject.Properties.Name
    if (-not $props -or $props.Count -eq 0) {
        [void]$sb.AppendLine("<div class='empty'>✓ No rows to display for this section.</div>")
        [void]$sb.AppendLine("</div>")
        return $sb.ToString()
    }

    [void]$sb.AppendLine("<div class='table-scroll'><table id='$Id'>")

    # Header
    [void]$sb.AppendLine("<thead><tr>")
    foreach ($p in $props) {
        [void]$sb.AppendLine("<th>$p</th>")
    }
    [void]$sb.AppendLine("</tr></thead>")

    # Body
    [void]$sb.AppendLine("<tbody>")
    foreach ($row in $rows) {
        $trClass = ""

        if ($row.PSObject.Properties.Name -contains 'BackupProtected') {
            if (-not $row.BackupProtected) {
                $trClass = " class='row-risk'"
            }
        }
        elseif ($row.PSObject.Properties.Name -contains 'RiskCategory') {
            if ($row.RiskCategory -and $row.RiskCategory -ne 'None') {
                $trClass = " class='row-risk'"
            }
        }

        [void]$sb.AppendLine("<tr$trClass>")
        foreach ($p in $props) {
            $val = $row.$p
            if ($null -eq $val) { $val = "" }
            [void]$sb.AppendLine("<td>$val</td>")
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

# Get all subs for the signed-in account (tenant already chosen by Az UI)
$subscriptions = Get-AzSubscription |
    Where-Object { $_.State -in @('Enabled', 'Warned') } |
    Sort-Object Name

if (-not $subscriptions) {
    throw "No subscriptions found for the current login."
}

# Use tenant ID from the first subscription (they will all be same tenant after the Az selection UI)
$tenantId = $subscriptions[0].TenantId
$runTimeUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
$userName = $ctx.Account.Id

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

# NEW collections
$vmDiskModernResults = @()  # VMs with HDD / unmanaged disks
$kvResults           = @()  # Key Vault config
$kvExpiryResults     = @()  # KV objects expiring
$nsgSubnetsMissing   = @()  # Subnets without NSG
$nsgNicsMissing      = @()  # NICs without NSG
$nsgOpenMgmtRules    = @()  # NSG rules exposing RDP/SSH

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
        [int]$SubnetsNoNsg,
        [int]$NicsNoNsg,
        [int]$NsgOpenMgmtRules,
        [int]$KeyVaultsNoPurge,
        [int]$KvSecretsExpiring60
    )

    $score = 100

    # Rough weighting; you can tweak later
    $score -= [math]::Min(40, $VmBad * 2)
    $score -= [math]::Min(20, $RgBad)
    $score -= [math]::Min(20, $StorageBad * 2)
    $score -= [math]::Min(10, ($UnattachedDisks + $FreePips))
    $score -= [math]::Min(10, ($VmHdd + $VmUnmanaged))
    $score -= [math]::Min(10, ($SubnetsNoNsg + $NicsNoNsg))
    $score -= [math]::Min(10, ($NsgOpenMgmtRules + $KeyVaultsNoPurge + [int]([math]::Ceiling($KvSecretsExpiring60 / 5.0))))

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

    # only by SubscriptionId – no TenantId
    Set-AzContext -SubscriptionId $sid -ErrorAction Stop | Out-Null

    #-------------------------
    # Governance – RGs without locks
    #-------------------------
    $rgList     = Get-AzResourceGroup
    $rgTotalSub = $rgList.Count

    $allLocks = @()
    try {
        $allLocks = Get-AzResourceLock -AtSubscriptionLevel -ErrorAction SilentlyContinue
    } catch { }

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
    }

    #-------------------------
    # Compute – VMs (backup + legacy disks)
    #-------------------------
    $vmList     = Get-AzVM -Status -ErrorAction SilentlyContinue
    $vmTotalSub = $vmList.Count

    # HashSet with names of protected VMs (lowercase)
    $protectedVmNames = [System.Collections.Generic.HashSet[string]]::new()

    $vaults = Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue
    foreach ($vault in $vaults) {
        try {
            # Get only AzureVM backup items from this vault
            $items = Get-AzRecoveryServicesBackupItem `
                -VaultId $vault.ID `
                -BackupManagementType AzureVM `
                -WorkloadType AzureVM `
                -ErrorAction SilentlyContinue

            foreach ($item in $items) {
                $vmName = $null

                # Newer Az modules – FriendlyName lives under .Properties
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
                    # Fallback: last segment of Name e.g. "VM;...;CG-VM-DC03"
                    $vmName = $Matches[1]
                }

                if ($vmName) {
                    [void]$protectedVmNames.Add($vmName.ToLowerInvariant())
                }
            }
        } catch { }
    }

    foreach ($vm in $vmList) {
        $vmName   = $vm.Name
        $rgName   = $vm.ResourceGroupName
        $location = $vm.Location

        # Backup protection
        $isProtected = $protectedVmNames.Contains($vmName.ToLowerInvariant())
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
    }

    #-------------------------
    # Compute – Unattached disks
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
    # Compute – Unattached Public IPs
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
    # Storage accounts – TLS, public access, soft delete, replication
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

        try {
            $publicNetwork = $st.NetworkRuleSet.DefaultAction
        } catch { }

        try {
            $allowBlobPublic = $st.AllowBlobPublicAccess
        } catch { }

        # Soft delete – Blob service
        try {
            $blobProps = Get-AzStorageBlobServiceProperty -ResourceGroupName $st.ResourceGroupName -AccountName $st.StorageAccountName -ErrorAction Stop
            if ($blobProps -and $blobProps.DeleteRetentionPolicy) {
                $softDeleteState = if ($blobProps.DeleteRetentionPolicy.Enabled) { 'Enabled' } else { 'Disabled' }
            }
        } catch { }

        # Soft delete – File service (Azure Files)
        try {
            $fileProps = Get-AzStorageFileServiceProperty -ResourceGroupName $st.ResourceGroupName -AccountName $st.StorageAccountName -ErrorAction Stop
            if ($fileProps -and $fileProps.ShareDeleteRetentionPolicy) {
                $softDeleteState = if ($fileProps.ShareDeleteRetentionPolicy.Enabled) { 'Enabled' } else { 'Disabled' }
            }
        } catch { }

        # Risk category: TLS < 1.2 and Blob public access
        if ($rawTls -in @('TLS1_0','TLS1_1')) {
            $riskCategory = 'TLS < 1.2'
        }
        if ($allowBlobPublic -eq $true) {
            if ($riskCategory -eq 'None') { $riskCategory = 'Blob public access' }
            else { $riskCategory = $riskCategory + '; Blob public access' }
        }

        $replication = $st.Sku.Name  # e.g. Standard_GRS, Standard_RAGRS, Standard_ZRS

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
    # Key Vault – config & expiring objects
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

        # Expiring secrets
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

        # Expiring certificates
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

        # Expiring keys
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
    # Network – NSG coverage & exposed ports
    #-------------------------

    # Subnets without NSG
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

    # NICs without NSG
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

    # NSG rules exposing RDP/SSH from Internet
    $nsgs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue
    foreach ($nsg in $nsgs) {
        foreach ($rule in $nsg.SecurityRules) {
            if ($rule.Direction -ne 'Inbound' -or $rule.Access -ne 'Allow') { continue }

            # Source any/Internet?
            $srcPrefixes = @()
            if ($rule.SourceAddressPrefix)  { $srcPrefixes += $rule.SourceAddressPrefix }
            if ($rule.SourceAddressPrefixes){ $srcPrefixes += $rule.SourceAddressPrefixes }

            $isInternet = $false
            foreach ($sp in $srcPrefixes) {
                if ($sp -in @('*','0.0.0.0/0','Internet')) { $isInternet = $true; break }
            }
            if (-not $isInternet) { continue }

            # Ports include 22 or 3389?
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
                    if ((22   -ge $from -and 22   -le $to) -or
                        (3389 -ge $from -and 3389 -le $to)) {
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
    # Aggregate per-subscription stats
    #-------------------------
    $rgWithoutLocks   = ($govResults          | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $vmWithoutBackup  = ($vmResults           | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $unattachedDisks  = ($diskResults         | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $freePips         = ($pipResults          | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $storageRisksSub  = ($storageResults      | Where-Object { $_.SubscriptionId -eq $sid -and $_.RiskCategory -ne 'None' } | Measure-Object).Count

    $vmHddSub         = ($vmDiskModernResults | Where-Object { $_.SubscriptionId -eq $sid -and $_.HasHddDisk }        | Measure-Object).Count
    $vmUnmanagedSub   = ($vmDiskModernResults | Where-Object { $_.SubscriptionId -eq $sid -and $_.HasUnmanagedDisk } | Measure-Object).Count

    $subnetsNoNsgSub  = ($nsgSubnetsMissing   | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $nicsNoNsgSub     = ($nsgNicsMissing      | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count
    $openMgmtRulesSub = ($nsgOpenMgmtRules    | Where-Object { $_.SubscriptionId -eq $sid } | Measure-Object).Count

    $kvWithoutPurgeSub = ($kvResults          | Where-Object { $_.SubscriptionId -eq $sid -and -not $_.PurgeProtection } | Measure-Object).Count
    $kvExpiring60Sub   = ($kvExpiryResults    | Where-Object { $_.SubscriptionId -eq $sid -and $_.DaysToExpiry -le 60 -and $_.DaysToExpiry -ge 0 } | Measure-Object).Count

    $hasIssue = (
        $rgWithoutLocks + $vmWithoutBackup + $unattachedDisks + $freePips + $storageRisksSub +
        $vmHddSub + $vmUnmanagedSub +
        $subnetsNoNsgSub + $nicsNoNsgSub + $openMgmtRulesSub +
        $kvWithoutPurgeSub + $kvExpiring60Sub
    ) -gt 0

    $score = Get-SubScore `
        -RgBad $rgWithoutLocks -VmBad $vmWithoutBackup -StorageBad $storageRisksSub `
        -UnattachedDisks $unattachedDisks -FreePips $freePips `
        -VmHdd $vmHddSub -VmUnmanaged $vmUnmanagedSub `
        -SubnetsNoNsg $subnetsNoNsgSub -NicsNoNsg $nicsNoNsgSub -NsgOpenMgmtRules $openMgmtRulesSub `
        -KeyVaultsNoPurge $kvWithoutPurgeSub -KvSecretsExpiring60 $kvExpiring60Sub

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
        SubnetsNoNsg         = $subnetsNoNsgSub
        NicsNoNsg            = $nicsNoNsgSub
        NsgOpenMgmtRules     = $openMgmtRulesSub
        KeyVaultsNoPurge     = $kvWithoutPurgeSub
        KvSecretsExpiring60  = $kvExpiring60Sub
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

$subsWithIssues   = ($subStats | Where-Object HasIssue).Count
$subBadGlobal     = $subsWithIssues
$subGoodGlobal    = $totalSubs - $subsWithIssues

$rgBadGlobal      = ($subStats | Measure-Object -Property RgBad      -Sum).Sum
$vmBadGlobal      = ($subStats | Measure-Object -Property VmBad      -Sum).Sum
$storageBadGlobal = ($subStats | Measure-Object -Property StorageBad -Sum).Sum

if (-not $rgBadGlobal)      { $rgBadGlobal = 0 }
if (-not $vmBadGlobal)      { $vmBadGlobal = 0 }
if (-not $storageBadGlobal) { $storageBadGlobal = 0 }

function Get-PercentPair {
    param(
        [int]$Bad,
        [int]$Total
    )
    if ($Total -le 0) {
        return ,(0, 0)
    }
    $badP  = [math]::Round(($Bad * 100.0) / $Total)
    $goodP = 100 - $badP
    return ,($badP, $goodP)
}

$subsPerc    = Get-PercentPair -Bad $subBadGlobal      -Total $totalSubs
$rgPerc      = Get-PercentPair -Bad $rgBadGlobal       -Total $totalRgAll
$vmPerc      = Get-PercentPair -Bad $vmBadGlobal       -Total $totalVmAll
$storagePerc = Get-PercentPair -Bad $storageBadGlobal  -Total $totalStorageAll

$subsBadPercent,    $subsGoodPercent    = $subsPerc
$rgBadPercent,      $rgGoodPercent      = $rgPerc
$vmBadPercent,      $vmGoodPercent      = $vmPerc
$storageBadPercent, $storageGoodPercent = $storagePerc

# Additional global metrics for new checks
$totalVmLegacyDisks = ($vmDiskModernResults | Measure-Object).Count
$totalSubnetsNoNsg  = ($nsgSubnetsMissing   | Measure-Object).Count
$totalNicsNoNsg     = ($nsgNicsMissing      | Measure-Object).Count
$totalNsgOpenRules  = ($nsgOpenMgmtRules    | Measure-Object).Count
$totalKvNoPurge     = ($kvResults           | Where-Object { -not $_.PurgeProtection }                                   | Measure-Object).Count
$totalKvExpiring60  = ($kvExpiryResults     | Where-Object { $_.DaysToExpiry -le 60 -and $_.DaysToExpiry -ge 0 }         | Measure-Object).Count

# Security metrics (kept for table, not for old bars)
$securityMetrics = @(
    [pscustomobject]@{ Name = 'Unattached Public IPs';                     Value = ($pipResults | Measure-Object).Count }
    [pscustomobject]@{ Name = 'Unattached disks';                          Value = ($diskResults | Measure-Object).Count }
    [pscustomobject]@{ Name = 'VMs without backup';                        Value = $totalVmNoBackup }
    [pscustomobject]@{ Name = 'VMs with legacy disks (HDD/unmanaged)';     Value = $totalVmLegacyDisks }
    [pscustomobject]@{ Name = 'RGs without locks';                         Value = $totalRgNoLocks }
    [pscustomobject]@{ Name = 'TLS < 1.2';                                 Value = ($storageResults | Where-Object { $_.RiskCategory -like '*TLS < 1.2*' } | Measure-Object).Count }
    [pscustomobject]@{ Name = 'Storage Account Public Access Enabled';     Value = ($storageResults | Where-Object { $_.RiskCategory -like '*Blob public access*' } | Measure-Object).Count }
    [pscustomobject]@{ Name = 'Subnets without NSG';                       Value = $totalSubnetsNoNsg }
    [pscustomobject]@{ Name = 'NICs without NSG';                          Value = $totalNicsNoNsg }
    [pscustomobject]@{ Name = 'NSG rules exposing RDP/SSH';                Value = $totalNsgOpenRules }
    [pscustomobject]@{ Name = 'Key Vaults without purge protection';       Value = $totalKvNoPurge }
    [pscustomobject]@{ Name = 'KV objects expiring ≤60 days';              Value = $totalKvExpiring60 }
)

$maxMetric = ($securityMetrics.Value | Measure-Object -Maximum).Maximum
if (-not $maxMetric -or $maxMetric -eq 0) { $maxMetric = 1 }

# Top 5 subscriptions by approximate "issues"
$topSubs = $subStats | ForEach-Object {
    $issues = $_.RgBad + $_.VmBad + $_.StorageBad + $_.UnattachedDisks + $_.FreePips +
              $_.VmHdd + $_.VmUnmanaged +
              $_.SubnetsNoNsg + $_.NicsNoNsg + $_.NsgOpenMgmtRules +
              $_.KeyVaultsNoPurge + $_.KvSecretsExpiring60

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
    [pscustomobject]@{ Category = 'Governance';      Count = $totalRgNoLocks }
    [pscustomobject]@{ Category = 'Backup';          Count = $totalVmNoBackup }
    [pscustomobject]@{ Category = 'Compute';         Count = $totalVmLegacyDisks }
    [pscustomobject]@{ Category = 'Storage';         Count = $totalStorageRisks }
    [pscustomobject]@{ Category = 'Network';         Count = $totalSubnetsNoNsg + $totalNicsNoNsg + $totalNsgOpenRules }
    [pscustomobject]@{ Category = 'KeyVault';        Count = $totalKvNoPurge + $totalKvExpiring60 }
) | Where-Object { $_.Count -gt 0 }

$categoryJson = $categoryBreakdown | ConvertTo-Json -Compress

$heatMapRows = foreach ($s in $subStats) {
    [pscustomobject]@{
        Subscription = $s.Name
        Governance   = [int]$s.RgBad
        Backup       = [int]$s.VmBad
        Compute      = [int]($s.VmHdd + $s.VmUnmanaged)
        Storage      = [int]$s.StorageBad
        Network      = [int]($s.SubnetsNoNsg + $s.NicsNoNsg + $s.NsgOpenMgmtRules)
        KeyVault     = [int]($s.KeyVaultsNoPurge + $s.KvSecretsExpiring60)
    }
}

$heatMapJson = $heatMapRows | ConvertTo-Json -Compress
$topSubsJson = $topSubs     | Select-Object Name, Issues | ConvertTo-Json -Compress

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
.hidden-sub {
    display: none;
}

/* New: charts layout */
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
.chart-card-full {
    margin-top: 10px;
}
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

/* About list */
.about-list {
    margin-top: 8px;
    padding-left: 18px;
    font-size: 12px;
    color: #4b5563;
}
.about-list li {
    margin-bottom: 3px;
}

@media (max-width: 1100px) {
    .summary-cards {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .sub-metrics {
        grid-template-columns: repeat(3, minmax(0, 1fr));
    }
    .charts-grid {
        grid-template-columns: 1fr;
    }
}
@media (max-width: 768px) {
    .summary-cards {
        grid-template-columns: 1fr;
    }
    .sub-metrics {
        grid-template-columns: 1fr 1fr;
    }
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

# Header
$header = @"
<div class="header">
  <div class="header-title">Azure Health Check</div>
  <div class="header-sub">Environment overview for governance, compute, storage, network and Key Vault</div>
  <div class="header-sub">
    Author: Joao Paulo Costa –
    <a href='https://getpractical.co.uk' target='_blank' rel='noopener noreferrer'>getpractical.co.uk</a> ·
    <a href='https://www.linkedin.com/in/jpsantoscosta' target='_blank' rel='noopener noreferrer'>LinkedIn</a>
  </div>
  <div class="header-meta">
    Tenant: $tenantId |
    Subscriptions: $totalSubs |
    Run (UTC): $runTimeUtc |
    User: $userName
  </div>
</div>
<div class="main">
"@
[void]$htmlSb.AppendLine($header)

# About this report – DETAILED
[void]$htmlSb.AppendLine(@"
<div class="section">
  <div class="table-title">About this report</div>
  <div class="sub-meta">
    This report provides a high-level health overview of your Azure subscriptions. It focuses on common
    governance, protection and hygiene issues that typically surface during health checks and readiness
    reviews.
  </div>
  <ul class="about-list">
    <li><strong>Governance</strong> – Resource groups without management locks, increasing the risk of accidental deletion or change.</li>
    <li><strong>Backup</strong> – Azure VMs that do not appear to be protected by Azure Backup.</li>
    <li><strong>Compute hygiene</strong> – VMs using legacy disk types (HDD / unmanaged).</li>
    <li><strong>Storage</strong> – Storage accounts with TLS &lt; 1.2, public blob access enabled, or soft delete / recovery not clearly configured.</li>
    <li><strong>Network</strong> – Subnets and NICs without NSG protection, and NSG rules exposing RDP (3389) or SSH (22) from the Internet.</li>
    <li><strong>Key Vault</strong> – Key Vaults without purge protection and secrets / keys / certificates expiring soon and requiring review.</li>
  </ul>
</div>
"@)

# Summary cards (initial values – JS will keep them live)
[void]$htmlSb.AppendLine("<div class='summary-cards'>")

# Subscriptions
[void]$htmlSb.AppendLine(@"
<div class='card'>
  <div class='card-title'>Subscriptions</div>
  <div class='card-value'><span id='summary-subs-value'>$totalSubs</span></div>
  <div class='card-sub'>
    <span class='bad'><span id='summary-subs-bad'>$subsBadPercent</span>% affected</span>
    ·
    <span class='good'><span id='summary-subs-good'>$subsGoodPercent</span>% healthy</span>
  </div>
</div>
"@)

# RGs without locks
[void]$htmlSb.AppendLine(@"
<div class='card'>
  <div class='card-title'>RGs without locks</div>
  <div class='card-value'><span id='summary-rg-value'>$totalRgNoLocks</span></div>
  <div class='card-sub'>
    <span class='bad'><span id='summary-rg-bad'>$rgBadPercent</span>% affected</span>
    ·
    <span class='good'><span id='summary-rg-good'>$rgGoodPercent</span>% ok</span>
  </div>
</div>
"@)

# VMs without backup
[void]$htmlSb.AppendLine(@"
<div class='card'>
  <div class='card-title'>VMs without backup</div>
  <div class='card-value'><span id='summary-vm-value'>$totalVmNoBackup</span></div>
  <div class='card-sub'>
    <span class='bad'><span id='summary-vm-bad'>$vmBadPercent</span>% affected</span>
    ·
    <span class='good'><span id='summary-vm-good'>$vmGoodPercent</span>% ok</span>
  </div>
</div>
"@)

# Storage risks
[void]$htmlSb.AppendLine(@"
<div class='card'>
  <div class='card-title'>Storage risks</div>
  <div class='card-value'><span id='summary-storage-value'>$totalStorageRisks</span></div>
  <div class='card-sub'>
    <span class='bad'><span id='summary-storage-bad'>$storageBadPercent</span>% affected</span>
    ·
    <span class='good'><span id='summary-storage-good'>$storageGoodPercent</span>% ok</span>
  </div>
</div>
"@)

[void]$htmlSb.AppendLine("</div>")  # summary-cards

# ===== NEW: Visual risk overview (donut + heat map) =====
[void]$htmlSb.AppendLine(@"
<div class='section'>
  <div class='table-title'>Risk overview</div>
  <div class='sub-meta'>Global risk distribution and per-subscription concentration.</div>
  <div class='charts-grid'>
    <div class='chart-card'>
      <div class='chart-title'>Risk by category</div>
      <div class='chart-sub'>Split of all findings across governance, backup, compute hygiene, storage, network and Key Vault.</div>
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

# ===== NEW: Top-5 subscriptions visual + table =====
[void]$htmlSb.AppendLine("<div class='section'>")
[void]$htmlSb.AppendLine("<div class='table-title'>Top 5 subscriptions by issue count</div>")
[void]$htmlSb.AppendLine("<div class='chart-card chart-card-full'><canvas id='topSubsChart'></canvas></div>")
[void]$htmlSb.AppendLine("<div class='table-scroll'><table><thead><tr><th>Subscription</th><th>Score</th><th>Approx. issues</th></tr></thead><tbody>")
foreach ($ts in $topSubs) {
    [void]$htmlSb.AppendLine("<tr><td>$($ts.Name)</td><td>$($ts.Score)</td><td>$($ts.Issues)</td></tr>")
}
[void]$htmlSb.AppendLine("</tbody></table></div></div>")

# Subscription filters with checkboxes + buttons
[void]$htmlSb.AppendLine("<div class='subscription-filters'>")
[void]$htmlSb.AppendLine("<div class='subscription-filters-controls'><strong>Subscriptions:</strong> <button type='button' id='btn-select-all'>Select all</button><button type='button' id='btn-clear-all'>Clear all</button></div>")
[void]$htmlSb.AppendLine("<div class='subscription-list'>")
foreach ($sub in $subscriptions) {
    $sid   = $sub.Id
    $sname = $sub.Name
    [void]$htmlSb.AppendLine("<label><input type='checkbox' class='sub-toggle' data-sub-id='$sid' checked /> $sname</label>")
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
    $diskSub       = $diskResults         | Where-Object { $_.SubscriptionId -eq $sid }
    $pipSub        = $pipResults          | Where-Object { $_.SubscriptionId -eq $sid }
    $storageSub    = $storageResults      | Where-Object { $_.SubscriptionId -eq $sid }
    $vmDiskSub     = $vmDiskModernResults | Where-Object { $_.SubscriptionId -eq $sid }
    $kvSub         = $kvResults           | Where-Object { $_.SubscriptionId -eq $sid }
    $kvExpSub      = $kvExpiryResults     | Where-Object { $_.SubscriptionId -eq $sid }
    $nsgSubnetsSub = $nsgSubnetsMissing   | Where-Object { $_.SubscriptionId -eq $sid }
    $nsgNicsSub    = $nsgNicsMissing      | Where-Object { $_.SubscriptionId -eq $sid }
    $nsgRulesSub   = $nsgOpenMgmtRules    | Where-Object { $_.SubscriptionId -eq $sid }
    $stats         = $subStats            | Where-Object { $_.Id -eq $sid }

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
        SubscriptionId,
        SubscriptionName,
        ResourceGroup,
        StorageAccountName,
        Location,
        Kind,
        Replication,
        MinimumTlsVersion,
        AllowBlobPublicAccess,
        SoftDeleteEnabled,
        PublicNetworkAccess,
        RiskCategory

    $kvSubDisplay     = $kvSub | Select-Object `
        SubscriptionId,
        SubscriptionName,
        ResourceGroup,
        VaultName,
        Location,
        SoftDelete,
        PurgeProtection

    $govHtml          = New-TableHtml -Data $govSub        -Id "gov-$($sid)"     -Title "Governance – Resource group locks"
    $vmHtml           = New-TableHtml -Data $vmSub         -Id "vm-$($sid)"      -Title "Compute – Virtual machines without backup"
    $vmDiskHtml       = New-TableHtml -Data $vmDiskSub     -Id "vmdisk-$($sid)"  -Title "Compute – VMs with legacy disk types (HDD / unmanaged)"
    $diskHtml         = New-TableHtml -Data $diskSub       -Id "disk-$($sid)"    -Title "Compute – Unattached disks"
    $pipHtml          = New-TableHtml -Data $pipSub        -Id "pip-$($sid)"     -Title "Compute – Unattached Public IPs"
    $storageHtml      = New-TableHtml -Data $storageSubDisplay -Id "stg-$($sid)" -Title "Storage accounts"
    $kvHtml           = New-TableHtml -Data $kvSubDisplay  -Id "kv-$($sid)"      -Title "Key Vaults – configuration"
    $kvExpHtml        = New-TableHtml -Data $kvExpSub      -Id "kvexp-$($sid)"   -Title "Key Vault objects expiring in next 90 days"
    $nsgSubnetsHtml   = New-TableHtml -Data $nsgSubnetsSub -Id "nsgsub-$($sid)"  -Title "Network – subnets without NSG"
    $nsgNicsHtml      = New-TableHtml -Data $nsgNicsSub    -Id "nsgnic-$($sid)"  -Title "Network – NICs without NSG"
    $nsgRulesHtml     = New-TableHtml -Data $nsgRulesSub   -Id "nsgrule-$($sid)" -Title "Network – NSG rules exposing RDP/SSH from Internet"

    $issueFlag = if ($hasIssue) { 1 } else { 0 }

    [void]$htmlSb.AppendLine("<div class='section sub-section' data-subscription-id='$sid' data-rg-no-locks='$rgWithoutLocks' data-rg-total='$rgTotalSub' data-vm-no-backup='$vmWithoutBackup' data-vm-total='$vmTotalSub' data-storage-risks='$storageRisksSub' data-storage-total='$storageTotalSub' data-has-issue='$issueFlag'>")
    [void]$htmlSb.AppendLine("<div class='sub-header'><strong>Subscription:</strong> $sname</div>")
    [void]$htmlSb.AppendLine("<div class='sub-meta'>$sid</div>")

    [void]$htmlSb.AppendLine("<div class='sub-metrics'>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>Score</div><div class='sub-card-value'>$scoreSub</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>RGs without locks</div><div class='sub-card-value'>$rgWithoutLocks</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>VMs without backup</div><div class='sub-card-value'>$vmWithoutBackup</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>Unattached disks</div><div class='sub-card-value'>$unattachedDisks</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>Unattached Public IPs</div><div class='sub-card-value'>$freePips</div></div>")
    [void]$htmlSb.AppendLine("<div class='sub-card'><div class='sub-card-title'>Storage risks</div><div class='sub-card-value'>$storageRisksSub</div></div>")
    [void]$htmlSb.AppendLine("</div>")

    [void]$htmlSb.AppendLine($govHtml)
    [void]$htmlSb.AppendLine($vmHtml)
    [void]$htmlSb.AppendLine($vmDiskHtml)
    [void]$htmlSb.AppendLine($diskHtml)
    [void]$htmlSb.AppendLine($pipHtml)
    [void]$htmlSb.AppendLine($storageHtml)
    [void]$htmlSb.AppendLine($kvHtml)
    [void]$htmlSb.AppendLine($kvExpHtml)
    [void]$htmlSb.AppendLine($nsgSubnetsHtml)
    [void]$htmlSb.AppendLine($nsgNicsHtml)
    [void]$htmlSb.AppendLine($nsgRulesHtml)

    [void]$htmlSb.AppendLine("</div>")
}

[void]$htmlSb.AppendLine("<div class='footer'>Report generated at $runTimeUtc (UTC)</div>")
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

    var subsGood = subsTotalSelected - subsBad;

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

  // CSV export helpers
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

  // Wire export buttons
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

  // Wire subscription filters
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
            labels: {
              color: '#374151',
              font: { size: 11 }
            }
          }
        }
      }
    });
  }

  // ----- Heat map (subscription vs category) -----
  var heatCanvas = document.getElementById('heatMap');
  if (heatCanvas && heatMapData.length > 0) {
    var ctxH = heatCanvas.getContext('2d');
    var categories = ['Governance','Backup','Compute','Storage','Network','KeyVault'];
    var subs = heatMapData.map(function (r) { return r.Subscription; });

    function countToSeverity(count) {
      if (count >= 10) return 3;  // High
      if (count >= 4)  return 2;  // Medium
      if (count >= 1)  return 1;  // Low
      return 0;                   // None
    }
    function sevToColor(v) {
      if (v === 3) return 'rgba(220,38,38,0.95)';   // high
      if (v === 2) return 'rgba(249,115,22,0.95)';  // medium
      if (v === 1) return 'rgba(250,204,21,0.9)';   // low
      return 'rgba(243,244,246,1)';                 // none
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
            var v = ctx.raw.v;
            return sevToColor(v);
          }
        }]
      },
      options: {
        maintainAspectRatio: false,
        scales: {
          x: {
            type: 'category',
            labels: categories,
            offset: true,
            ticks: { color: '#4b5563', font: { size: 10 } },
            grid: { display: false }
          },
          y: {
            type: 'category',
            labels: subs,
            offset: true,
            ticks: { color: '#4b5563', font: { size: 10 } },
            grid: { display: false }
          }
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
                if (r.v === 3) return count + ' finding(s) – High';
                if (r.v === 2) return count + ' finding(s) – Medium';
                if (r.v === 1) return count + ' finding(s) – Low';
                return 'No findings';
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
          x: {
            ticks: { color: '#4b5563', precision: 0 },
            grid: { color: 'rgba(229,231,235,1)' }
          },
          y: {
            ticks: { color: '#4b5563' },
            grid: { display: false }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                return ctx.raw + ' finding(s)';
              }
            }
          }
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

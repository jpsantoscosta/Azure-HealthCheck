# Azure Health Check

**Azure Health Check HTML Report for governance, compute, storage, network, Key Vault, Activity Log, SQL and Azure Policy.**

This PowerShell script generates a full HTML-based health report across every Azure subscription available in your current context.  
It analyses common governance gaps, security misconfigurations, compute/storage/network risks, Key Vault configuration, upcoming expirations, and more.

---

## 📊 Features

### **✔ Governance**
- Detects Resource Groups without management locks
- Highlights potential accidental-deletion risks

### **✔ Backup**
- Lists all VMs not protected by Azure Backup
- Cross-checks across all Recovery Services Vaults

### **✔ Compute**
- VMs with legacy disks (HDD / unmanaged)
- VMs without backup
- **VMs with high CPU** — flags VMs whose P95 CPU utilisation (hourly average over 7 days) exceeds the threshold (default 80%)
- Unattached disks
- Unattached Public IPs

### **✔ Storage Accounts**
- TLS version issues (TLS 1.0 / 1.1)
- Blob public access enabled
- Soft delete status (Blob / File)
- Replication tier (GRS, ZRS, etc.)

### **✔ Network**
- Subnets without NSG
- NICs without NSG
- Inbound NSG rules exposing RDP/SSH to the Internet

### **✔ Key Vault**
- Vaults without purge protection
- Secrets, certificates and keys expiring within 90 days

### **✔ Activity Log**
- Checks whether subscription-level Activity Log diagnostics are configured
- Supports any destination: Log Analytics, Storage Account, Event Hub, or Partner

### **✔ SQL Inventory**
- Inventory of all SQL instances across subscriptions:
  - Azure SQL logical servers
  - Azure SQL Managed Instances
  - SQL Server on Azure VMs (SQL IaaS Agent)

### **✔ Azure Policy**
- Inventory of all Policy assignments at subscription scope
- Shows display name, scope, and policy definition ID

---

## 🧰 Output

The script generates a **single HTML dashboard** with:

- Summary cards
- Donut chart (risk by category)
- Heat map (subscription vs issue type)
- Top 5 subscriptions by risk
- Per-subscription detailed tables
- Export-to-CSV buttons for each section

---

## 🚀 Usage

### Install from PowerShell Gallery

```powershell
Install-Script -Name Invoke-AzHealthCheck -Force
```

### Run

```powershell
Invoke-AzHealthCheck
Invoke-AzHealthCheck -OpenAfterExport
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OpenAfterExport` | Switch | `$false` | Automatically opens the HTML report after generation |
| `-CpuHighThresholdPercent` | Int | `80` | CPU P95 threshold (%) above which a VM is flagged as high-CPU |
| `-CpuTopNPerSubscription` | Int | `20` | Maximum number of high-CPU VMs reported per subscription |

### Output location

```
C:\TEMP\Health Check script\
Azure-HealthCheck_<TenantId>_MULTI_<timestamp>.html
```

---

## 🔐 Required Permissions

The script is read-only and does not modify any resources.

| Component | Required Role |
|-----------|--------------|
| Resources (VMs, RGs, storage, network, etc.) | Reader |
| Key Vault expiry metadata | Key Vault Secrets User (or custom: `secrets/read`, `keys/read`, `certificates/read`) |
| Recovery Services Vault (backup items) | Reader (or Backup Reader in restricted tenants) |
| CPU metrics | Monitoring Reader (or `Microsoft.Insights/metrics/read`) |

---

## 📝 Roadmap

- Add filters for regions, categories and subscriptions
- Add PDF export
- Add dark mode UI for HTML report

---

## 🤝 Contributing

Pull requests are welcome!  
Feel free to submit issues or feature requests using GitHub Issues.

---

## 🧑‍💻 Author

João Paulo Costa  
Blog: https://getpractical.co.uk  
LinkedIn: https://www.linkedin.com/in/jpsantoscosta

---

## 📜 License

This project is licensed under the MIT License.

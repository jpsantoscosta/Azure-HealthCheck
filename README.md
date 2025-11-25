# Azure Health Check

**Azure Health Check HTML Report for governance, compute, storage, network, Key Vault and subscription hygiene.**

This PowerShell script generates a full HTML-based health report across every Azure subscription available in your current context.  
It analyses common governance gaps, security misconfigurations, compute/storage/network risks, Key Vault configuration and upcoming expirations.

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
- Unattached disks  
- VMs without backup

### **✔ Public IPs**
- Identifies unused/unattached Public IPs  
- Highlights potential cost or security waste

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

```powershell
# Run the script
.\Azure-HealthCheck.ps1 -OpenAfterExport
```
Use -OpenAfterExport to automatically open the HTML report after generation.

Output location (default):

```powershell
C:\TEMP\Health Check script\
Azure-HealthCheck_<Tenant>_MULTI_<timestamp>.html
```

---
🔐 Required Permissions

The script is read-only and does not modify resources.

Minimum required Azure roles:

Component	Required Role
Resources (VMs, RGs, storage, network, etc.) 	Reader
Key Vault expiry metadata	Key Vault Secrets User (or custom: secrets/read, keys/read, certificates/read)
Recovery Services Vault (backup items)**	Reader (or Backup Reader in restricted tenants)

---
📦 Installation (PowerShell Gallery)

Coming soon:
```powershell
Install-Script -Name Azure-HealthCheck
```

---
📝 Roadmap

Add GitHub Actions pipeline to publish automatically to PowerShell Gallery
Add filters for regions, categories and subscriptions
Add PDF export
Add dark mode UI for HTML report

---
🤝 Contributing

Pull requests are welcome!
Feel free to submit issues or feature requests using GitHub Issues.

---
🧑‍💻 Author

João Paulo Costa
Blog: https://getpractical.co.uk
LinkedIn: https://www.linkedin.com/in/jpsantoscosta

---
📜 License

This project is licensed under the MIT License.

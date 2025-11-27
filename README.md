### 🔍 DC-ShareRisk

A lightweight PowerShell tool to detect non-default SMB shares on Domain Controllers and identify insecure or misconfigured ACLs.

---
### 📘 Overview

Domain Controllers should never host custom SMB shares.  
Only `SYSVOL` and `NETLOGON` are expected by design.

Any additional share created on a DC, intentionally or not, has been considered a bad practice for many years and exposes the environment to unnecessary risks.

This script scans all Domain Controllers, detects non-standard shares, and analyzes their ACLs to identify:
- Unauthorized accounts  
- Dangerous or non-whitelisted permissions  
- Non-inherited ACEs  
- Unexpected or unapproved shares  
---
### ⚠️ Why non-default shares on DCs are dangerous

### 1. Domain Controllers are Tier-0 assets

A Domain Controller holds the highest privileges in the environment.  
Any misconfiguration, including an unnecessary SMB share, becomes a potential entry point for attackers.

### 2. Excessive permissions = compromise

A share with `Write` or `FullControl` for normal users can allow:

- Dropping malicious files  
- Overwriting configuration or script files  
- Persistence or privilege escalation paths  
- NTLM hash capture via `.lnk`, `SCF` or `desktop.ini` techniques  
- First-step lateral movement on a Tier-0 asset  

### 3. Rarely audited

Most security tools (such as PingCastle or PurpleKnight) do not inspect SMB shares on Domain Controllers, which means dangerous shares can remain unnoticed for years.

### 4. Not aligned with Microsoft / CIS / ANSSI guidelines

Unexpected SMB shares on Domain Controllers are considered a high-risk misconfiguration in most hardening baselines.

### ✅ Why use this script

- Detects all non-default shares on Domain Controllers  
- Analyzes ACLs without requiring RSAT  
- Identifies unsafe or unexpected permissions  
- Works from any Windows machine joined to the domain  
- Does not require elevated privileges  
---

### 🛡️ HardenSysvol integration

This functionality is also included, with richer reporting and additional checks, in **HardenSysvol**:

[https://github.com/dakhama-mehdi/HardenSysvol](https://github.com/dakhama-mehdi/Harden-Sysvol)

For production environments and broader AD security assessments, using HardenSysvol is recommended.

### ⚙️ Usage

1. Copy the `.ps1` script to any Windows 10, Windows 11, or Windows Server machine that is joined to the domain.  
2. No administrator rights are required to run it.  
3. Execute the script from a PowerShell session:

```powershell
.\DC-ShareAudit.ps1
```
### 📝 License

This project is released under the **MIT License**.
You are free to **use**, **modify**, and **distribute** it for personal, educational, or internal business use.  
For commercial integration, please contact the author.

### 🙌 Credits
*** 👤 Author**: Mehdi Dakhama
*** 🛠️ Project**: `DC-ShareRisk`  
*** 🔗 Related tools**: 
- 🔐 [HardenSysvol](https://github.com/dakhama-mehdi/HardenSysvol) – Secure your SYSVOL and GPO infrastructure  

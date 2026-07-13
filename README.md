<div align="center">

# 🛡️ System Hardening Lab – Linux · Windows Server 2022 · Active Directory

### Lynis · Microsoft Security Compliance Toolkit · PingCastle · GPO Hardening

![Domain](https://img.shields.io/badge/Type-System%20Hardening%20Lab-darkblue?style=for-the-badge)
![Tools](https://img.shields.io/badge/Tools-Lynis%20%7C%20Policy%20Analyzer%20%7C%20PingCastle-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Findings-All%20Resolved-brightgreen?style=for-the-badge)

<img src="https://img.shields.io/badge/Linux-Lynis%203.1.6%20%7C%20Hardening%20Index%2062%2F100-orange?style=flat-square" />
<img src="https://img.shields.io/badge/Windows-Microsoft%20Security%20Baseline%20GPO-blue?style=flat-square" />
<img src="https://img.shields.io/badge/Active%20Directory-PingCastle%20%7C%20NTLMv1%20Resolved-purple?style=flat-square" />
<img src="https://img.shields.io/badge/MITRE-T1557.001%20Addressed-red?style=flat-square" />
<img src="https://img.shields.io/badge/Approach-Assess%20%E2%86%92%20Remediate%20%E2%86%92%20Verify-green?style=flat-square" />

---

**Prepared by:** Bikash Raya
**Project Type:** System Hardening Lab — Linux, Windows Server 2022 & Active Directory

</div>

---

## 📁 Repository Structure

| File | Description |
| --- | --- |
| [System_Hardening_Lab_Report.pdf](./System_Hardening_Lab_Report.pdf) | Complete lab report with all screenshots embedded |
| README.md | Project overview |

---

## 📋 Overview

This lab applies a structured, tool-driven hardening approach across three environments — a Kali Linux host, a Windows Server 2022 domain member, and an Active Directory domain. Rather than making arbitrary configuration changes, each environment is assessed with a recognised security tool, gaps are identified against industry standards, targeted remediations are applied, and improvement is verified through re-assessment.

This mirrors how hardening is performed in real enterprise environments: **measure first, fix based on evidence, verify the fix worked.**

---

## 🛠️ Tools Used

| Tool | Environment | Purpose |
| --- | --- | --- |
| **Lynis 3.1.6** | Kali Linux | CIS-aligned host security audit |
| **Microsoft Security Compliance Toolkit** | Windows Server 2022 | Baseline gap analysis via Policy Analyzer |
| **PingCastle** | Active Directory | Domain health check and risk scoring |
| **Group Policy (GPO)** | Windows Server / AD | Deploying hardening settings at scale |

---

## 🌐 Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│                   PART 1 — LINUX                    │
│  Kali Linux → Lynis audit → Score 62/100            │
│  Fix: AppArmor · auditd · Sysctl · Password Policy  │
│  Verify: Targeted Lynis re-scans per finding        │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│             PART 2 — WINDOWS SERVER 2022             │
│  BIKSEC-WEB01 → Policy Analyzer → Baseline gaps     │
│  Fix: Secure_Baseline GPO + Audit Policy GPO        │
│  Verify: gpresult + Policy Analyzer re-compare      │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│            PART 3 — ACTIVE DIRECTORY                │
│  biksec.com → PingCastle → NTLMv1 (+15 risk pts)   │
│  Fix: GPO enforcing NTLMv2 only                     │
│  Verify: PingCastle re-scan — finding resolved      │
└─────────────────────────────────────────────────────┘
```

---

## 🐧 Part 1 — Linux Hardening (Lynis)

### Tool & Baseline

```bash
sudo apt install lynis -y
sudo lynis audit system
```

**Baseline result:** Hardening index **62/100** | 270 tests | 3 warnings | 49 suggestions

### Remediations

<details>
<summary><b>Remediation 1 — AppArmor (Mandatory Access Control)</b></summary>

**Finding:** AppArmor is installed but the MAC framework shows NONE — no Mandatory Access Control is active.

**Risk:** Without MAC enforcement, a compromised process has unrestricted access to whatever the running user can touch. There is no containment layer beyond standard file permissions.

**Fix:**
```bash
sudo systemctl enable apparmor
sudo systemctl start apparmor
```

**Verify:**
```bash
sudo lynis audit system | grep -E "AppArmor status|implemented MAC framework"
```
✅ MAC framework now active

</details>

<details>
<summary><b>Remediation 2 — auditd (Audit Logging)</b></summary>

**Finding:** No audit daemon (auditd) present — Lynis reports NOT FOUND.

**Risk:** Without auditd, security-relevant events leave no tamper-evident record. There is no way to answer "who changed this and when" after an incident.

**Fix:**
```bash
sudo apt install auditd -y
sudo systemctl enable --now auditd
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
```

**Verify:**
```bash
sudo lynis audit system | grep -E "Checking auditd"
auditctl -l   # confirms /etc/passwd watch rule active
```
✅ auditd found and active — file integrity monitoring on /etc/passwd confirmed

</details>

<details>
<summary><b>Remediation 3 — Kernel Sysctl Hardening</b></summary>

**Finding:** kernel.kptr_restrict, net.ipv4.conf.all.accept_redirects, and rp_filter all show DIFFERENT from hardened baseline.

**Risk:** Default values increase exposure to kernel pointer leakage (aids exploit development) and IP spoofing/ICMP redirect attacks.

**Fix:**
```bash
sudo bash -c 'cat > /etc/sysctl.d/99-hardening.conf <<EOF
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
EOF
sysctl --system'
```

**Verify:**
```bash
sudo lynis audit system | grep -E "kernel.kptr_restrict|accept_redirects|rp_filter"
```
✅ All three sysctl values now show OK

</details>

<details>
<summary><b>Remediation 4 — Password Policy</b></summary>

**Finding:** Password aging (min/max) disabled, no PAM strength module — Lynis reports DISABLED.

**Risk:** Without aging or complexity enforcement, accounts can retain the same weak or stale password indefinitely — increasing exposure to credential-based attacks.

**Fix:**
```bash
sudo apt install libpam-pwquality -y

# /etc/pam.d/common-password
password requisite pam_pwquality.so retry=3 minlen=12

# /etc/login.defs
PASS_MAX_DAYS  90
PASS_MIN_DAYS   7
PASS_WARN_AGE  14
```

**Verify:**
```bash
grep pwquality /etc/pam.d/common-password
grep PASS /etc/login.defs
sudo lynis audit system | grep -E "password aging"
```
✅ Password aging minimum CONFIGURED | maximum CONFIGURED

</details>

---

## 🪟 Part 2 — Windows Server 2022 Hardening

### Tool & Approach

**Microsoft Security Compliance Toolkit 1.0** — Policy Analyzer compares the current effective security configuration against the official Microsoft recommended baseline for Windows Server 2022, highlighting every configuration gap.

### Steps

**1. Download and import baseline**
- Downloaded Policy Analyzer and Windows Server 2022 Security Baseline
- Imported baseline into Policy Analyzer as "Secure_Baseline"

**2. Compare effective state vs baseline**
- Yellow cells = configuration gap vs Microsoft recommendation
- White cells = setting matches baseline

**3. Deploy Secure_Baseline GPO**
```cmd
gpupdate /force
gpresult /r /scope:computer
```
✅ Secure_Baseline confirmed in Applied Group Policy Objects on BIKSEC-WEB01

**4. Verify in Policy Analyzer**
- Re-compared after GPO deployment
- Yellow cells turned white — baseline settings now match effective state

### Advanced Audit Policy GPO

A dedicated **"Logging Server and Workstation"** GPO was created to enable critical security event logging:

| Audit Policy | Setting | Event IDs | Purpose |
| --- | --- | --- | --- |
| Audit Logon | Success & Failure | 4624, 4625 | Authentication attempts, brute-force detection |
| Audit Credential Validation | Success & Failure | 4776 | Credential validation failures |
| Audit Process Creation | Success | 4688 | Process execution, scripts, payload detection |
| Audit User Account Management | Success & Failure | 4720, 4726, 4738 | Account creation, deletion, modification |

---

## 🏛️ Part 3 — Active Directory Hardening (PingCastle)

### Tool & Scan

PingCastle performs a domain health check and scores the AD environment against known attack vectors, producing a risk-scored report of findings.

### Finding — S-OldNtlm (NTLMv1 Permitted)

| Property | Detail |
| --- | --- |
| Rule ID | S-OldNtlm |
| Risk Points | +15 |
| Issue | NTLMv1 and LM authentication permitted — no GPO sets the LAN Manager Authentication Level |
| Attack Risk | Attacker can capture NTLMv1 hashes via network sniffing or coerced authentication and crack them offline — potentially impersonating the DC |
| MITRE | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay |

### Remediation — Enforce NTLMv2 via GPO

| Setting | Value |
| --- | --- |
| GPO Name | Disable NTLM |
| Policy | Network Security: LAN Manager Authentication Level |
| GPO Path | Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options |
| Value | Send NTLMv2 response only. Refuse LM & NTLM |

### Verification

PingCastle re-scan after GPO deployment:
✅ **S-OldNtlm finding no longer present** — 15-point risk penalty resolved

---

## 📊 Hardening Summary

| Environment | Finding | Severity | Status |
| --- | --- | --- | --- |
| Linux | AppArmor — MAC framework not active | 🔴 High | ✅ Resolved |
| Linux | auditd — audit daemon not installed | 🔴 High | ✅ Resolved |
| Linux | Kernel sysctl — kptr_restrict, rp_filter, redirects | 🟠 Medium | ✅ Resolved |
| Linux | Password policy — aging disabled, no complexity | 🟠 Medium | ✅ Resolved |
| Windows Server | Configuration gaps vs Microsoft Security Baseline | 🔴 High | ✅ Resolved via GPO |
| Windows Server | Advanced Audit Policy — critical events not logged | 🔴 High | ✅ Configured via GPO |
| Active Directory | NTLMv1/LM permitted — S-OldNtlm (+15 risk points) | 🔴 High | ✅ Resolved via GPO |

---

## 🎯 Skills Demonstrated

* Linux Security Auditing (Lynis / CIS-aligned)
* AppArmor / Mandatory Access Control
* auditd & File Integrity Monitoring
* Kernel Sysctl Hardening (persistent configuration)
* PAM Password Policy Configuration
* Microsoft Security Compliance Toolkit (Policy Analyzer)
* Baseline Gap Analysis (current state vs recommended)
* GPO-Based Hardening Deployment
* Advanced Audit Policy Configuration (Event IDs 4624, 4625, 4688, 4720)
* Active Directory Security Assessment (PingCastle)
* NTLMv1/LM Remediation via Group Policy
* Assess → Remediate → Verify Methodology

---

## 🎯 Key Takeaway

> This lab demonstrates a structured, evidence-based approach to system hardening across Linux, Windows Server, and Active Directory — using the same tools employed by security teams and compliance auditors in production environments. Each environment was assessed with a recognised tool, gaps were identified against industry standards (CIS, Microsoft Security Baseline, PingCastle risk scoring), targeted remediations were applied, and improvement was verified through re-assessment. This assess → remediate → verify cycle is the foundation of real-world hardening programmes.

---

## 🔗 Related Projects

> Part of the **Bikash Security Lab** series:
> * [Nessus Vulnerability Management Lab](https://github.com/Bikash-Raya/Nessus-Vulnerability-Management-Lab)
> * [Microsoft Sentinel & Defender XDR — SOC IR Lab](https://github.com/Bikash-Raya/Sentinel-Defender-XDR-SOC-Incident-Response-lab)

---

## 🔗 Connect With Me

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/bikash-raya/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/Bikash-Raya)

</div>

---

<div align="center">

⭐ If you find this project useful, feel free to star the repository ⭐

</div>

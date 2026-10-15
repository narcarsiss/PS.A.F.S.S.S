# PS.A.F.S.S.S
>[!IMPORTANT]
> RESEARCH ONLY: PowerShell Anti-Forensic and Stateless System Script

# 📁 Project Status Notice: Anti-Forensic Stateless Workstation
### 🇦🇺 Australia Enterprise Deployment Architecture Reference

This repository maintains the structural design blueprint and architectural reference for a fully automated, **11-Phase Pre-OS / OOBE Windows Hardening Toolkit**. 

> [!WARNING]
> Due to strict regulatory compliance parameters under Australian federal law, **fully executable source code distribution is restricted**. This project serves as an abstract specification and audit roadmap.

---

## ⚖️ Legal & Compliance Constraints (Why Code is Withheld)

The deployment mechanisms outlined here manage low-level operating system states, identity masking, and stateless storage filters. Under **Part 10.7 (Computer Offences) of the Commonwealth Criminal Code Act 1995 (Cth)**, public hosting or unrestricted distribution of execution scripts of this nature poses severe compliance risks:

*   **Division 478.3 (Possession or Control of Data with Intent):** Publicly supplying or creating open-source modules designed to actively spoof physical identities (SMBIOS/MAC) or neutralize administrative system tracking carries liability if accessed by unauthorized actors [0.1.3, 5].
*   **Division 477.2 & 478.2 (Data Modification and System Impairment):** Automated tools capable of deleting partition structures, dropping cryptographic TPM containers, or executing hard kernel panic halts fall under restricted data modification frameworks unless deployed via authenticated corporate ownership channels [0.1.3, 5].
*   **Crimes Act 1914 (Section 39 - Destruction of Evidence):** Because this architecture utilizes volatile memory (RAM) flooding alongside native API bugchecks (`NtRaiseHardError`) to bypass graceful log commitments, the source logic is withheld to prevent automated deployment on systems subject to legal or forensic inquiry [0.1.3, 5].

To maintain compliance with Australian cybersecurity statutes, the operational script logic is managed through an isolated, out-of-band enterprise deployment pipeline. Only the high-level design specification is permitted here.

---

## 📊 Deployment Architecture & Execution Flow

The framework executes across a strict multi-pass sequence to establish the stateless baseline before arming the volume protection layer.

### Operational Flowchart:
👉 ![Deployment Architecture](./Neon%20Security%20Deployment%20Flowchart.png)

*(If the visual map above fails to render natively due to GitHub markdown scaling, utilize the [Direct Full-Resolution Asset Link](./Neon%20Security%20Deployment%20Flowchart.png) to read the full specification.)*

### 🛠️ The 11-Phase Provisioning Lifecycle

```text
PASS 1: Provisioning (UWF Inactive)
├── Phase 0: Preflight Verification + Immediate Physical NIC Isolation
├── Phase 1: Neutralise Timeline Artifacts (EventLog, Prefetch, BAM, Amcache, ShellBags)
├── Phase 2: Suppress Activation & Suppress Licensing Subsystems (sppsvc, ClipSVC)
├── Phase 3: Hardware Identity Masking (SMBIOS/DMI Randomisation & MAC Spoofing)
├── Phase 4: Enforce Default-Deny Outbound/Inbound Firewall Matrices
├── Phase 5: Emit Under-Overlay Child Scripts (scrub, kill, watch, plant, stash, ghost)
├── Phase 6: Bake Security Baselines (Fixed Disk Serial, SMART Delta, USB Footprints)
├── Phase 7: Stage WDAC Deny Base Policy (User-Mode Code Integrity Enabled)
├── Phase 8: Deploy Active Deception Payloads (Decoy trees, fake manifests, nested bombs)
├── Phase 9: Drop Instant Kill Endpoint Link & Inject Strict ACL Restrictions
└── Phase 10: Enable Unified Write Filter Feature Container
    └──> [AUTOMATED REBOOT]

PASS 2: Arming (UWF Installed)
├── Step 1: Run Idempotent Phase Verification
├── Step 2: Set Write Filter Volume Protection on C:
├── Step 3: Configure Active Overlay Type to RAM (4096MB Allocation)
└── Step 4: Force Global Filter Enable Flag
    └──> [AUTOMATED REBOOT]

STEADY STATE: Operational Runtime (Stateless Window Active)
├── Watcher Engine: Tripwire monitors process names, titles, and environment deltas
└── Trigger Action: Execution of tool results in instant RAM flood + hard kernel halt
```


---

## ⚙️ Technical Reference Matrix

All configuration parameters are declared as unified booleans in the master control engine, governing the following core behaviors:

| Architectural Control | Mechanism Implemented | Defensive/Anti-Forensic Function |
| :--- | :--- | :--- |
| **Stateless Persistence** | RAM-Backed Unified Write Filter (`uwfmgr`) | Forces all runtime changes, MFT modifications, and session artifacts into volatile memory, leaving physical sectors pristine upon power loss. |
| **Network Isolation** | Default-Deny Outbound / Inbound Firewall Profiles | Drops all communication except explicitly whitelisting the local browser, Windows Update, and minimum operational protocols. |
| **Identity Masking** | SMBIOS Spoofing & Class Subkey MAC Manipulation | Generates a random locally-administered MAC (first octet `0x02`) and generic hardware labels to sever persistent device tracking. |
| **Trace Excision** | Registry Cleanse & Default Hive Mounting (`NTUSER.DAT`) | Purges BAM UserSettings, AppCompatCache, UserAssist, RecentDocs, and ShellBags during the provisioning window. |
| **Active Deception** | Advanced Stashing, Path Spoofing, & Nested ZIP Bombs | Generates deceptive directory maps, corrupts file manifests by one nibble, creates fake USN history, and places canary files in Slack space. |
| **Autonomous Tripwires** | Hidden Watcher (`watch.ps1`) via `EnumWindows` P/Invoke | Scans active windows, image paths, descriptions, and processes against the `af-tokens.txt` source of truth to detect unapproved tools or forensic environments. |
| **Instant Kill Routine** | `NtRaiseHardError` (`0xC000021A`) + RAM Page Flooding | Performs a user-space registry flush, allocates massive arrays to scrub 25% of physical memory, and triggers an instant hardware crash without generating debugging memory dumps. |

---

## ⚠️ Stated Design Limits & Known Behaviors

As outlined in the architecture's Engineering Standard Guide, operators must maintain awareness of native platform constraints:

1.  **Timestamp Asymmetry:** Standard Windows tools manipulate `$STANDARD_INFORMATION` attributes; however, `$FILE_NAME` MFT attributes only update on genuine file creations or renames, leaving a detectable delta under advanced forensic scrutiny.
2.  **SMBIOS UUID Bounds:** The system UUID is retrieved directly from physical firmware via WMI at boot. Registry modifications only survive across a warm reboot if executed prior to the active write filter arming cycle.
3.  **UWF Overlay Vulnerabilities:** Executing disk-clearing commands like `cipher /w` post-arm is restricted. Because `cipher` writes full-volume temporary fill files, it will immediately saturate and overflow the allocated 4096MB RAM overlay, leading to an unstable user-space crash.
4.  **WDAC Wildcard Limitations:** The kernel-level code integrity blocklist relies strictly on token name boundaries. Overly broad configurations may cause unintended validation issues if name collisions match vital operational binaries.

---

## 🛠️ Verification & Operational Commands

To confirm statelessness and policy enforcement post-deployment, administrators utilize the following verification checks:

```powershell
# 1. Verify Core Tracking and Diagnostic Services are Terminated (Should output 4)
'EventLog','DiagTrack','sysmain','bam','PcaSvc','sppsvc' | ForEach-Object {
    [pscustomobject]@{ Service=\$_; StartMode=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$_").Start }
}

# 2. Confirm Universal Outbound/Inbound Blockade State
Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, DefaultOutboundAction

# 3. Assert Active Write Filter Status
uwfmgr.exe volume get-config C:
uwfmgr.exe overlay get-config

# 4. Perform Cold Boot Stateless Validation Test
'ValidationToken' | Out-File C:\stateless_test.txt; Restart-Computer -Force
# Following boot: Test-Path C:\stateless_test.txt (Must return False)
```
---
## Our Research paper:  
The Architecture of Volatile Hardening: Design, Implementation, and Anti-Forensic Efficacy of Stateless Tactical Workstations.  

![Deployment Architecture](./MHS_Research_PSAFSSS.md)

---

*For enterprise verification, identity-vetted audits, or to request access to signed offline compliance builds via authorized channels, please open a formal internal engineering tracking ticket.*


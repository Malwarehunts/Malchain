# Detection Library

Every technique ships a runnable Microsoft Defender / Sentinel **KQL** query; 30 techniques with file or memory artifacts also ship a validated **YARA** rule. Open a technique for its rules, or grab the phase-grouped files under [`detections/`](../detections/).

[← Home](../README.md)

## Coverage matrix

| Technique | Name | KQL | YARA |
|-----------|------|-----|------|
| [`ING-01`](phases/ing/MC-ING-01.md) | Removable Media & File Transfer | ✅ | ✅ |
| [`ING-02`](phases/ing/MC-ING-02.md) | Malvertising & Drive-By Downloads | ✅ | ✅ |
| [`ING-03`](phases/ing/MC-ING-03.md) | Supply Chain Compromise | ✅ | ✅ |
| [`ING-04`](phases/ing/MC-ING-04.md) | Credential Abuse | ✅ | — |
| [`ING-05`](phases/ing/MC-ING-05.md) | Malicious or Compromised USB Devices | ✅ | ✅ |
| [`ING-06`](phases/ing/MC-ING-06.md) | Watering Hole Attacks | ✅ | ✅ |
| [`ING-07`](phases/ing/MC-ING-07.md) | External Remote Services | ✅ | — |
| [`ACT-01`](phases/act/MC-ACT-01.md) | User-Executed Files | ✅ | ✅ |
| [`ACT-02`](phases/act/MC-ACT-02.md) | Script-Based Execution | ✅ | ✅ |
| [`ACT-03`](phases/act/MC-ACT-03.md) | Service-Based Execution | ✅ | — |
| [`ACT-04`](phases/act/MC-ACT-04.md) | DLL Side-Loading or Hijacking | ✅ | ✅ |
| [`ACT-05`](phases/act/MC-ACT-05.md) | WMI-Based Execution | ✅ | — |
| [`ACT-06`](phases/act/MC-ACT-06.md) | Browser Extension Execution | ✅ | ✅ |
| [`ACT-07`](phases/act/MC-ACT-07.md) | Boot / Firmware Execution | ✅ | — |
| [`ANC-01`](phases/anc/MC-ANC-01.md) | Startup & Logon Execution | ✅ | — |
| [`ANC-02`](phases/anc/MC-ANC-02.md) | Scheduled & Triggered Execution | ✅ | — |
| [`ANC-03`](phases/anc/MC-ANC-03.md) | Service & Daemon Persistence | ✅ | — |
| [`ANC-04`](phases/anc/MC-ANC-04.md) | Registry-Based Persistence | ✅ | — |
| [`ANC-05`](phases/anc/MC-ANC-05.md) | Browser-Based Persistence | ✅ | — |
| [`ANC-06`](phases/anc/MC-ANC-06.md) | WMI & Event Subscription Persistence | ✅ | ✅ |
| [`ANC-07`](phases/anc/MC-ANC-07.md) | Fileless & In-Memory Persistence | ✅ | ✅ |
| [`ANC-08`](phases/anc/MC-ANC-08.md) | Boot & Pre-OS Persistence | ✅ | — |
| [`CON-01`](phases/con/MC-CON-01.md) | Obfuscation & Packing | ✅ | ✅ |
| [`CON-02`](phases/con/MC-CON-02.md) | Fileless Malware Execution | ✅ | ✅ |
| [`CON-03`](phases/con/MC-CON-03.md) | Security Tool Tampering | ✅ | ✅ |
| [`CON-04`](phases/con/MC-CON-04.md) | Masquerading & Impersonation | ✅ | ✅ |
| [`CON-05`](phases/con/MC-CON-05.md) | Environment & Sandbox Evasion | ✅ | ✅ |
| [`CON-06`](phases/con/MC-CON-06.md) | Process Injection | ✅ | ✅ |
| [`CON-07`](phases/con/MC-CON-07.md) | Polymorphism & Metamorphism | ✅ | ✅ |
| [`CON-08`](phases/con/MC-CON-08.md) | Log & Artifact Manipulation | ✅ | ✅ |
| [`CON-09`](phases/con/MC-CON-09.md) | Living-off-the-Land for Evasion | ✅ | ✅ |
| [`CON-10`](phases/con/MC-CON-10.md) | Anti-Forensics & Cleanup | ✅ | ✅ |
| [`EXP-01`](phases/exp/MC-EXP-01.md) | Living-off-the-Land Lateral Movement | ✅ | — |
| [`EXP-02`](phases/exp/MC-EXP-02.md) | Credential Reuse & Relay | ✅ | — |
| [`EXP-03`](phases/exp/MC-EXP-03.md) | Pass-the-Hash / Pass-the-Ticket | ✅ | ✅ |
| [`EXP-04`](phases/exp/MC-EXP-04.md) | Remote Service & Protocol Abuse | ✅ | — |
| [`EXP-05`](phases/exp/MC-EXP-05.md) | Network Share Propagation | ✅ | — |
| [`EXP-06`](phases/exp/MC-EXP-06.md) | Worm-like Self-Propagation | ✅ | ✅ |
| [`EXP-07`](phases/exp/MC-EXP-07.md) | Privilege Escalation Across Hosts | ✅ | — |
| [`EXP-08`](phases/exp/MC-EXP-08.md) | Identity & Trust Relationship Abuse | ✅ | ✅ |
| [`EXP-09`](phases/exp/MC-EXP-09.md) | Directory Services Targeting | ✅ | ✅ |
| [`EXP-10`](phases/exp/MC-EXP-10.md) | Cloud & Hybrid Lateral Movement | ✅ | — |
| [`EXT-01`](phases/ext/MC-EXT-01.md) | HTTP / HTTPS Data Exfiltration | ✅ | — |
| [`EXT-02`](phases/ext/MC-EXT-02.md) | DNS Tunneling | ✅ | ✅ |
| [`EXT-03`](phases/ext/MC-EXT-03.md) | Cloud Storage Abuse | ✅ | — |
| [`EXT-04`](phases/ext/MC-EXT-04.md) | Messaging and Social Platform Channels | ✅ | ✅ |
| [`EXT-05`](phases/ext/MC-EXT-05.md) | FTP / SFTP / FTPS Transfer | ✅ | — |
| [`EXT-06`](phases/ext/MC-EXT-06.md) | Tor / Proxy / VPN Anonymization Channels | ✅ | ✅ |
| [`EXT-07`](phases/ext/MC-EXT-07.md) | Encrypted Command-and-Control Channels | ✅ | ✅ |
| [`EXT-08`](phases/ext/MC-EXT-08.md) | Removable Media Data Extraction | ✅ | — |
| [`EXT-09`](phases/ext/MC-EXT-09.md) | Steganographic Data Transfer | ✅ | ✅ |
| [`EXT-10`](phases/ext/MC-EXT-10.md) | Multi-Channel Redundant Exfiltration | ✅ | — |

**Totals:** 52 techniques · 52 KQL queries · 30 YARA rules.

# MalChain Detection Library

Ready-to-use detection content mapped 1:1 to MalChain techniques.

- **KQL** — Microsoft Defender XDR / Microsoft Sentinel Advanced Hunting queries (`detections/kql/`). One query per technique (52 total).
- **YARA** — file/memory signatures for techniques with tangible artifacts (`detections/yara/`, 30 rules). Behavioral/network-only techniques are KQL-only by design.

> These are detection **starting points**. Tune time windows, thresholds and allow-lists to your environment; validate in audit mode before alerting.

## Usage

```bash
# Compile / scan with YARA
yara -w -r detections/yara/CONCEALMENT.yar /path/to/samples
```

Paste any `.kql` block into Defender XDR *Advanced Hunting* or a Sentinel rule.

## Coverage matrix

| Technique | Name | KQL | YARA |
| --------- | ---- | --- | ---- |
| `MC-ING-01` | Removable Media & File Transfer | ✅ | ✅ |
| `MC-ING-02` | Malvertising & Drive-By Downloads | ✅ | ✅ |
| `MC-ING-03` | Supply Chain Compromise | ✅ | ✅ |
| `MC-ING-04` | Credential Abuse | ✅ | — |
| `MC-ING-05` | Malicious or Compromised USB Devices | ✅ | ✅ |
| `MC-ING-06` | Watering Hole Attacks | ✅ | ✅ |
| `MC-ING-07` | External Remote Services | ✅ | — |
| `MC-ACT-01` | User-Executed Files | ✅ | ✅ |
| `MC-ACT-02` | Script-Based Execution | ✅ | ✅ |
| `MC-ACT-03` | Service-Based Execution | ✅ | — |
| `MC-ACT-04` | DLL Side-Loading or Hijacking | ✅ | ✅ |
| `MC-ACT-05` | WMI-Based Execution | ✅ | — |
| `MC-ACT-06` | Browser Extension Execution | ✅ | ✅ |
| `MC-ACT-07` | Boot / Firmware Execution | ✅ | — |
| `MC-ANC-01` | Startup & Logon Execution | ✅ | — |
| `MC-ANC-02` | Scheduled & Triggered Execution | ✅ | — |
| `MC-ANC-03` | Service & Daemon Persistence | ✅ | — |
| `MC-ANC-04` | Registry-Based Persistence | ✅ | — |
| `MC-ANC-05` | Browser-Based Persistence | ✅ | — |
| `MC-ANC-06` | WMI & Event Subscription Persistence | ✅ | ✅ |
| `MC-ANC-07` | Fileless & In-Memory Persistence | ✅ | ✅ |
| `MC-ANC-08` | Boot & Pre-OS Persistence | ✅ | — |
| `MC-CON-01` | Obfuscation & Packing | ✅ | ✅ |
| `MC-CON-02` | Fileless Malware Execution | ✅ | ✅ |
| `MC-CON-03` | Security Tool Tampering | ✅ | ✅ |
| `MC-CON-04` | Masquerading & Impersonation | ✅ | ✅ |
| `MC-CON-05` | Environment & Sandbox Evasion | ✅ | ✅ |
| `MC-CON-06` | Process Injection | ✅ | ✅ |
| `MC-CON-07` | Polymorphism & Metamorphism | ✅ | ✅ |
| `MC-CON-08` | Log & Artifact Manipulation | ✅ | ✅ |
| `MC-CON-09` | Living-off-the-Land for Evasion | ✅ | ✅ |
| `MC-CON-10` | Anti-Forensics & Cleanup | ✅ | ✅ |
| `MC-EXP-01` | Living-off-the-Land Lateral Movement | ✅ | — |
| `MC-EXP-02` | Credential Reuse & Relay | ✅ | — |
| `MC-EXP-03` | Pass-the-Hash / Pass-the-Ticket | ✅ | ✅ |
| `MC-EXP-04` | Remote Service & Protocol Abuse | ✅ | — |
| `MC-EXP-05` | Network Share Propagation | ✅ | — |
| `MC-EXP-06` | Worm-like Self-Propagation | ✅ | ✅ |
| `MC-EXP-07` | Privilege Escalation Across Hosts | ✅ | — |
| `MC-EXP-08` | Identity & Trust Relationship Abuse | ✅ | ✅ |
| `MC-EXP-09` | Directory Services Targeting | ✅ | ✅ |
| `MC-EXP-10` | Cloud & Hybrid Lateral Movement | ✅ | — |
| `MC-EXT-01` | HTTP / HTTPS Data Exfiltration | ✅ | — |
| `MC-EXT-02` | DNS Tunneling | ✅ | ✅ |
| `MC-EXT-03` | Cloud Storage Abuse | ✅ | — |
| `MC-EXT-04` | Messaging and Social Platform Channels | ✅ | ✅ |
| `MC-EXT-05` | FTP / SFTP / FTPS Transfer | ✅ | — |
| `MC-EXT-06` | Tor / Proxy / VPN Anonymization Channels | ✅ | ✅ |
| `MC-EXT-07` | Encrypted Command-and-Control Channels | ✅ | ✅ |
| `MC-EXT-08` | Removable Media Data Extraction | ✅ | — |
| `MC-EXT-09` | Steganographic Data Transfer | ✅ | ✅ |
| `MC-EXT-10` | Multi-Channel Redundant Exfiltration | ✅ | — |

**Totals:** 52 techniques · 52 KQL queries · 30 YARA rules.

_License: MIT. Contributions of additional rules and tuned thresholds welcome._

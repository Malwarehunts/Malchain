# EXP-01 · Living-off-the-Land Lateral Movement

**Phase:** [Expansion](../exp.md) · Lateral Movement  |  **Detections:** KQL

[← Back to Expansion](../exp.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Living-off-the-Land Lateral Movement refers to the use of legitimate administrative tools, system utilities, and built-in management functions to move between systems within a target environment. This includes leveraging trusted protocols, remote execution utilities, and native operating system capabilities to access additional hosts without deploying external malware. Within MalChain, this capability begins once attacker-controlled actions enable movement from one system to another using authorized tools or services. Attackers exploit implicit trust in administrative functionality and network management processes to expand access while maintaining operational stealth. Routine reliance on remote management and automation tools often allows lateral movement activity to blend with normal system operations. Trust abuse may involve executing commands through trusted utilities, reusing administrative sessions, or initiating remote connections presented as routine system maintenance. Common movement methods include:

* Executing commands remotely using administrative tools  
* Accessing remote systems through built-in management utilities  
* Leveraging trusted protocols to initiate system connections  
* Using system credentials to authenticate across hosts  
* Automating remote execution through legitimate utilities  

Real world usage includes:

* Enterprise intrusion campaigns expanding access across network segments  
* Ransomware operators spreading to multiple systems before activation  
* Insider threat scenarios involving unauthorized system access  
* Persistent threats maintaining stealth during network expansion

## Detection Guidance

Detection relies on monitoring remote execution behavior, system connection patterns, and command usage associated with administrative tools. Contextual correlation between legitimate tool usage and unexpected system access is essential to reduce false positives.

* Monitor remote command execution between internal systems  
* Detect unusual authentication attempts across multiple hosts  
* Correlate administrative tool usage with network connection activity  
* Alert on remote access initiated from unexpected systems  
* Identify rare or unauthorized lateral movement patterns

## KQL Detection Concepts

* Remote execution events initiated through administrative utilities  
* Authentication activity involving multiple systems in short intervals  
* Network connection patterns associated with remote management tools

## YARA Detection Concepts

* Scripts or binaries invoking remote execution commands  
* Code patterns automating system-to-system communication  
* Executable components interacting with administrative protocols

## KQL Detection Rule

```kql
// LotL Lateral Movement: remote exec tools launched to another host
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe","psexesvc.exe","wmic.exe","winrs.exe") or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Invoke-Command","New-PSSession","-ComputerName","Enter-PSSession"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Restrict remote administration privileges to authorized users  
* Implement network segmentation and access control policies  
* Monitor usage of administrative tools across the environment  
* Enforce multi-factor authentication for remote access

## Incident Response

* Identify systems involved in lateral movement activity  
* Isolate affected hosts from the network  
* Review authentication and connection logs  
* Analyze command execution history across systems

## Chain Linking

`EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables next:**

- [Credential Reuse & Relay](../exp/MC-EXP-02.md) (`EXP-02`)
- [Privilege Escalation Across Hosts](../exp/MC-EXP-07.md) (`EXP-07`)
- [HTTP / HTTPS Data Exfiltration](../ext/MC-EXT-01.md) (`EXT-01`)

---

[← Anti-Forensics & Cleanup](../con/MC-CON-10.md) | [Credential Reuse & Relay →](../exp/MC-EXP-02.md)

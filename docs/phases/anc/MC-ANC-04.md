# ANC-04 · Registry-Based Persistence

**Phase:** [Anchoring](../anc.md) · Persistence  |  **Detections:** KQL

[← Back to Anchoring](../anc.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Registry-Based Persistence refers to the use of system configuration settings within the operating system registry to maintain attacker-controlled execution across system restarts or user sessions. This includes creating, modifying, or leveraging registry keys that automatically launch programs, scripts, or services during system initialization or user authentication. Within MalChain, this capability begins once registry entries are configured to reliably trigger execution without requiring repeated attacker interaction. Attackers exploit implicit trust in system configuration mechanisms and automated startup behavior to sustain long-term presence. System configuration flexibility and routine administrative changes often allow registry modifications to occur without immediate detection. Trust abuse may involve hidden registry keys, modified execution paths, or configuration entries presented as legitimate system settings. Common persistence methods include:

* Creating registry keys that trigger execution at system startup  
* Modifying existing registry entries to launch malicious programs  
* Configuring autorun or run-once registry settings  
* Registering scripts or executables as system initialization components  
* Using registry entries to redirect execution paths  

Real world usage includes:

* Persistence mechanisms in enterprise intrusion campaigns  
* Automated execution of malware following system reboot  
* Long-term access maintenance in targeted espionage operations  
* Configuration-based persistence in ransomware and surveillance tools

## Detection Guidance

Detection relies on monitoring registry modification events, configuration changes, and execution behavior associated with system startup entries. Contextual correlation between registry changes and subsequent process execution is essential to reduce false positives.

* Monitor creation or modification of registry startup keys  
* Detect changes to execution paths defined in registry settings  
* Correlate registry activity with process launches after reboot  
* Alert on registry entries referencing user-controlled directories  
* Identify rare or unauthorized registry configuration changes

## KQL Detection Concepts

* Registry modification events associated with startup or initialization keys  
* Process execution triggered by recently modified registry entries  
* Registry entries referencing executable files in temporary directories

## YARA Detection Concepts

* Registry configuration patterns associated with persistence mechanisms  
* Scripts or binaries referencing registry autorun keys  
* Executable components designed to modify registry settings

## KQL Detection Rule

```kql
// Registry-Based Persistence: less-common autostart locations
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where RegistryKey has_any (@"\Image File Execution Options", @"\AppInit_DLLs", @"\Userinit", @"\Shell", @"\CurrentVersion\Policies\Explorer\Run")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Restrict permissions to modify critical registry keys  
* Enforce registry change auditing and monitoring policies  
* Monitor startup configuration and execution behavior  
* Implement configuration integrity validation controls

## Incident Response

* Identify newly created or modified registry entries  
* Remove unauthorized registry persistence mechanisms  
* Analyze associated executables or scripts  
* Review system startup and configuration timelines

## Chain Linking

`ANCHORING → Presence Assured → CONCEALMENT`

**Enables next:**

- [Browser-Based Persistence](../anc/MC-ANC-05.md) (`ANC-05`)
- [Log & Artifact Manipulation](../con/MC-CON-08.md) (`CON-08`)
- [Privilege Escalation Across Hosts](../exp/MC-EXP-07.md) (`EXP-07`)

---

[← Service & Daemon Persistence](../anc/MC-ANC-03.md) | [Browser-Based Persistence →](../anc/MC-ANC-05.md)

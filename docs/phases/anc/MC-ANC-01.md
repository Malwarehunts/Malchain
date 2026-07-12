# ANC-01 · Startup & Logon Execution

**Phase:** [Anchoring](../anc.md) · Persistence  |  **Detections:** KQL

[← Back to Anchoring](../anc.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Startup & Logon Execution refers to the automatic execution of attacker-controlled logic when a system starts or a user logs into an environment. This includes configuring programs, scripts, or system components to run during initialization sequences without requiring manual interaction. Within MalChain, this capability begins once execution is reliably triggered by system startup or user authentication events. Attackers exploit implicit trust in routine initialization processes and user session management to maintain consistent execution across system restarts. Operational requirements and automated system behavior often allow startup mechanisms to run without continuous verification. Trust abuse may involve modified startup folders, login scripts, or configuration settings presented as legitimate system components. Common execution methods include:

* Placing executable files in startup directories  
* Modifying login or initialization scripts  
* Configuring applications to run automatically at user logon  
* Altering system startup configuration settings  
* Registering programs to execute during system boot or session start  

Real world usage includes:

* Persistence mechanisms in enterprise malware campaigns  
* Automated execution of surveillance or monitoring tools  
* Ransomware deployment triggered after system restart  
* Long-term system access in targeted intrusion operations

## Detection Guidance

Detection relies on monitoring system initialization behavior, configuration changes, and execution patterns associated with startup or logon events. Contextual correlation between configuration changes and repeated execution activity is essential to reduce false positives.

* Monitor creation or modification of startup configuration entries  
* Detect execution of programs immediately after system startup  
* Correlate login activity with unexpected application launches  
* Alert on changes to initialization scripts or configuration files  
* Identify rare or unauthorized programs executing at session start

## KQL Detection Concepts

* Process execution events occurring immediately after system boot or user logon  
* Configuration changes to startup directories or initialization settings  
* Repeated execution of programs triggered by authentication events

## YARA Detection Concepts

* Files designed to execute automatically during startup sequences  
* Scripts containing initialization or session-triggered logic  
* Executable components referencing startup configuration paths

## KQL Detection Rule

```kql
// Startup & Logon: Run key or Startup-folder persistence created
union
(DeviceRegistryEvents
 | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
 | where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Winlogon")
 | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName),
(DeviceFileEvents
 | where FolderPath has @"\Start Menu\Programs\Startup\"
 | project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName)
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Restrict modification of startup configuration settings  
* Enforce application control for automatically executed programs  
* Monitor system initialization behavior and configuration changes  
* Implement user session management and access control policies

## Incident Response

* Identify startup or logon configuration changes  
* Disable unauthorized automatic execution mechanisms  
* Analyze executed programs and associated configuration files  
* Review authentication and system startup timelines

## Chain Linking

`ANCHORING → Presence Assured → reinforced within ANCHORING`

**Enables next:**

- [Scheduled & Triggered Execution](../anc/MC-ANC-02.md) (`ANC-02`)
- [Registry-Based Persistence](../anc/MC-ANC-04.md) (`ANC-04`)
- [Log & Artifact Manipulation](../con/MC-CON-08.md) (`CON-08`)

---

[← Boot / Firmware Execution](../act/MC-ACT-07.md) | [Scheduled & Triggered Execution →](../anc/MC-ANC-02.md)

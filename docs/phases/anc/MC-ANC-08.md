# ANC-08 · Boot & Pre-OS Persistence

**Phase:** [Anchoring](../anc.md) · Persistence  |  **Detections:** KQL

[← Back to Anchoring](../anc.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Boot & Pre-OS Persistence refers to the maintenance of attacker-controlled execution through components that operate before the operating system fully initializes. This includes modifying boot loaders, firmware configurations, or pre-operating system modules to ensure execution occurs during system startup. Within MalChain, this capability begins once malicious logic is embedded into the boot process and reliably executes prior to standard operating system controls. Attackers exploit implicit trust in system initialization routines and low-level hardware interfaces to maintain persistent access that survives reinstallation or system recovery procedures. System reliability requirements and automated startup behavior often allow boot components to operate with limited inspection. Trust abuse may involve modified boot configurations, unauthorized firmware modules, or hidden startup components presented as legitimate system updates. Common persistence methods include:

* Modifying boot loader or startup configuration files  
* Embedding malicious code within firmware or boot components  
* Replacing legitimate boot modules with altered versions  
* Injecting execution logic into system initialization routines  
* Configuring persistent execution before operating system startup  

Real world usage includes:

* Long-term persistence mechanisms in advanced persistent threat campaigns  
* Stealthy control of systems within critical infrastructure environments  
* Recovery-resistant persistence in targeted espionage operations  
* Firmware-level persistence in high-value enterprise systems

## Detection Guidance

Detection relies on monitoring boot configuration integrity, firmware modification activity, and system startup behavior associated with low-level execution components. Contextual correlation between configuration changes and recurring execution behavior is essential to reduce false positives.

* Monitor boot configuration or firmware modification events  
* Detect unauthorized changes to startup initialization sequences  
* Correlate system startup anomalies with configuration updates  
* Alert on firmware components failing integrity validation checks  
* Identify rare or unexpected boot sequence behavior

## KQL Detection Concepts

* System events indicating modification of boot configuration or firmware settings  
* Startup sequence anomalies associated with pre-operating system components  
* Firmware update activity initiated outside approved maintenance windows

## YARA Detection Concepts

* Firmware images containing unauthorized code segments  
* Boot loader components with modified execution logic  
* Files associated with firmware manipulation utilities

## KQL Detection Rule

```kql
// Boot & Pre-OS Persistence: bootkit / raw disk write tooling
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("bcdedit.exe","bootim.exe","reagentc.exe") and ProcessCommandLine has_any ("set","disable","/set")
    or ProcessCommandLine has_any (@"\.\PhysicalDrive0", "\Device\Harddisk0")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Enforce secure boot and firmware integrity validation  
* Restrict firmware update privileges to authorized administrators  
* Monitor system startup and configuration changes  
* Implement hardware-based security controls and attestation mechanisms

## Incident Response

* Identify systems with modified boot or firmware components  
* Validate firmware integrity against trusted baselines  
* Restore boot configuration from secure sources  
* Review system logs and startup timelines

## Chain Linking

`ANCHORING → Presence Assured → CONCEALMENT`

**Enables next:**

- [Obfuscation & Packing](../con/MC-CON-01.md) (`CON-01`)
- [Environment & Sandbox Evasion](../con/MC-CON-05.md) (`CON-05`)
- [Identity & Trust Relationship Abuse](../exp/MC-EXP-08.md) (`EXP-08`)

---

[← Fileless & In-Memory Persistence](../anc/MC-ANC-07.md) | [Obfuscation & Packing →](../con/MC-CON-01.md)

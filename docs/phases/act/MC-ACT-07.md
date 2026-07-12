# ACT-07 · Boot / Firmware Execution

**Phase:** [Activation](../act.md) · Execution  |  **Detections:** KQL

[← Back to Activation](../act.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Boot or Firmware Execution refers to the execution of attacker-controlled logic during system initialization before the operating system fully loads. This includes modifying boot loaders, firmware components, or pre-operating system configurations to gain persistent and privileged control over a system. Within MalChain, this capability begins once malicious code executes as part of the system startup sequence at the firmware or boot level. Attackers exploit implicit trust in hardware initialization processes and low-level system components to establish execution outside traditional security controls. System reliability requirements and automated startup behavior often allow firmware components to operate without continuous verification. Trust abuse may involve modified firmware images, compromised boot loaders, or unauthorized configuration changes presented as legitimate system updates. Common execution methods include:

* Modifying system firmware or BIOS/UEFI components  
* Replacing or altering boot loader configurations  
* Injecting malicious code into firmware update processes  
* Executing code during system startup initialization  
* Deploying persistent logic in pre-operating system environments  

Real world usage includes:

* Advanced persistent threat operations targeting critical infrastructure  
* Stealthy persistence mechanisms in high-value enterprise systems  
* Supply chain attacks involving compromised hardware or firmware updates  
* Long-term surveillance or control of sensitive computing environments

## Detection Guidance

Detection relies on monitoring firmware integrity, boot configuration changes, and system startup behavior associated with low-level execution components. Contextual correlation between firmware updates and system anomalies is essential to reduce false positives.

* Monitor firmware and boot configuration modification events  
* Detect unauthorized firmware update attempts  
* Correlate system startup anomalies with configuration changes  
* Alert on unexpected boot sequence behavior  
* Identify firmware components failing integrity validation checks

## KQL Detection Concepts

* System events indicating boot configuration or firmware modification  
* Startup sequence anomalies associated with firmware components  
* Firmware update activity initiated outside approved maintenance windows

## YARA Detection Concepts

* Firmware images containing unauthorized code sections  
* Boot loader components with modified execution logic  
* Files associated with firmware manipulation utilities

## KQL Detection Rule

```kql
// Boot / Firmware Execution: bootloader / BCD tampering utilities
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("bcdedit.exe","bootcfg.exe","mountvol.exe") and ProcessCommandLine has_any ("set","/set","testsigning","nointegritychecks")
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

* Identify affected systems and firmware components  
* Validate firmware integrity against trusted baselines  
* Reflash or restore firmware from secure sources  
* Review system logs and update history

## Chain Linking

`ACTIVATION → Code Executing → ANCHORING`

**Enables next:**

- [Startup & Logon Execution](../anc/MC-ANC-01.md) (`ANC-01`)
- [Boot & Pre-OS Persistence](../anc/MC-ANC-08.md) (`ANC-08`)
- [Environment & Sandbox Evasion](../con/MC-CON-05.md) (`CON-05`)

---

[← Browser Extension Execution](../act/MC-ACT-06.md) | [Startup & Logon Execution →](../anc/MC-ANC-01.md)

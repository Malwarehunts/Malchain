# ACT-05 · WMI-Based Execution

**Phase:** [Activation](../act.md) · Execution  |  **Detections:** KQL

[← Back to Activation](../act.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

WMI-Based Execution refers to the use of Windows Management Instrumentation (WMI) to run attacker-controlled commands or scripts within a target environment. This includes invoking remote or local execution through management interfaces designed for administrative automation and system monitoring. Within MalChain, this capability begins once WMI infrastructure is used to initiate execution logic without relying on traditional interactive processes. Attackers exploit implicit trust in system management frameworks and administrative tooling to perform actions that appear consistent with legitimate operations. Administrative flexibility and remote management requirements often allow WMI activity to occur without strict scrutiny. Trust abuse may involve remote command invocation, hidden execution methods, or scheduled management tasks presented as routine system maintenance. Common execution methods include:

* Remote command execution through WMI interfaces  
* Local script execution triggered by management events  
* Automated administrative task execution  
* Hidden execution using WMI process creation mechanisms  
* Distributed execution across multiple systems using WMI  

Real world usage includes:

* Remote administration abuse during lateral movement operations  
* Fileless malware deployment campaigns  
* Enterprise network reconnaissance and command execution  
* Coordinated execution across managed infrastructure

## Detection Guidance

Detection relies on monitoring management interface activity, process creation events, and remote execution behavior associated with WMI operations. Contextual correlation between management actions and system changes is essential to reduce false positives.

* Monitor remote execution requests initiated through management interfaces  
* Detect unusual command execution patterns associated with administrative tools  
* Correlate WMI activity with privilege changes or system modifications  
* Alert on execution initiated from non-administrative user accounts  
* Identify rare or unexpected management operations across systems

## KQL Detection Concepts

* Process creation events initiated through WMI execution mechanisms  
* Remote command execution originating from administrative management services  
* Execution of commands associated with system management interfaces

## YARA Detection Concepts

* Scripts or binaries containing remote management execution routines  
* Code patterns interacting with system management infrastructure  
* Files invoking command execution through management interfaces

## KQL Detection Rule

```kql
// WMI-Based Execution: wmiprvse spawning interpreters (remote/lateral exec)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Restrict remote management permissions to authorized administrators  
* Enforce logging and auditing of management interface activity  
* Monitor remote execution and administrative command usage  
* Implement network segmentation to limit management access

## Incident Response

* Identify systems targeted by management-based execution  
* Collect logs related to management interface activity  
* Analyze commands executed through administrative channels  
* Review authentication and access control events

## Chain Linking

`ACTIVATION → Code Executing → EXPANSION`

**Enables next:**

- [Browser Extension Execution](../act/MC-ACT-06.md) (`ACT-06`)
- [WMI & Event Subscription Persistence](../anc/MC-ANC-06.md) (`ANC-06`)
- [Living-off-the-Land Lateral Movement](../exp/MC-EXP-01.md) (`EXP-01`)

---

[← DLL Side-Loading or Hijacking](../act/MC-ACT-04.md) | [Browser Extension Execution →](../act/MC-ACT-06.md)

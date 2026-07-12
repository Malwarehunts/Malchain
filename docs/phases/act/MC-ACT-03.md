# ACT-03 · Service-Based Execution

**Phase:** [Activation](../act.md) · Execution  |  **Detections:** KQL

[← Back to Activation](../act.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Service-Based Execution refers to the use of system services or background processes to run attacker-controlled logic within a target environment. This includes creating new services, modifying existing service configurations, or leveraging legitimate service management mechanisms to execute commands automatically. Within MalChain, this capability begins once a service is installed, modified, or triggered to execute attacker-defined instructions. Attackers exploit implicit trust in system services and administrative management tools to maintain reliable execution with elevated privileges. Operational necessity and automated system behavior often allow service execution to occur without close inspection. Trust abuse may involve disguised service names, modified startup parameters, or services presented as legitimate maintenance components. Common execution methods include:

* Creating new system services  
* Modifying existing service configurations  
* Executing commands through service management utilities  
* Triggering service-based scheduled operations  
* Installing services with automatic startup behavior  

Real world usage includes:

* Persistence and execution mechanisms in ransomware campaigns  
* Privileged execution in enterprise network compromises  
* Remote service abuse during lateral movement operations  
* Deployment of long-running malware components

## Detection Guidance

Detection relies on monitoring service lifecycle events, configuration changes, and execution behavior associated with system services. Contextual correlation between service creation, modification, and system activity is essential to reduce false positives.

* Monitor creation of new services or daemons  
* Detect modifications to service startup configurations  
* Correlate service execution with administrative account usage  
* Alert on services created from temporary or user-controlled paths  
* Identify rare or unexpected service names or descriptions

## KQL Detection Concepts

* Service installation or configuration change events  
* Service processes launched with unusual command-line parameters  
* Execution of services originating from non-standard directories

## YARA Detection Concepts

* Suspicious service configuration structures or registry entries  
* Service binaries containing persistence or privilege escalation logic  
* Executable files designed to run as background services

## KQL Detection Rule

```kql
// Service-Based Execution: new service created for code execution
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
    or (InitiatingProcessFileName =~ "services.exe" and FileName in~ ("cmd.exe","powershell.exe"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Restrict service creation privileges to authorized administrators  
* Enforce service configuration auditing and change control  
* Monitor service activity and startup behavior  
* Implement application control for service binaries

## Incident Response

* Identify newly created or modified services  
* Disable or remove unauthorized services  
* Analyze service binaries and configuration settings  
* Review system logs for service-related execution timelines

## Chain Linking

`ACTIVATION → Code Executing → ANCHORING`

**Enables next:**

- [DLL Side-Loading or Hijacking](../act/MC-ACT-04.md) (`ACT-04`)
- [Scheduled & Triggered Execution](../anc/MC-ANC-02.md) (`ANC-02`)
- [Service & Daemon Persistence](../anc/MC-ANC-03.md) (`ANC-03`)

---

[← Script-Based Execution](../act/MC-ACT-02.md) | [DLL Side-Loading or Hijacking →](../act/MC-ACT-04.md)

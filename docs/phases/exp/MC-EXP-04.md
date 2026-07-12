# EXP-04 · Remote Service & Protocol Abuse

**Phase:** [Expansion](../exp.md) · Lateral Movement  |  **Detections:** KQL

[← Back to Expansion](../exp.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Remote Service & Protocol Abuse refers to the misuse of legitimate network services and communication protocols to gain access to additional systems within a target environment. This includes leveraging remote management services, file sharing protocols, and administrative interfaces to execute commands or transfer data between hosts. Within MalChain, this capability begins once attacker-controlled activity successfully uses a trusted network service or protocol to initiate access or execution on another system. Attackers exploit implicit trust in standardized communication mechanisms and administrative workflows to expand operational reach while appearing consistent with normal system behavior. Routine reliance on remote connectivity and system administration services often allows misuse to occur without immediate detection. Trust abuse may involve unauthorized remote connections, misuse of administrative protocols, or execution of commands through trusted service channels presented as routine operational activity. Common movement methods include:

* Initiating remote connections using administrative services  
* Executing commands through network management protocols  
* Transferring files using trusted communication channels  
* Accessing systems through remote login interfaces  
* Leveraging built-in services to control remote hosts  

Real world usage includes:

* Enterprise intrusion campaigns expanding access through remote services  
* Ransomware operators deploying payloads across networked systems  
* Insider threat scenarios involving unauthorized remote administration  
* Persistent threats maintaining control through trusted service interfaces

## Detection Guidance

Detection relies on monitoring network connection behavior, service usage patterns, and execution activity associated with remote services. Contextual correlation between service access and system behavior is essential to reduce false positives.

* Monitor remote connection attempts between internal systems  
* Detect execution of commands initiated through remote services  
* Correlate network traffic with unexpected system access  
* Alert on remote sessions initiated outside normal operational hours  
* Identify rare or unauthorized use of administrative protocols

## KQL Detection Concepts

* Network connection events involving remote administration services  
* Process execution initiated through remote protocol sessions  
* Service access patterns inconsistent with normal system behavior

## YARA Detection Concepts

* Scripts or binaries invoking remote service communication routines  
* Code patterns associated with remote command execution  
* Executable components interacting with network service protocols

## KQL Detection Rule

```kql
// Remote Service & Protocol Abuse: remote service creation over the network
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "sc.exe" and ProcessCommandLine has_any (@"\\", "\\") and ProcessCommandLine has "create"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Restrict access to remote services based on role and necessity  
* Implement network segmentation and service access controls  
* Monitor remote session activity and protocol usage  
* Enforce strong authentication for remote connections

## Incident Response

* Identify systems accessed through remote services  
* Terminate unauthorized remote sessions  
* Review network logs and service access history  
* Analyze command execution associated with remote activity

## Chain Linking

`EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables next:**

- [Network Share Propagation](../exp/MC-EXP-05.md) (`EXP-05`)
- [Privilege Escalation Across Hosts](../exp/MC-EXP-07.md) (`EXP-07`)
- [HTTP / HTTPS Data Exfiltration](../ext/MC-EXT-01.md) (`EXT-01`)

---

[← Pass-the-Hash / Pass-the-Ticket](../exp/MC-EXP-03.md) | [Network Share Propagation →](../exp/MC-EXP-05.md)

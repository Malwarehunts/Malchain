# ANC-07 · Fileless & In-Memory Persistence

**Phase:** [Anchoring](../anc.md) · Persistence  |  **Detections:** KQL · YARA

[← Back to Anchoring](../anc.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Fileless & In-Memory Persistence refers to the maintenance of attacker-controlled execution through code that resides primarily in system memory rather than on disk. This includes injecting scripts, commands, or executable logic into running processes or memory regions that are automatically reloaded during system activity. Within MalChain, this capability begins once execution logic is retained in memory or reconstructed during runtime without relying on traditional file storage mechanisms. Attackers exploit implicit trust in legitimate system processes and runtime environments to sustain persistence while minimizing forensic artifacts. Operational reliance on memory-resident processes and dynamic execution behavior often allows malicious activity to remain undetected. Trust abuse may involve encoded payloads, hidden process injections, or memory-based scripts presented as legitimate runtime operations. Common persistence methods include:

* Injecting executable code into running processes  
* Storing scripts or commands within system memory structures  
* Reconstructing payloads dynamically during execution  
* Leveraging legitimate system utilities to reload memory-resident logic  
* Maintaining persistent execution through repeated memory injection events  

Real world usage includes:

* Fileless malware campaigns targeting enterprise environments  
* Persistent command execution without creating disk artifacts  
* Stealthy surveillance operations in high-security systems  
* Long-term persistence mechanisms in advanced intrusion campaigns

## Detection Guidance

Detection relies on monitoring process memory behavior, execution patterns, and runtime anomalies associated with memory-resident code. Contextual correlation between memory activity and recurring execution behavior is essential to reduce false positives.

* Monitor abnormal memory allocation and execution patterns  
* Detect repeated code injection into legitimate processes  
* Correlate memory activity with unexpected process behavior  
* Alert on execution originating from non-file-backed memory regions  
* Identify rare or unauthorized runtime code modifications

## KQL Detection Concepts

* Process behavior indicating execution from memory rather than disk  
* Repeated injection events targeting critical system processes  
* Execution anomalies associated with dynamic memory allocation

## YARA Detection Concepts

* Memory patterns associated with injected shellcode  
* Encoded payload fragments stored in process memory  
* Code structures designed for in-memory execution

## KQL Detection Rule

```kql
// Fileless & In-Memory Persistence: registry blob storing encoded payload
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where strlen(RegistryValueData) > 2048
| where RegistryValueData matches regex @"[A-Za-z0-9+/]{500,}={0,2}"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, DataLen=strlen(RegistryValueData), InitiatingProcessFileName
```

## YARA Detection Rule

```yara
rule MC_ANC_07_Fileless_Registry_Payload_Loader
{
    meta:
        author = "MalChain"
        technique = "MC-ANC-07 Fileless & In-Memory Persistence"
        description = "Loader reading an encoded payload from the registry into memory"
    strings:
        $r1 = "Get-ItemProperty" ascii nocase
        $r2 = "RegOpenKeyEx" ascii
        $b1 = "FromBase64String" ascii nocase
        $m1 = "VirtualAlloc" ascii
        $m2 = "[Reflection.Assembly]::Load" ascii nocase
    condition:
        (1 of ($r*)) and $b1 and (1 of ($m*))
}
```

## Mitigation

* Enforce memory protection and execution control mechanisms  
* Monitor process integrity and runtime behavior  
* Restrict use of utilities capable of dynamic code execution  
* Implement endpoint detection and response monitoring

## Incident Response

* Identify processes exhibiting abnormal memory behavior  
* Capture memory snapshots for forensic analysis  
* Terminate or isolate compromised processes  
* Review execution timelines and runtime activity

## Chain Linking

`ANCHORING → Presence Assured → EXTRACTION`

**Enables next:**

- [Boot & Pre-OS Persistence](../anc/MC-ANC-08.md) (`ANC-08`)
- [Process Injection](../con/MC-CON-06.md) (`CON-06`)
- [Encrypted Command-and-Control Channels](../ext/MC-EXT-07.md) (`EXT-07`)

---

[← WMI & Event Subscription Persistence](../anc/MC-ANC-06.md) | [Boot & Pre-OS Persistence →](../anc/MC-ANC-08.md)

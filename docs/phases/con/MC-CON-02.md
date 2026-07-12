# CON-02 · Fileless Malware Execution

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Fileless Malware Execution refers to the execution of attacker-controlled logic directly in system memory without relying on traditional files stored on disk. This includes the use of scripting engines, legitimate system utilities, or memory injection techniques to run commands dynamically during runtime. Within MalChain, this capability begins once execution occurs without the presence of a persistent file artifact, allowing malicious activity to operate with reduced forensic visibility. Attackers exploit implicit trust in legitimate system processes and runtime environments to perform actions that appear consistent with routine operations. Operational reliance on memory-resident execution and automation tools often allows fileless activity to occur without triggering file-based detection controls. Trust abuse may involve encoded commands, injected scripts, or runtime payloads presented as legitimate administrative actions. Common execution methods include:

* Executing commands directly in system memory  
* Injecting scripts into running processes  
* Leveraging system utilities to execute in-memory payloads  
* Running encoded commands through scripting engines  
* Triggering dynamic execution without creating files on disk  

Real world usage includes:

* Fileless intrusion campaigns targeting enterprise networks  
* Stealthy execution of reconnaissance and data collection tools  
* Memory-based ransomware deployment techniques  
* Advanced persistent threat operations focused on evasion

## Detection Guidance

Detection relies on monitoring runtime behavior, process memory activity, and execution patterns associated with memory-resident code. Contextual correlation between process behavior and system activity is essential to reduce false positives.

* Monitor execution originating from memory rather than disk  
* Detect abnormal process injection or code execution behavior  
* Correlate runtime activity with unexpected system changes  
* Alert on execution of encoded or dynamically generated commands  
* Identify rare or unauthorized process behavior patterns

## KQL Detection Concepts

* Process execution events without associated file creation activity  
* Repeated execution patterns involving memory-resident processes  
* Abnormal command-line activity indicating dynamic execution

## YARA Detection Concepts

* Memory patterns associated with injected shellcode  
* Encoded command sequences within process memory  
* Code structures designed for in-memory execution

## KQL Detection Rule

```kql
// Fileless Execution: interpreter with no file, downloading & running in memory
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("IEX","Invoke-Expression","DownloadString","Reflection.Assembly","[Convert]::FromBase64String","VirtualAlloc")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

## YARA Detection Rule

```yara
rule MC_CON_02_Fileless_Reflective_Loader
{
    meta:
        author = "MalChain"
        technique = "MC-CON-02 Fileless Malware Execution"
        description = "In-memory reflective loading / shellcode allocation primitives"
    strings:
        $a1 = "VirtualAlloc" ascii
        $a2 = "VirtualAllocEx" ascii
        $a3 = "RtlMoveMemory" ascii
        $a4 = "CreateThread" ascii
        $a5 = "[Reflection.Assembly]::Load" ascii nocase
        $a6 = "ReflectiveLoader" ascii
    condition:
        3 of them
}
```

## Mitigation

* Implement behavior-based monitoring and endpoint detection controls  
* Restrict execution privileges for scripting and administrative utilities  
* Monitor process memory integrity and runtime behavior  
* Enforce least-privilege access for system processes

## Incident Response

* Identify processes executing code from memory  
* Capture memory snapshots for forensic analysis  
* Terminate suspicious processes and isolate affected systems  
* Review runtime behavior and execution timelines

## Chain Linking

`CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables next:**

- [Security Tool Tampering](../con/MC-CON-03.md) (`CON-03`)
- [Process Injection](../con/MC-CON-06.md) (`CON-06`)
- [Encrypted Command-and-Control Channels](../ext/MC-EXT-07.md) (`EXT-07`)

---

[← Obfuscation & Packing](../con/MC-CON-01.md) | [Security Tool Tampering →](../con/MC-CON-03.md)

# CON-06 · Process Injection

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Process Injection refers to the insertion of attacker-controlled code into the memory space of a legitimate running process within a target environment. This includes modifying process memory, spawning remote threads, or manipulating execution flow to run malicious logic under the identity of a trusted application. Within MalChain, this capability begins once code is successfully introduced into another process and executed without creating a separate standalone process. Attackers exploit implicit trust in legitimate system processes and security assumptions about running applications to conceal malicious activity. Routine reliance on trusted processes and shared memory operations often allows injected code to execute with reduced visibility. Trust abuse may involve targeting high-privilege system processes, modifying execution contexts, or embedding hidden payloads presented as routine process activity. Common injection methods include:

* Writing malicious code into the memory of a running process  
* Creating remote threads to execute injected payloads  
* Modifying process execution flow or memory structures  
* Leveraging legitimate system utilities to perform injection  
* Using process hollowing or similar memory manipulation techniques  

Real world usage includes:

* Stealthy malware execution within trusted system processes  
* Privilege escalation and persistence in enterprise intrusion campaigns  
* Evasion of endpoint detection systems through hidden execution  
* Deployment of command-and-control logic inside legitimate applications

## Detection Guidance

Detection relies on monitoring memory manipulation behavior, process relationships, and execution anomalies associated with injected code. Contextual correlation between process activity and unexpected memory operations is essential to reduce false positives.

* Monitor processes performing memory write operations to other processes  
* Detect creation of remote threads within legitimate applications  
* Correlate abnormal parent-child process relationships  
* Alert on unexpected execution originating from injected memory regions  
* Identify rare or unauthorized process behavior patterns

## KQL Detection Concepts

* Process events indicating cross-process memory modification  
* Creation of threads in processes not normally associated with execution  
* Execution behavior inconsistent with normal process activity

## YARA Detection Concepts

* Memory patterns associated with injected shellcode  
* Code structures indicating process hollowing or thread injection  
* Executable components designed to manipulate process memory

## KQL Detection Rule

```kql
// Process Injection: cross-process handle open + remote thread indicators
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("CreateRemoteThreadApiCall","WriteToLsassProcessMemory","QueueUserApcRemoteApiCall","SetThreadContextRemoteApiCall")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, FileName, AdditionalFields
```

## YARA Detection Rule

```yara
rule MC_CON_06_Process_Injection_Primitives
{
    meta:
        author = "MalChain"
        technique = "MC-CON-06 Process Injection"
        description = "Classic remote-injection / process-hollowing API set"
    strings:
        $a1 = "OpenProcess" ascii
        $a2 = "VirtualAllocEx" ascii
        $a3 = "WriteProcessMemory" ascii
        $a4 = "CreateRemoteThread" ascii
        $a5 = "NtUnmapViewOfSection" ascii
        $a6 = "SetThreadContext" ascii
        $a7 = "QueueUserAPC" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
```

## Mitigation

* Implement memory protection and application isolation controls  
* Monitor process behavior and inter-process communication  
* Restrict privileges required for memory manipulation operations  
* Deploy endpoint detection and response monitoring solutions

## Incident Response

* Identify processes involved in memory manipulation activity  
* Capture memory snapshots for forensic analysis  
* Terminate compromised processes and isolate affected systems  
* Review execution timelines and system activity

## Chain Linking

`CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables next:**

- [Polymorphism & Metamorphism](../con/MC-CON-07.md) (`CON-07`)
- [Log & Artifact Manipulation](../con/MC-CON-08.md) (`CON-08`)
- [Privilege Escalation Across Hosts](../exp/MC-EXP-07.md) (`EXP-07`)

---

[← Environment & Sandbox Evasion](../con/MC-CON-05.md) | [Polymorphism & Metamorphism →](../con/MC-CON-07.md)

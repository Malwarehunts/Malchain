# CON-05 · Environment & Sandbox Evasion

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Environment & Sandbox Evasion refers to the detection and avoidance of analysis, monitoring, or controlled execution environments by attacker-controlled code within a target system. This includes identifying virtual machines, sandbox environments, debugging tools, or security monitoring systems and altering behavior to prevent detection. Within MalChain, this capability begins once execution logic conditionally modifies its behavior based on environmental indicators that suggest analysis or monitoring is present. Attackers exploit implicit trust in system configuration visibility and runtime detection limitations to delay or prevent defensive response. Operational reliance on automated analysis tools and predictable monitoring patterns often allows evasion techniques to succeed without immediate detection. Trust abuse may involve hidden execution conditions, delayed activation routines, or environment checks presented as normal application logic. Common evasion methods include:

* Detecting virtual machine or sandbox artifacts  
* Checking for debugging or monitoring tools  
* Delaying execution to bypass automated analysis  
* Terminating execution when analysis conditions are detected  
* Modifying behavior based on system configuration checks  

Real world usage includes:

* Malware designed to evade automated sandbox analysis  
* Targeted intrusion campaigns avoiding detection during testing  
* Advanced persistent threat operations using conditional execution logic  
* Ransomware variants delaying activation to bypass monitoring systems

## Detection Guidance

Detection relies on monitoring conditional execution behavior, system environment checks, and runtime anomalies associated with evasion logic. Contextual correlation between execution patterns and environmental conditions is essential to reduce false positives.

* Monitor execution patterns that change based on system configuration  
* Detect processes performing repeated environment or hardware checks  
* Correlate delayed execution with suspicious system activity  
* Alert on programs terminating when monitoring tools are detected  
* Identify rare or unusual system environment queries

## KQL Detection Concepts

* Process behavior indicating conditional execution based on environment checks  
* Repeated queries for system configuration or virtualization indicators  
* Execution delays associated with suspicious runtime behavior

## YARA Detection Concepts

* Code patterns associated with virtualization or debugger detection  
* Scripts containing environment-checking logic  
* Executables performing conditional execution routines

## KQL Detection Rule

```kql
// Sandbox / Environment Evasion: reconnaissance of VM & analysis artifacts
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("vmware","vbox","virtualbox","qemu","sbiedll","wireshark","procmon","Win32_ComputerSystem","NumberOfCores")
| where FileName in~ ("wmic.exe","powershell.exe","reg.exe","cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

```yara
rule MC_CON_05_Sandbox_Evasion_Strings
{
    meta:
        author = "MalChain"
        technique = "MC-CON-05 Environment & Sandbox Evasion"
        description = "Anti-VM / anti-analysis artifact strings"
    strings:
        $v1 = "VBoxGuest" ascii nocase
        $v2 = "vmware" ascii nocase
        $v3 = "vmtoolsd" ascii nocase
        $v4 = "SbieDll.dll" ascii nocase
        $v5 = "QEMU" ascii
        $v6 = "IsDebuggerPresent" ascii
        $v7 = "CheckRemoteDebuggerPresent" ascii
    condition:
        3 of them
}
```

## Mitigation

* Implement behavior-based monitoring and anomaly detection  
* Randomize analysis environment characteristics  
* Monitor execution timing and conditional logic behavior  
* Maintain updated detection rules for evasion techniques

## Incident Response

* Identify processes exhibiting evasion behavior  
* Analyze execution conditions and environment checks  
* Capture runtime activity for forensic review  
* Review system logs and execution timelines

## Chain Linking

`CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables next:**

- [Process Injection](../con/MC-CON-06.md) (`CON-06`)
- [Polymorphism & Metamorphism](../con/MC-CON-07.md) (`CON-07`)
- [Living-off-the-Land Lateral Movement](../exp/MC-EXP-01.md) (`EXP-01`)

---

[← Masquerading & Impersonation](../con/MC-CON-04.md) | [Process Injection →](../con/MC-CON-06.md)

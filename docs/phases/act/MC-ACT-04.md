# ACT-04 · DLL Side-Loading or Hijacking

**Phase:** [Activation](../act.md) · Execution  |  **Detections:** KQL · YARA

[← Back to Activation](../act.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

DLL Side-Loading or Hijacking refers to the execution of attacker-controlled dynamic libraries through the misuse of legitimate application loading behavior. This includes placing malicious libraries in directories searched by trusted programs so that the operating system loads attacker-provided code instead of legitimate components. Within MalChain, this capability begins once a trusted application loads a manipulated or substituted library during execution. Attackers exploit implicit trust in application dependencies and library search order mechanisms to execute code without triggering traditional security controls. Operational reliance on shared libraries and automated loading behavior often allows malicious modules to execute silently. Trust abuse may involve renamed library files, copied application directories, or manipulated software packages presented as legitimate installations. Common execution methods include:

* Placing malicious libraries in application directories  
* Replacing legitimate dependency files with modified versions  
* Loading libraries through portable or relocated applications  
* Executing programs that automatically search local directories for libraries  
* Delivering applications bundled with malicious dependency files  

Real world usage includes:

* Advanced persistent threat operations targeting enterprise software  
* Software supply chain and update manipulation campaigns  
* Stealthy malware deployment within trusted applications  
* Evasion of application whitelisting and security monitoring controls

## Detection Guidance

Detection relies on monitoring module load events, application behavior, and file integrity changes associated with library dependencies. Contextual correlation between application execution and unexpected library loading activity is essential to reduce false positives.

* Monitor library load events from non-standard directories  
* Detect execution of applications loading unsigned or unknown modules  
* Correlate application launches with recent file creation events  
* Alert on duplicate library names located in unexpected paths  
* Identify applications executing from temporary or user-controlled locations

## KQL Detection Concepts

* Module load events referencing libraries outside trusted system directories  
* Application processes loading unsigned or newly created DLL files  
* Execution of portable applications from user-writable locations

## YARA Detection Concepts

* Suspicious library export tables or abnormal function mappings  
* Libraries containing embedded shellcode or execution routines  
* Files masquerading as legitimate dependency modules

## KQL Detection Rule

```kql
// DLL Side-Loading: signed app loading an unsigned DLL from its own directory
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath !startswith "C:\\Windows"
| where FolderPath =~ InitiatingProcessFolderPath
| where isempty(Signer) or SignatureStatus != "Valid"
| where FileName endswith ".dll"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SignatureStatus
```

## YARA Detection Rule

```yara
rule MC_ACT_04_DLL_SideLoad_Proxy
{
    meta:
        author = "MalChain"
        technique = "MC-ACT-04 DLL Side-Loading or Hijacking"
        description = "Proxy DLL exporting forwarders plus payload staging APIs"
    strings:
        $e1 = "LoadLibraryA" ascii
        $e2 = "GetProcAddress" ascii
        $f1 = ".dll" ascii nocase
        $a1 = "VirtualProtect" ascii
        $a2 = "CreateThread" ascii
    condition:
        uint16(0) == 0x5A4D and $e1 and $e2 and $f1 and 1 of ($a*)
}
```

## Mitigation

* Enforce application and library integrity validation  
* Restrict execution from untrusted directories  
* Implement code signing and dependency verification controls  
* Monitor application installation and update processes

## Incident Response

* Identify the application responsible for loading the malicious library  
* Isolate affected systems from the network  
* Collect and analyze suspicious library files  
* Review execution timelines and dependency changes

## Chain Linking

`ACTIVATION → Code Executing → CONCEALMENT`

**Enables next:**

- [WMI-Based Execution](../act/MC-ACT-05.md) (`ACT-05`)
- [Registry-Based Persistence](../anc/MC-ANC-04.md) (`ANC-04`)
- [Process Injection](../con/MC-CON-06.md) (`CON-06`)

---

[← Service-Based Execution](../act/MC-ACT-03.md) | [WMI-Based Execution →](../act/MC-ACT-05.md)

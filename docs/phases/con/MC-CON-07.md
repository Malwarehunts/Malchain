# CON-07 · Polymorphism & Metamorphism

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Polymorphism & Metamorphism refers to the continuous modification of attacker-controlled code to evade detection mechanisms within a target environment. This includes dynamically changing code structure, encryption keys, or instruction sequences while preserving the original functionality of the malicious logic. Within MalChain, this capability begins once code is automatically altered to produce new variants that avoid signature-based detection or analysis. Attackers exploit implicit trust in static detection mechanisms and predictable pattern recognition systems to maintain stealth and operational persistence. Routine reliance on known signatures and consistent file structures often allows modified code to bypass defensive controls. Trust abuse may involve encrypted payloads, randomized execution routines, or self-modifying code presented as normal software behavior. Common evasion methods include:

* Automatically generating new variants of executable code  
* Encrypting payloads with changing keys  
* Rewriting instruction sequences during execution  
* Modifying file structure while preserving functionality  
* Using self-modifying or dynamically generated code  

Real world usage includes:

* Malware families designed to evade signature-based detection systems  
* Ransomware campaigns using continuously changing payload variants  
* Persistent threats adapting code to bypass updated security controls  
* Automated malware distribution systems generating unique samples

## Detection Guidance

Detection relies on monitoring behavioral consistency, code transformation patterns, and execution anomalies associated with dynamically changing software. Contextual correlation between repeated activity and variable code signatures is essential to reduce false positives.

* Monitor files that repeatedly change structure without functional changes  
* Detect execution behavior consistent across multiple unique file hashes  
* Correlate file creation events with rapidly changing binary characteristics  
* Alert on processes generating new executable variants  
* Identify rare or unusual patterns of code transformation

## KQL Detection Concepts

* Multiple executable files created with similar behavior but different hashes  
* Repeated process execution associated with dynamically generated files  
* File modification events indicating frequent structural changes

## YARA Detection Concepts

* Code patterns associated with self-modifying logic  
* Executables containing dynamic encryption or decryption routines  
* File structures designed to change during execution

## KQL Detection Rule

```kql
// Polymorphism/Metamorphism: many distinct hashes, same filename across fleet
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType == "FileCreated"
| summarize DistinctHashes=dcount(SHA256), Hosts=dcount(DeviceName) by FileName
| where DistinctHashes > 10 and Hosts > 3
| project FileName, DistinctHashes, Hosts
```

## YARA Detection Rule

```yara
rule MC_CON_07_Polymorphic_Loader
{
    meta:
        author = "MalChain"
        technique = "MC-CON-07 Polymorphism & Metamorphism"
        description = "Self-modifying / runtime-decrypting loader primitives"
    strings:
        $a1 = "VirtualProtect" ascii
        $a2 = "WriteProcessMemory" ascii
        $x1 = { 33 ?? 88 ?? ?? 40 }        // xor/store/inc decrypt-loop shape
        $x2 = { 80 34 ?? ?? 40 3B }        // xor byte ptr [reg+key]; inc; cmp
    condition:
        uint16(0) == 0x5A4D and 1 of ($a*) and 1 of ($x*)
}
```

## Mitigation

* Implement behavior-based detection and anomaly monitoring  
* Use reputation and integrity validation systems  
* Monitor repeated file generation or transformation activity  
* Maintain updated detection rules for evolving threats

## Incident Response

* Identify processes generating modified code variants  
* Collect and analyze multiple file samples for comparison  
* Isolate affected systems to prevent propagation  
* Review execution timelines and transformation patterns

## Chain Linking

`CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables next:**

- [Log & Artifact Manipulation](../con/MC-CON-08.md) (`CON-08`)
- [Anti-Forensics & Cleanup](../con/MC-CON-10.md) (`CON-10`)
- [Multi-Channel Redundant Exfiltration](../ext/MC-EXT-10.md) (`EXT-10`)

---

[← Process Injection](../con/MC-CON-06.md) | [Log & Artifact Manipulation →](../con/MC-CON-08.md)

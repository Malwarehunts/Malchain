# CON-10 · Anti-Forensics & Cleanup

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Anti-Forensics & Cleanup refers to the deliberate removal, alteration, or concealment of artifacts that could reveal attacker presence or activity within a target environment. This includes deleting temporary files, clearing command histories, removing tools after execution, and restoring system configurations to their original state to reduce evidence of compromise. Within MalChain, this capability begins once attacker-controlled processes initiate actions specifically intended to obscure investigative visibility or delay forensic analysis. Attackers exploit implicit trust in routine system maintenance and cleanup operations to perform evidence removal without immediate suspicion. Regular system housekeeping activities and automated maintenance routines often allow cleanup actions to occur without raising alerts. Trust abuse may involve scheduled cleanup scripts, temporary file deletion routines, or system reset operations presented as legitimate maintenance tasks. Common cleanup methods include:

* Deleting temporary files or execution artifacts  
* Clearing command-line or application history logs  
* Removing tools and scripts after use  
* Resetting system configuration settings to default values  
* Overwriting files to prevent data recovery  

Real world usage includes:

* Intrusion campaigns attempting to erase evidence after data exfiltration  
* Ransomware operators removing staging tools before encryption  
* Insider threat scenarios involving deliberate record destruction  
* Persistent threats minimizing forensic traceability

## Detection Guidance

Detection relies on monitoring file deletion behavior, system cleanup activity, and execution patterns associated with artifact removal. Contextual correlation between cleanup actions and suspicious system behavior is essential to reduce false positives.

* Monitor deletion of files immediately following execution events  
* Detect clearing of command histories or application logs  
* Correlate cleanup activity with unexpected system state changes  
* Alert on repeated deletion of temporary or system files  
* Identify rare or unauthorized cleanup operations

## KQL Detection Concepts

* File deletion events occurring shortly after execution activity  
* Commands associated with clearing system or application histories  
* Repeated file removal patterns across multiple systems

## YARA Detection Concepts

* Scripts or binaries designed to delete artifacts or logs  
* Code patterns associated with file wiping or overwriting routines  
* Executable components invoking cleanup or reset operations

## KQL Detection Rule

```kql
// Anti-Forensics: shadow copy deletion & timestomping
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("vssadmin delete shadows","wmic shadowcopy delete","Delete-VssShadow","fsutil usn deletejournal","bcdedit /set {default} recoveryenabled no","wbadmin delete catalog")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

```yara
rule MC_CON_10_AntiForensics_Cleanup
{
    meta:
        author = "MalChain"
        technique = "MC-CON-10 Anti-Forensics & Cleanup"
        description = "Shadow copy deletion / recovery disabling / journal wipe"
    strings:
        $a = "vssadmin delete shadows" ascii nocase
        $b = "wmic shadowcopy delete" ascii nocase
        $c = "wbadmin delete catalog" ascii nocase
        $d = "fsutil usn deletejournal" ascii nocase
        $e = "recoveryenabled no" ascii nocase
    condition:
        1 of them
}
```

## Mitigation

* Enforce logging and retention policies for critical system data  
* Monitor file deletion and cleanup activity across endpoints  
* Restrict execution privileges for cleanup utilities  
* Maintain secure backups and forensic snapshots

## Incident Response

* Identify systems where cleanup activity occurred  
* Preserve remaining artifacts and system state  
* Analyze deletion patterns and associated execution timelines  
* Restore affected systems from trusted backups if necessary

## Chain Linking

`CONCEALMENT → Visibility Degraded → EXTRACTION`

**Enables next:**

- [Living-off-the-Land Lateral Movement](../exp/MC-EXP-01.md) (`EXP-01`)
- [Multi-Channel Redundant Exfiltration](../ext/MC-EXT-10.md) (`EXT-10`)
- [Log & Artifact Manipulation](../con/MC-CON-08.md) (`CON-08`)

---

[← Living-off-the-Land for Evasion](../con/MC-CON-09.md) | [Living-off-the-Land Lateral Movement →](../exp/MC-EXP-01.md)

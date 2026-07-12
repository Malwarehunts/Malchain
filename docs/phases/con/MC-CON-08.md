# CON-08 · Log & Artifact Manipulation

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Log & Artifact Manipulation refers to the deliberate modification, deletion, or suppression of system records and forensic evidence within a target environment to conceal attacker activity. This includes altering log files, clearing event histories, modifying timestamps, or disabling logging mechanisms to prevent accurate detection and investigation. Within MalChain, this capability begins once system-generated records or artifacts are intentionally changed in a way that obscures the true sequence of events. Attackers exploit implicit trust in system logging and recordkeeping processes to disrupt visibility and delay incident response. Routine reliance on automated logging systems and centralized monitoring often allows manipulated records to persist unnoticed. Trust abuse may involve deleting log entries, overwriting system records, or disabling logging services presented as legitimate maintenance actions. Common manipulation methods include:

* Deleting or clearing system event logs  
* Modifying timestamps associated with files or processes  
* Disabling or reconfiguring logging mechanisms  
* Overwriting log records with fabricated data  
* Removing temporary files or execution artifacts  

Real world usage includes:

* Intrusion campaigns attempting to erase evidence of unauthorized access  
* Ransomware operations hiding execution traces before encryption  
* Insider threat activities modifying records to conceal actions  
* Persistent threats delaying forensic investigation through record manipulation

## Detection Guidance

Detection relies on monitoring log integrity, system record changes, and execution patterns associated with logging behavior. Contextual correlation between missing records and suspicious system activity is essential to reduce false positives.

* Monitor deletion or modification of system log files  
* Detect sudden gaps in logging activity or event sequences  
* Correlate timestamp inconsistencies with system behavior  
* Alert on changes to logging configuration settings  
* Identify rare or unauthorized log management actions

## KQL Detection Concepts

* Events indicating log file deletion or clearing activity  
* Changes to logging configuration or audit policy settings  
* Sudden absence of expected system log events

## YARA Detection Concepts

* Scripts or binaries designed to manipulate log files  
* Code patterns associated with timestamp modification routines  
* Executable components interacting with logging mechanisms

## KQL Detection Rule

```kql
// Log & Artifact Manipulation: event-log clearing
union
(DeviceProcessEvents
 | where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl ","clear-log"))
     or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Clear-EventLog")
 | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine),
(DeviceEvents | where ActionType == "SecurityLogCleared" | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName)
```

## YARA Detection Rule

```yara
rule MC_CON_08_Log_Manipulation
{
    meta:
        author = "MalChain"
        technique = "MC-CON-08 Log & Artifact Manipulation"
        description = "Event log clearing / tampering commands"
    strings:
        $a = "wevtutil cl" ascii nocase
        $b = "Clear-EventLog" ascii nocase
        $c = "wevtutil clear-log" ascii nocase
        $d = "Remove-EventLog" ascii nocase
    condition:
        1 of them
}
```

## Mitigation

* Enforce log integrity validation and retention policies  
* Implement centralized and tamper-resistant logging systems  
* Monitor configuration changes affecting logging behavior  
* Maintain secure backups of critical system records

## Incident Response

* Identify systems with altered or missing log records  
* Restore logs from trusted backups if available  
* Analyze system activity surrounding log modification events  
* Review execution timelines for inconsistencies

## Chain Linking

`CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables next:**

- [Living-off-the-Land for Evasion](../con/MC-CON-09.md) (`CON-09`)
- [Anti-Forensics & Cleanup](../con/MC-CON-10.md) (`CON-10`)
- [Multi-Channel Redundant Exfiltration](../ext/MC-EXT-10.md) (`EXT-10`)

---

[← Polymorphism & Metamorphism](../con/MC-CON-07.md) | [Living-off-the-Land for Evasion →](../con/MC-CON-09.md)

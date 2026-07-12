# ANC-02 · Scheduled & Triggered Execution

**Phase:** [Anchoring](../anc.md) · Persistence  |  **Detections:** KQL

[← Back to Anchoring](../anc.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Scheduled & Triggered Execution refers to the automatic execution of attacker-controlled logic based on predefined schedules or system events within a target environment. This includes configuring tasks, timers, or event-driven mechanisms that initiate execution without direct user interaction. Within MalChain, this capability begins once a task or trigger reliably initiates execution according to defined conditions or timing intervals. Attackers exploit implicit trust in automation systems and maintenance routines to maintain consistent execution while reducing visibility. Operational efficiency and system management requirements often allow scheduled operations to run without continuous inspection. Trust abuse may involve disguised maintenance tasks, hidden triggers, or automated routines presented as legitimate administrative processes. Common execution methods include:

* Creating scheduled tasks with recurring execution intervals  
* Configuring event-based triggers to launch programs or scripts  
* Scheduling commands to run during system maintenance windows  
* Registering automated jobs to execute at system startup or shutdown  
* Using timers or task schedulers to initiate background processes  

Real world usage includes:

* Persistence mechanisms in enterprise intrusion campaigns  
* Automated execution of malware during off-peak hours  
* Coordinated deployment of ransomware or data collection tools  
* Remote administration abuse for recurring command execution

## Detection Guidance

Detection relies on monitoring task scheduling systems, trigger configuration changes, and execution patterns associated with automated routines. Contextual correlation between new task creation and repeated execution behavior is essential to reduce false positives.

* Monitor creation or modification of scheduled tasks  
* Detect execution of programs triggered by system events  
* Correlate task scheduling changes with administrative activity  
* Alert on tasks configured to run from user-controlled directories  
* Identify rare or unauthorized automated job configurations

## KQL Detection Concepts

* Task creation or modification events within scheduling systems  
* Execution of programs initiated by scheduled or event-based triggers  
* Repeated task execution occurring at unusual times or intervals

## YARA Detection Concepts

* Task configuration files containing suspicious execution logic  
* Scripts designed to run automatically on schedule  
* Executable components associated with automated task triggers

## KQL Detection Rule

```kql
// Scheduled & Triggered: task created via schtasks/PowerShell with suspicious action
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "schtasks.exe" and ProcessCommandLine has "/create")
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Register-ScheduledTask")
| where ProcessCommandLine has_any ("powershell","cmd","mshta","rundll32","http","AppData","Temp")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Restrict permissions to create or modify scheduled tasks  
* Enforce task configuration auditing and approval workflows  
* Monitor automated job execution and scheduling behavior  
* Implement role-based access controls for task management systems

## Incident Response

* Identify newly created or modified scheduled tasks  
* Disable unauthorized automated execution mechanisms  
* Analyze task configuration and associated executable files  
* Review execution history and scheduling timelines

## Chain Linking

`ANCHORING → Presence Assured → reinforced within ANCHORING`

**Enables next:**

- [Service & Daemon Persistence](../anc/MC-ANC-03.md) (`ANC-03`)
- [Registry-Based Persistence](../anc/MC-ANC-04.md) (`ANC-04`)
- [Log & Artifact Manipulation](../con/MC-CON-08.md) (`CON-08`)

---

[← Startup & Logon Execution](../anc/MC-ANC-01.md) | [Service & Daemon Persistence →](../anc/MC-ANC-03.md)

# CON-03 · Security Tool Tampering

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Security Tool Tampering refers to the deliberate modification, disabling, or bypassing of defensive mechanisms designed to detect or prevent malicious activity within a target environment. This includes interfering with antivirus software, endpoint protection agents, logging systems, or monitoring services to reduce visibility and delay detection. Within MalChain, this capability begins once a security control is altered or suppressed in a way that allows attacker activity to proceed with reduced resistance. Attackers exploit implicit trust in system configuration privileges and administrative tools to manipulate protective mechanisms that rely on continuous operation. Operational dependencies on automated protection services often allow changes to occur without immediate validation. Trust abuse may involve disabling monitoring components, modifying configuration settings, or stopping protective services presented as legitimate maintenance actions. Common tampering methods include:

* Disabling or stopping security services or monitoring agents  
* Modifying security configuration settings or policies  
* Uninstalling or bypassing protective software components  
* Blocking security updates or signature downloads  
* Altering logging or alerting mechanisms  

Real world usage includes:

* Ransomware campaigns disabling endpoint protection before encryption  
* Intrusion operations suppressing detection tools during lateral movement  
* Malware attempting to evade antivirus or endpoint detection systems  
* Persistent threats maintaining stealth by weakening security controls

## Detection Guidance

Detection relies on monitoring configuration changes, service status events, and execution patterns associated with security tools. Contextual correlation between security control modification and subsequent suspicious activity is essential to reduce false positives.

* Monitor stopping or disabling of security-related services  
* Detect changes to protection policies or configuration settings  
* Correlate security tool status changes with unusual system behavior  
* Alert on removal or modification of monitoring agents  
* Identify rare or unauthorized changes to defensive controls

## KQL Detection Concepts

* Service state changes involving security or monitoring components  
* Configuration modifications affecting security tool functionality  
* Execution of commands associated with disabling protection mechanisms

## YARA Detection Concepts

* Scripts or binaries designed to disable security services  
* Code patterns interacting with monitoring or protection components  
* Files containing commands intended to bypass defensive controls

## KQL Detection Rule

```kql
// Security Tool Tampering: defender / EDR service or exclusion manipulation
union
(DeviceProcessEvents
 | where ProcessCommandLine has_any ("Set-MpPreference","DisableRealtimeMonitoring","Add-MpPreference -ExclusionPath","sc stop","net stop") and ProcessCommandLine has_any ("defender","sense","windefend","MsMpEng","exclusion")
 | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine),
(DeviceRegistryEvents
 | where RegistryKey has @"\Windows Defender" and RegistryValueName in ("DisableAntiSpyware","DisableRealtimeMonitoring")
 | project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName)
```

## YARA Detection Rule

```yara
rule MC_CON_03_Security_Tool_Tampering
{
    meta:
        author = "MalChain"
        technique = "MC-CON-03 Security Tool Tampering"
        description = "Commands disabling AV/EDR or adding exclusions"
    strings:
        $a = "Set-MpPreference" ascii nocase
        $b = "DisableRealtimeMonitoring" ascii nocase
        $c = "Add-MpPreference -ExclusionPath" ascii nocase
        $d = "sc stop WinDefend" ascii nocase
        $e = "DisableAntiSpyware" ascii nocase
    condition:
        1 of them
}
```

## Mitigation

* Restrict administrative privileges required to modify security controls  
* Enforce tamper protection and configuration integrity policies  
* Monitor security tool health and operational status continuously  
* Implement centralized logging and alerting mechanisms

## Incident Response

* Identify affected security controls and configuration changes  
* Restore protection services and monitoring components  
* Analyze system activity during periods of reduced visibility  
* Review logs and configuration history for unauthorized modifications

## Chain Linking

`CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables next:**

- [Masquerading & Impersonation](../con/MC-CON-04.md) (`CON-04`)
- [Log & Artifact Manipulation](../con/MC-CON-08.md) (`CON-08`)
- [Privilege Escalation Across Hosts](../exp/MC-EXP-07.md) (`EXP-07`)

---

[← Fileless Malware Execution](../con/MC-CON-02.md) | [Masquerading & Impersonation →](../con/MC-CON-04.md)

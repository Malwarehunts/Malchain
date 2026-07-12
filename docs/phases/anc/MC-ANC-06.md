# ANC-06 · WMI & Event Subscription Persistence

**Phase:** [Anchoring](../anc.md) · Persistence  |  **Detections:** KQL · YARA

[← Back to Anchoring](../anc.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

WMI & Event Subscription Persistence refers to the use of Windows Management Instrumentation (WMI) event mechanisms to maintain attacker-controlled execution based on system conditions or triggers. This includes creating persistent event subscriptions that automatically execute commands or scripts when predefined system events occur. Within MalChain, this capability begins once an event subscription is configured to reliably trigger execution without requiring direct user interaction. Attackers exploit implicit trust in system management infrastructure and automated monitoring frameworks to maintain covert and resilient persistence. Administrative automation and event-driven system behavior often allow these mechanisms to operate with minimal visibility. Trust abuse may involve hidden event filters, modified subscription handlers, or execution routines presented as legitimate system monitoring tasks. Common persistence methods include:

* Creating persistent WMI event subscriptions tied to system events  
* Configuring event filters that trigger script or command execution  
* Registering command-line handlers for system state changes  
* Deploying hidden monitoring routines using management infrastructure  
* Using event-driven execution to maintain recurring system access  

Real world usage includes:

* Fileless persistence mechanisms in enterprise intrusion campaigns  
* Stealthy command execution triggered by system activity  
* Long-term access maintenance in targeted espionage operations  
* Automated re-entry mechanisms following system restart or user login

## Detection Guidance

Detection relies on monitoring management infrastructure changes, event subscription configuration activity, and execution behavior associated with automated triggers. Contextual correlation between subscription creation and recurring execution behavior is essential to reduce false positives.

* Monitor creation or modification of WMI event subscriptions  
* Detect execution triggered by system events without user interaction  
* Correlate management infrastructure activity with repeated execution patterns  
* Alert on hidden or unauthorized event subscription configurations  
* Identify rare or unexpected command execution triggered by system conditions

## KQL Detection Concepts

* Event subscription creation or modification recorded in system logs  
* Execution of commands associated with management event triggers  
* Repeated execution patterns initiated by system monitoring mechanisms

## YARA Detection Concepts

* Scripts or binaries designed to create persistent event subscriptions  
* Code patterns interacting with system management infrastructure  
* Files containing event-driven execution logic

## KQL Detection Rule

```kql
// WMI Event Subscription Persistence: permanent consumer/binding creation
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("__EventFilter","CommandLineEventConsumer","ActiveScriptEventConsumer","__FilterToConsumerBinding","root\subscription")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

```yara
rule MC_ANC_06_WMI_Event_Consumer
{
    meta:
        author = "MalChain"
        technique = "MC-ANC-06 WMI & Event Subscription Persistence"
        description = "Script creating permanent WMI event subscription persistence"
    strings:
        $a = "__EventFilter" ascii nocase
        $b = "CommandLineEventConsumer" ascii nocase
        $c = "ActiveScriptEventConsumer" ascii nocase
        $d = "__FilterToConsumerBinding" ascii nocase
        $e = "root\\subscription" ascii nocase
    condition:
        2 of them
}
```

## Mitigation

* Restrict permissions to create or modify event subscriptions  
* Enforce auditing and monitoring of management infrastructure activity  
* Monitor automated execution triggered by system events  
* Implement role-based access controls for management interfaces

## Incident Response

* Identify newly created or modified event subscriptions  
* Remove unauthorized event-driven execution mechanisms  
* Analyze associated scripts or command handlers  
* Review system logs and execution timelines

## Chain Linking

`ANCHORING → Presence Assured → CONCEALMENT`

**Enables next:**

- [Fileless & In-Memory Persistence](../anc/MC-ANC-07.md) (`ANC-07`)
- [Log & Artifact Manipulation](../con/MC-CON-08.md) (`CON-08`)
- [Living-off-the-Land Lateral Movement](../exp/MC-EXP-01.md) (`EXP-01`)

---

[← Browser-Based Persistence](../anc/MC-ANC-05.md) | [Fileless & In-Memory Persistence →](../anc/MC-ANC-07.md)

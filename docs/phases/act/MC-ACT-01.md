# ACT-01 · User-Executed Files

**Phase:** [Activation](../act.md) · Execution  |  **Detections:** KQL · YARA

[← Back to Activation](../act.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

User-Executed Files refers to the execution of attacker-controlled content initiated directly by a user action within a target environment. This includes opening attachments, launching downloaded files, running shared utilities, or executing documents containing embedded code. Within MalChain, this capability begins once delivered content is intentionally or unintentionally executed by a user. Attackers exploit implicit trust in familiar file formats and routine operational workflows. Curiosity, urgency, and perceived legitimacy often override security warnings or established procedures. Trust abuse may involve renamed executables, document icons, or files presented as required tools or updates. Common execution methods include:

* Opening email attachments
* Launching downloaded files
* Running shared utilities or installers
* Executing files from network locations
* Double-clicking disguised executable files

Real world usage includes:

* Phishing and spear-phishing campaigns
* Initial malware deployment in enterprise environments
* Business email compromise operations
* Commodity malware infections through user interaction

## Detection Guidance

Detection relies on monitoring process creation events, user interaction telemetry, and execution patterns associated with newly introduced files. Contextual correlation between file origin and execution behavior is essential to reduce false positives.

* Monitor process launches initiated by user sessions
* Detect execution of files from temporary or download locations
* Correlate email attachment access with process execution
* Alert on execution of files with uncommon extensions
* Identify rare or newly introduced applications executed by users

## KQL Detection Concepts

* Process execution events initiated by user context
* Executable launches from Downloads or Temp directories
* File execution immediately following email attachment access

## YARA Detection Concepts

* Suspicious executable headers or embedded payload indicators
* Document files containing macro or script logic
* Files with mismatched file extension and content type

## KQL Detection Rule

```kql
// User-Executed Files: process launched from Downloads/Temp by a user session
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\Temp\", @"\Users\Public\")
| where InitiatingProcessFileName in~ ("explorer.exe","outlook.exe","winrar.exe","7zFM.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine, SHA256
```

## YARA Detection Rule

```yara
rule MC_ACT_01_Office_Macro_Executor
{
    meta:
        author = "MalChain"
        technique = "MC-ACT-01 User-Executed Files"
        description = "Office document with auto-exec VBA spawning a shell"
    strings:
        $a1 = "AutoOpen" ascii nocase
        $a2 = "Document_Open" ascii nocase
        $a3 = "Auto_Open" ascii nocase
        $s1 = "Shell(" ascii nocase
        $s2 = "WScript.Shell" ascii nocase
        $s3 = "CreateObject" ascii nocase
    condition:
        1 of ($a*) and 1 of ($s*)
}
```

## Mitigation

* Implement application control and execution policies
* Restrict execution from user-writable directories
* Enforce attachment and download scanning controls
* Educate users on recognizing suspicious files

## Incident Response

* Identify the executed file and associated processes
* Isolate affected systems from the network
* Collect and analyze execution artifacts
* Review user activity and execution timeline

## Chain Linking

`ACTIVATION → Code Executing → reinforced within ACTIVATION`

**Enables next:**

- [Script-Based Execution](../act/MC-ACT-02.md) (`ACT-02`)
- [DLL Side-Loading or Hijacking](../act/MC-ACT-04.md) (`ACT-04`)
- [Startup & Logon Execution](../anc/MC-ANC-01.md) (`ANC-01`)

---

[← External Remote Services](../ing/MC-ING-07.md) | [Script-Based Execution →](../act/MC-ACT-02.md)

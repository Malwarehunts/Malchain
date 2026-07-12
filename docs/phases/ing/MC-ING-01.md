# ING-01 · Removable Media & File Transfer

**Phase:** [Ingress](../ing.md) · Initial Access  |  **Detections:** KQL · YARA

[← Back to Ingress](../ing.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Removable Media & File Transfer refers to the introduction of attacker-controlled content into a target environment via portable storage devices or ad-hoc file transfer methods. This includes USB drives, external hard disks, shared folders, peer-to-peer transfers, and informal file exchange channels. Within MalChain, this capability ends once content is delivered and an execution opportunity exists. Attackers exploit implicit trust in physical media and informal file sharing. Human curiosity, convenience, and operational pressure often bypass security controls. Trust abuse may involve labeled media, disguised documents, or files presented as legitimate tools. Common delivery methods include:

*   USB flash drives
*   External HDDs or SSDs
*   Network shares
*   Email-based file transfer
*   Ad-hoc cloud sharing links

Real world usage includes:

*   Targeted espionage campaigns
*   Industrial control system attacks
*   Air-gapped environment breaches
*   Opportunistic malware spread

## Detection Guidance

Detection relies on monitoring device connection events, file creation telemetry, and abnormal execution patterns originating from removable media. Contextual correlation is essential to reduce false positives.

*   Monitor removable media mount events
*   Detect executable creation on external drives
*   Correlate file access with execution attempts
*   Alert on shortcut execution from removable paths
*   Identify rare file types transferred via media

## KQL Detection Concepts

*   File creation events where DriveType is Removable
*   Process execution originating from removable volumes
*   LNK execution referencing external media paths

## YARA Detection Concepts

*   Malicious LNK structures
*   Embedded payloads in documents
*   Auto-execution logic

## KQL Detection Rule

```kql
// Removable Media: execution or executable drop from removable drives
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessAccountName != "system"
| where FolderPath matches regex @"^[D-Z]:\\" and (FileName endswith ".exe" or FileName endswith ".lnk" or FileName endswith ".scr" or FileName == "autorun.inf")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, SHA256
| join kind=leftouter (
    DeviceProcessEvents | where FolderPath matches regex @"^[D-Z]:\\"
    | project DeviceName, ExecFolder=FolderPath, ProcessCommandLine
) on DeviceName
```

## YARA Detection Rule

```yara
rule MC_ING_01_Removable_Media_Autorun
{
    meta:
        author = "MalChain"
        technique = "MC-ING-01 Removable Media & File Transfer"
        description = "Autorun.inf abusing removable media to auto-launch a payload"
    strings:
        $a = "[autorun]" ascii nocase
        $b = "open=" ascii nocase
        $c = "shellexecute=" ascii nocase
        $d = "shell\\open\\command" ascii nocase
        $exe = ".exe" ascii nocase
    condition:
        $a and 1 of ($b,$c,$d) and $exe
}
```

## Mitigation

*   Disable autorun features
*   Enforce removable media policies
*   Scan external drives on insertion
*   Educate users on media risks

## Incident Response

*   Identify all accessed files
*   Quarantine affected endpoints
*   Analyze transferred artifacts
*   Review execution timelines

## Chain Linking

`INGRESS → Media Delivery → Trust Establishment → ACTIVATION`

**Enables next:**

- [User-Executed Files](../act/MC-ACT-01.md) (`ACT-01`)
- [Script-Based Execution](../act/MC-ACT-02.md) (`ACT-02`)
- [DLL Side-Loading or Hijacking](../act/MC-ACT-04.md) (`ACT-04`)

---

[Malvertising & Drive-By Downloads →](../ing/MC-ING-02.md)

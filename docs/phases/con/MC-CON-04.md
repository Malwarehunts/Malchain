# CON-04 · Masquerading & Impersonation

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Masquerading & Impersonation refers to the deliberate presentation of attacker-controlled components as legitimate users, processes, files, or services within a target environment. This includes renaming files to resemble trusted system components, using stolen credentials to assume authorized identities, or mimicking legitimate applications to avoid suspicion. Within MalChain, this capability begins once attacker activity successfully blends into normal operational patterns by adopting trusted identities or appearances. Attackers exploit implicit trust in familiar names, expected behaviors, and recognized system components to evade detection and maintain operational continuity. Routine reliance on known system processes and authenticated user sessions often allows disguised activity to persist without immediate investigation. Trust abuse may involve deceptive file names, cloned user accounts, or forged service identities presented as legitimate operational resources. Common masquerading methods include:

* Renaming malicious files to resemble trusted system components  
* Using stolen credentials to impersonate authorized users  
* Deploying processes with names similar to legitimate applications  
* Creating accounts that mimic administrative or service identities  
* Modifying file metadata to appear legitimate  

Real world usage includes:

* Credential-based intrusion campaigns targeting enterprise networks  
* Malware disguising itself as system utilities or update components  
* Insider threat scenarios involving unauthorized account use  
* Persistent threats blending malicious activity into routine operations

## Detection Guidance

Detection relies on monitoring identity usage, process naming behavior, and system activity associated with trusted components. Contextual correlation between expected behavior and observed activity is essential to reduce false positives.

* Monitor creation of accounts or processes with suspicious naming patterns  
* Detect authentication events inconsistent with normal user behavior  
* Correlate file execution with unexpected process identities  
* Alert on duplicate or similar system component names  
* Identify rare or unauthorized account or process activity

## KQL Detection Concepts

* Authentication events involving unusual user or service accounts  
* Process creation events using names similar to trusted system components  
* File execution patterns inconsistent with expected application behavior

## YARA Detection Concepts

* Files containing metadata designed to mimic legitimate components  
* Executables using naming patterns associated with trusted system utilities  
* Code structures intended to disguise process identity

## KQL Detection Rule

```kql
// Masquerading: system-named binary running from a non-system path
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("svchost.exe","lsass.exe","services.exe","csrss.exe","winlogon.exe","explorer.exe")
| where FolderPath !startswith "C:\\Windows"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256
```

## YARA Detection Rule

```yara
rule MC_CON_04_Masquerade_System_Name
{
    meta:
        author = "MalChain"
        technique = "MC-CON-04 Masquerading & Impersonation"
        description = "PE claiming a core Windows original filename but lacking MS company"
    strings:
        $n1 = "svchost.exe" wide ascii nocase
        $n2 = "lsass.exe" wide ascii nocase
        $n3 = "services.exe" wide ascii nocase
        $ms = "Microsoft Corporation" wide ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($n*) and not $ms
}
```

## Mitigation

* Enforce strong identity verification and authentication controls  
* Monitor account creation and privilege assignment activity  
* Implement application control and file integrity validation  
* Maintain strict naming and identity management policies

## Incident Response

* Identify accounts or processes involved in impersonation activity  
* Disable compromised or unauthorized identities  
* Analyze system activity associated with disguised components  
* Review authentication and execution timelines

## Chain Linking

`CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables next:**

- [Environment & Sandbox Evasion](../con/MC-CON-05.md) (`CON-05`)
- [Log & Artifact Manipulation](../con/MC-CON-08.md) (`CON-08`)
- [Identity & Trust Relationship Abuse](../exp/MC-EXP-08.md) (`EXP-08`)

---

[← Security Tool Tampering](../con/MC-CON-03.md) | [Environment & Sandbox Evasion →](../con/MC-CON-05.md)

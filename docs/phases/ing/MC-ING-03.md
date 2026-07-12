# ING-03 · Supply Chain Compromise

**Phase:** [Ingress](../ing.md) · Initial Access  |  **Detections:** KQL · YARA

[← Back to Ingress](../ing.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Supply Chain Compromise refers to initial access gained through the manipulation, poisoning, or compromise of third-party software, hardware, services, or dependencies that are trusted by the target organization. In MalChain, this capability ends once malicious code or access is delivered through a trusted channel and execution becomes possible. Attackers exploit institutional trust placed in:

*   Software vendors
*   Update mechanisms
*   Open-source dependencies
*   Managed service providers
*   Hardware suppliers

Because trust is pre-established, detection is often delayed. Attack vectors include:

*   Trojanized software updates
*   Compromised build pipelines
*   Dependency confusion attacks
*   Backdoored libraries
*   Malicious firmware or hardware components

The real world usage includes:

*   Espionage campaigns
*   Large-scale ransomware operations
*   Open-source ecosystem abuse
*   Hardware and firmware backdoors

## Detection Guidance

Detection focuses on integrity validation, anomaly detection, and monitoring trusted update channels for deviations. Traditional signature-based detection is often ineffective.

*   Validate software and update signatures
*   Monitor update behavior anomalies
*   Detect unexpected network destinations during updates
*   Track dependency version changes
*   Correlate trusted updates with execution events

## KQL Detection Concepts

*   Execution triggered by update services
*   Network traffic to non-standard update domains
*   Signed binaries exhibiting anomalous behavior

## YARA Detection Concepts

*   Embedded backdoor logic
*   Unexpected network routines
*   Hardcoded command-and-control indicators

## KQL Detection Rule

```kql
// Supply Chain: unexpected child process from a signed updater / installer
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("update","installer","setup","msiexec.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","curl.exe","certutil.exe")
| where ProcessCommandLine has_any ("http://","https://","-enc","DownloadString","Invoke-WebRequest")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## YARA Detection Rule

```yara
rule MC_ING_03_Supply_Chain_Installer_Backdoor
{
    meta:
        author = "MalChain"
        technique = "MC-ING-03 Supply Chain Compromise"
        description = "Installer/updater carrying embedded shell or download logic"
    strings:
        $u1 = "cmd.exe /c" ascii nocase
        $u2 = "powershell -" ascii nocase
        $u3 = "DownloadString" ascii nocase
        $u4 = "certutil -urlcache" ascii nocase
        $msi = "Windows Installer" ascii nocase
    condition:
        $msi and 2 of ($u1,$u2,$u3,$u4)
}
```

## Mitigation

*   Enforce code signing and verification
*   Pin dependency versions
*   Audit vendor security posture
*   Monitor build pipelines

## Incident Response

*   Identify scope of affected assets
*   Validate integrity of software artifacts
*   Revoke compromised trust relationships
*   Coordinate with vendors and partners

## Chain Linking

`INGRESS → Trusted Update or Dependency → ACTIVATION`

**Enables next:**

- [Service-Based Execution](../act/MC-ACT-03.md) (`ACT-03`)
- [DLL Side-Loading or Hijacking](../act/MC-ACT-04.md) (`ACT-04`)
- [Fileless & In-Memory Persistence](../anc/MC-ANC-07.md) (`ANC-07`)

---

[← Malvertising & Drive-By Downloads](../ing/MC-ING-02.md) | [Credential Abuse →](../ing/MC-ING-04.md)

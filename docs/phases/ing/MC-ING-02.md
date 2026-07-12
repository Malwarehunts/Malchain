# ING-02 · Malvertising & Drive-By Downloads

**Phase:** [Ingress](../ing.md) · Initial Access  |  **Detections:** KQL · YARA

[← Back to Ingress](../ing.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Malvertising & Drive-By Downloads refer to the delivery of malicious content through compromised or malicious online advertisements and websites. Victims may receive malware without knowingly downloading files, as exploitation occurs through browser interactions, redirect chains, or exploit kits. Within MalChain, this capability ends once a payload is delivered or execution becomes possible. Attackers abuse trust in:

*   Legitimate advertising networks
*   Popular websites
*   Browser security assumptions

Victims often do not realize exposure has occurred, increasing dwell time. Common delivery mechanisms include:

*   Malicious ad creatives
*   Redirect chains
*   Exploit kits
*   Fake update prompts
*   Browser plugin abuse

Real world usage includes:

*   Banking Trojans
*   Ransomware loaders
*   Information stealers
*   Cryptocurrency miners

## Detection Guidance

Detection relies on browser telemetry, network traffic analysis, and correlation between web activity and subsequent file or script execution. Early detection significantly reduces downstream impact.

*   Monitor browser redirect chains
*   Detect anomalous JavaScript execution
*   Identify unexpected file downloads
*   Alert on fake update indicators
*   Correlate web activity with execution events

## KQL Detection Concepts

*   Browser process initiating file downloads
*   JavaScript execution followed by process creation
*   Network connections to newly registered domains

## YARA Detection Concepts

*   Exploit kit fingerprints
*   Obfuscated JavaScript loaders
*   Suspicious redirect logic

## KQL Detection Rule

```kql
// Malvertising / Drive-by: browser spawning script interpreters or writing executables
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
```

## YARA Detection Rule

```yara
rule MC_ING_02_Malvertising_HTA_Dropper
{
    meta:
        author = "MalChain"
        technique = "MC-ING-02 Malvertising & Drive-By Downloads"
        description = "HTA/JS drive-by dropper invoking script hosts or downloads"
    strings:
        $hta = "<hta:application" ascii nocase
        $ws  = "WScript.Shell" ascii nocase
        $ado = "ADODB.Stream" ascii nocase
        $xhr = "MSXML2.XMLHTTP" ascii nocase
        $ps  = "powershell" ascii nocase
    condition:
        ($hta or $ws) and 2 of ($ado,$xhr,$ps)
}
```

## Mitigation

*   Use ad-blocking and script control
*   Harden browser configurations
*   Disable unnecessary plugins
*   Enforce patch management

## Incident Response

*   Review browser history and cache
*   Identify downloaded artifacts
*   Isolate affected endpoints
*   Hunt for follow-on execution

## Chain Linking

`INGRESS → Web Exposure → Silent Payload Delivery → ACTIVATION`

**Enables next:**

- [Script-Based Execution](../act/MC-ACT-02.md) (`ACT-02`)
- [User-Executed Files](../act/MC-ACT-01.md) (`ACT-01`)
- [DLL Side-Loading or Hijacking](../act/MC-ACT-04.md) (`ACT-04`)

---

[← Removable Media & File Transfer](../ing/MC-ING-01.md) | [Supply Chain Compromise →](../ing/MC-ING-03.md)

# ING-06 · Watering Hole Attacks

**Phase:** [Ingress](../ing.md) · Initial Access  |  **Detections:** KQL · YARA

[← Back to Ingress](../ing.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Watering Hole Attacks refer to the compromise of websites, portals, or online services that are trusted and frequently accessed by a target population. Attackers inject malicious scripts or redirect logic to deliver payloads selectively. Within MalChain, this capability ends once malicious content is delivered or execution becomes possible. Attackers exploit trust in:

*   Industry-specific websites
*   Internal portals and partner sites
*   Community forums
*   Vendor documentation pages
  
Victims rarely suspect compromise of familiar resources. Watering hole campaigns rely on profiling to maximize effectiveness:

*   IP range filtering
*   User-agent inspection
*   Geolocation checks
*   Time-based activation
  
The real world usage includes:

*   Espionage-focused APT groups
*   Long-term surveillance campaigns
*   Targeted credential harvesting operations

## Detection Guidance

Detection requires visibility into web traffic, script execution, and correlation between visited sites and subsequent execution events. Because delivery is selective, detection often relies on anomaly hunting.

*   Monitor web traffic to rarely compromised sites
*   Detect injected or modified JavaScript
*   Identify browser redirects to unknown domains
*   Correlate site visits with execution events
*   Monitor selective targeting behavior

## KQL Detection Concepts

*   Browser process contacting rare domains after known site visits
*   JavaScript execution followed by payload download
*   Redirect chains tied to specific user groups

## YARA Detection Concepts

*   Malicious JavaScript loaders
*   Conditional execution logic
*   Obfuscated redirect scripts

## KQL Detection Rule

```kql
// Watering Hole: navigation to a compromised site then payload retrieval
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")
| where RemoteUrl has_any (".hta",".jar",".ps1",".js",".vbs",".scr")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
```

## YARA Detection Rule

```yara
rule MC_ING_06_Watering_Hole_Injected_Script
{
    meta:
        author = "MalChain"
        technique = "MC-ING-06 Watering Hole Attacks"
        description = "Obfuscated JS injected into web content for selective delivery"
    strings:
        $s1 = "eval(" ascii
        $s2 = "String.fromCharCode(" ascii
        $s3 = "unescape(" ascii
        $s4 = "document.write(" ascii
        $s5 = "atob(" ascii
    condition:
        3 of them
}
```

## Mitigation

*   Enforce content security policies
*   Monitor integrity of trusted websites
*   Use browser isolation technologies
*   Educate users on targeted web risks

## Incident Response

*   Identify affected users and systems
*   Capture browser artifacts and cache
*   Coordinate with site owners
*   Hunt for follow-on execution

## Chain Linking

`INGRESS → Targeted Web Exposure → ACTIVATION`

**Enables next:**

- [Script-Based Execution](../act/MC-ACT-02.md) (`ACT-02`)
- [Credential Abuse](../ing/MC-ING-04.md) (`ING-04`)
- [DLL Side-Loading or Hijacking](../act/MC-ACT-04.md) (`ACT-04`)

---

[← Malicious or Compromised USB Devices](../ing/MC-ING-05.md) | [External Remote Services →](../ing/MC-ING-07.md)
